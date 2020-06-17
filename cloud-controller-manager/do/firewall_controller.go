/*
Copyright 2020 DigitalOcean

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package do

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/digitalocean/godo"
	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/component-base/metrics/prometheus/ratelimiter"
	"k8s.io/klog"
)

const (
	// Interval of synchronizing service status from apiserver.
	serviceSyncPeriod = 30 * time.Second
	minRetryDelay     = 5 * time.Second
	maxRetryDelay     = 300 * time.Second

	// The format we should expect for ccm worker firewall names.
	firewallWorkerCCMNameFormat = "k8s-%s-ccm"
)

// CachedFirewall stores the current state of the CCM worker firewall.
type CachedFirewall struct {
	// The cached state of the firewall.
	state *godo.Firewall
}

// FirewallCache stores a cached firewall and mutex to handle concurrent access.
type FirewallCache struct {
	mu       sync.RWMutex // protects firewallMap.
	firewall *CachedFirewall
}

// FirewallManagerOp handles communication with methods of the FirewallManager.
type FirewallManagerOp struct {
	client  *godo.Client
	fwCache *FirewallCache
}

type FirewallManager interface {
	// Get returns the current CCM worker firewall representation (i.e., the DO Firewall object).
	Get(ctx context.Context, inboundRules []godo.InboundRule, c *FirewallController) (godo.Firewall, error)

	// Set applies the given inbound rules to the CCM worker firewall.
	Set(ctx context.Context, inboundRules []godo.InboundRule, c *FirewallController) error
}

// FirewallController helps to keep cloud provider service firewalls in sync.
type FirewallController struct {
	kubeClient         clientset.Interface
	client             *godo.Client
	workerFirewallName string
	tags               []string
	serviceLister      corelisters.ServiceLister
	firewallManager    FirewallManager
}

// NewFirewallController returns a new firewall controller to reconcile CCM worker firewall state.
func NewFirewallController(
	workerFwName string,
	kubeClient clientset.Interface,
	serviceInformer coreinformers.ServiceInformer,
	tags []string,
	fwManager FirewallManager,
	ctx context.Context,
) (*FirewallController, error) {
	if kubeClient != nil && kubeClient.CoreV1().RESTClient().GetRateLimiter() != nil {
		if err := ratelimiter.RegisterMetricAndTrackRateLimiterUsage("firewall_controller", kubeClient.CoreV1().RESTClient().GetRateLimiter()); err != nil {
			return nil, err
		}
	}

	fc := &FirewallController{
		kubeClient:         kubeClient,
		client:             &godo.Client{},
		workerFirewallName: workerFwName,
		tags:               tags,
		firewallManager:    fwManager,
	}

	serviceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				fc.onServiceChange(ctx)
			},
			UpdateFunc: func(old, cur interface{}) {
				fc.onServiceChange(ctx)
			},
			DeleteFunc: func(obj interface{}) {
				fc.onServiceChange(ctx)
			},
		},
		serviceSyncPeriod,
	)
	fc.serviceLister = serviceInformer.Lister()

	return fc, nil
}

func (fc *FirewallController) Run(ctx context.Context, inboundRules []godo.InboundRule, fm *FirewallManagerOp, stopCh <-chan struct{}) {
	wait.Until(func() {
		firewall, err := fm.Get(ctx, inboundRules, fc)
		if err != nil {
			klog.Errorf("failed to get worker firewall: %s", err)
			return
		}
		firewallCachedState := *fm.fwCache.firewall.state
		if cmp.Equal(&firewallCachedState, firewall) {
			return
		}
		err = fc.onServiceChange(ctx)
		if err != nil {
			klog.Errorf("Failed to reconcile worker firewall: %s", err)
		}
	}, 5*time.Minute, stopCh)
}

// Get returns the current CCM worker firewall representation.
func (fm *FirewallManagerOp) Get(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) (*godo.Firewall, error) {
	// return the firewall stored in the cache.
	if fm.firewallCacheExists() {
		fwsvc := fm.client.Firewalls
		fw, _, err := fwsvc.Get(ctx, fm.fwCache.firewall.state.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get firewall: %s", err)
		}
		return fw, nil
	}
	// cached firewall does not exist, so iterate through firewall API provided list and return
	// the firewall with the matching firewall name.
	firewallList, err := allFirewallList(ctx, fm.client)
	if err != nil {
		return nil, fmt.Errorf("failed to list firewalls: %s", err)
	}
	for _, fw := range firewallList {
		if fw.Name == fc.workerFirewallName {
			return &fw, nil
		}
	}
	// firewall is not found via firewalls API, so we need to create it.
	fw, err := fm.createFirewallAndUpdateCache(ctx, inboundRules, fc)
	if err != nil {
		return nil, fmt.Errorf("failed to create firewall: %s", err)
	}
	return fw, nil
}

// Set applies the given inbound rules to the CCM worker firewall when the current rules and target rules differ.
func (fm *FirewallManagerOp) Set(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) error {
	// retrieve the target firewall representation (CCM worker firewall from cache) and the
	// current firewall representation from the DO firewalls API. If there are any differences,
	// handle it.
	fw, err := fm.Get(ctx, inboundRules, fc)
	if err != nil {
		return fmt.Errorf("failed to get firewall state: %s", err)
	}
	err = fm.checkFirewallEquality(ctx, fw, inboundRules, fc)
	if err != nil {
		return fmt.Errorf("failed to reconcile current firewall state with target firewall state: %v", err)
	}

	return nil
}

func (fm *FirewallManagerOp) checkFirewallEquality(ctx context.Context, fw *godo.Firewall, inboundRules []godo.InboundRule, fc *FirewallController) error {
	fm.fwCache.mu.RLock()
	defer fm.fwCache.mu.RUnlock()

	cachedFw := fm.fwCache.firewall.state
	isEqual := cmp.Equal(cachedFw, fw)
	if cmp.Equal(cachedFw.InboundRules, inboundRules) && cmp.Equal(fw.InboundRules, inboundRules) {
		if isEqual {
			return nil
		}
	} else if !cmp.Equal(cachedFw.InboundRules, inboundRules) && cmp.Equal(fw.InboundRules, inboundRules) {
		fm.updateCache(fw)
	} else if !cmp.Equal(fw.InboundRules, inboundRules) {
		err := fm.updateFirewallRules(ctx, inboundRules, fc)
		if err != nil {
			return fmt.Errorf("failed to update firewall state: %s", err)
		}
	}
	if !isEqual {
		err := fm.reconcileFirewall(ctx, *cachedFw, *fw, fc)
		if err != nil {
			return fmt.Errorf("failed to reconcile firewall state: %s", err)
		}
	}
	return nil
}

func (fc *FirewallController) onServiceChange(ctx context.Context) error {
	var nodePortInboundRules []godo.InboundRule
	serviceList, err := fc.serviceLister.List(labels.Nothing())
	if err != nil {
		return fmt.Errorf("failed to get service state: %s", err)
	}
	for _, svc := range serviceList {
		if svc.Spec.Type == v1.ServiceTypeNodePort {
			// this is a nodeport service so we should check for existing inbound rules on all ports.
			for _, servicePort := range svc.Spec.Ports {
				nodePortInboundRules = append(nodePortInboundRules, godo.InboundRule{
					Protocol:  "tcp",
					PortRange: strconv.Itoa(int(servicePort.NodePort)),
					Sources: &godo.Sources{
						Tags: fc.tags,
					},
				})
			}
		}
	}
	if len(nodePortInboundRules) == 0 {
		return nil
	}
	return fc.firewallManager.Set(ctx, nodePortInboundRules, fc)
}

func (fm *FirewallManagerOp) updateCache(firewall *godo.Firewall) {
	fm.fwCache.mu.Lock()
	defer fm.fwCache.mu.Unlock()
	fw := &CachedFirewall{state: firewall}
	fm.fwCache.firewall.state = fw.state
}

func (fm *FirewallManagerOp) firewallCacheExists() bool {
	fm.fwCache.mu.RLock()
	defer fm.fwCache.mu.RUnlock()
	if fm.fwCache.firewall != nil {
		return true
	}
	return false
}

func (fm *FirewallManagerOp) updateFirewallRules(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) error {
	rr := godo.FirewallRulesRequest{
		InboundRules: inboundRules,
	}
	fwsvc := fm.client.Firewalls
	resp, err := fwsvc.AddRules(ctx, fm.fwCache.firewall.state.ID, &rr)
	if err != nil {
		return fmt.Errorf("failed to add firewall inbound rules: %s", err)
	}
	if resp.StatusCode == 404 {
		fm.createFirewallAndUpdateCache(ctx, inboundRules, fc)
		return nil
	}
	return nil
}

// check each field of the cached firewall and the DO API firewall and update any discrepancies until it
// matches the target state (cached firewall).
func (fm *FirewallManagerOp) reconcileFirewall(ctx context.Context, targetState godo.Firewall, currentState godo.Firewall, fc *FirewallController) error {
	updateStateRequest := &godo.FirewallRequest{}
	if targetState.Name != currentState.Name {
		updateStateRequest.Name = targetState.Name
	}
	if !cmp.Equal(targetState.InboundRules, currentState.InboundRules) {
		updateStateRequest.InboundRules = targetState.InboundRules
	}
	if !cmp.Equal(targetState.OutboundRules, currentState.OutboundRules) {
		updateStateRequest.OutboundRules = targetState.OutboundRules
	}
	if !cmp.Equal(targetState.DropletIDs, currentState.DropletIDs) {
		updateStateRequest.DropletIDs = targetState.DropletIDs
	}
	if !cmp.Equal(targetState.Tags, currentState.Tags) {
		updateStateRequest.Tags = targetState.Tags
	}
	fwsvc := fm.client.Firewalls
	_, resp, err := fwsvc.Update(ctx, targetState.ID, updateStateRequest)
	if err != nil {
		return fmt.Errorf("failed to update firewall state: %s", err)
	}
	if resp.StatusCode == 404 {
		fm.createFirewallAndUpdateCache(ctx, targetState.InboundRules, fc)
		return nil
	}
	return nil
}

func (fm *FirewallManagerOp) createFirewallAndUpdateCache(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) (*godo.Firewall, error) {
	// make create request since firewall does not exist, then cache firewall state.
	fr := &godo.FirewallRequest{
		Name:         fc.workerFirewallName,
		InboundRules: inboundRules,
	}
	fwsvc := fm.client.Firewalls
	fw, _, err := fwsvc.Create(ctx, fr)
	if err != nil {
		return nil, fmt.Errorf("failed to create firewall: %s", err)
	}
	fm.updateCache(fw)
	return fw, nil
}
