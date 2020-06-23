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

// cachedFirewall stores the current state of the CCM worker firewall.
type cachedFirewall struct {
	// The cached state of the firewall.
	state *godo.Firewall
}

// firewallCache stores a cached firewall and mutex to handle concurrent access.
type firewallCache struct {
	mu       sync.RWMutex // protects firewallMap.
	firewall *cachedFirewall
}

// firewallManagerOp handles communication with methods of the FirewallManager.
type firewallManagerOp struct {
	client  *godo.Client
	fwCache *firewallCache
}

// FirewallManager manages the interaction with the DO Firewalls API.
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
	// firewallManager    *FirewallManager
	// firewallManagerOp  *firewallManagerOp
}

// NewFirewallController returns a new firewall controller to reconcile CCM worker firewall state.
func NewFirewallController(
	workerFwName string,
	kubeClient clientset.Interface,
	client *godo.Client,
	serviceInformer coreinformers.ServiceInformer,
	tags []string,
	// fwManager *FirewallManager,
	ctx context.Context,
) (*FirewallController, error) {
	if kubeClient != nil && kubeClient.CoreV1().RESTClient().GetRateLimiter() != nil {
		if err := ratelimiter.RegisterMetricAndTrackRateLimiterUsage("firewall_controller", kubeClient.CoreV1().RESTClient().GetRateLimiter()); err != nil {
			return nil, err
		}
	}

	fc := &FirewallController{
		kubeClient:         kubeClient,
		client:             client,
		workerFirewallName: workerFwName,
		// firewallManager:    fwManager,
	}

	fwManagerOp := &firewallManagerOp{
		client:  client,
		fwCache: &firewallCache{},
	}

	serviceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				fc.onServiceChange(ctx, fwManagerOp)
			},
			UpdateFunc: func(old, cur interface{}) {
				fc.onServiceChange(ctx, fwManagerOp)
			},
			DeleteFunc: func(obj interface{}) {
				fc.onServiceChange(ctx, fwManagerOp)
			},
		},
		serviceSyncPeriod,
	)
	fc.serviceLister = serviceInformer.Lister()

	return fc, nil
}

func (fc *FirewallController) Run(ctx context.Context, inboundRules []godo.InboundRule, currentFirewallState *godo.Firewall, fm *firewallManagerOp, stopCh <-chan struct{}) {
	wait.Until(func() {
		targetFirewallState, err := fm.Get(ctx, inboundRules, fc)
		if err != nil {
			klog.Errorf("failed to get worker firewall: %s", err)
			return
		}
		cache := fm.fwCache
		if cache == nil {
			fc.updateCache(&targetFirewallState, &firewallManagerOp{})
		}
		if currentFirewallState != nil {
			if cmp.Equal(currentFirewallState, targetFirewallState) {
				return
			}
		}
		err = fc.onServiceChange(ctx, fm)
		if err != nil {
			klog.Errorf("Failed to reconcile worker firewall: %s", err)
		}
	}, 5*time.Minute, stopCh)
}

// Get returns the current CCM worker firewall representation.
func (fm *firewallManagerOp) Get(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) (godo.Firewall, error) {
	if fm.cachedFirewallExists() {
		return *fm.fwCache.firewall.state, nil
	}
	// cached firewall does not exist, so iterate through firewall API provided list and return
	// the firewall with the matching firewall name.
	firewallList, err := allFirewallList(ctx, fm.client)
	if err != nil {
		return godo.Firewall{}, fmt.Errorf("failed to retrieve firewall from DO firewall API: %s", err)
	}
	if err == nil && firewallList != nil {
		for _, fw := range firewallList {
			if fw.Name == fc.workerFirewallName {
				// update the firewall cache before returning
				fc.updateCache(&fw, fm)
				return fw, nil
			}
		}
	}
	return godo.Firewall{}, nil
}

// Set applies the given inbound rules to the CCM worker firewall when the current rules and target rules differ.
func (fm *firewallManagerOp) Set(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) error {
	// retrieve the target firewall representation (CCM worker firewall from cache) and the
	// current firewall representation from the DO firewalls API. If there are any differences,
	// handle it.
	fw, err := fm.Get(ctx, inboundRules, fc)
	if err != nil {
		return fmt.Errorf("failed to get firewall state: %s", err)
	}
	err = fm.checkFirewallEquality(ctx, &fw, inboundRules, fc)
	if err != nil {
		return fmt.Errorf("failed to reconcile current firewall state with target firewall state: %v", err)
	}

	return nil
}

func (fm *firewallManagerOp) checkFirewallEquality(ctx context.Context, fw *godo.Firewall, inboundRules []godo.InboundRule, fc *FirewallController) error {
	fm.fwCache.mu.RLock()
	defer fm.fwCache.mu.RUnlock()

	cachedFw := fm.fwCache.firewall.state
	isEqual := cmp.Equal(cachedFw, fw)
	if cmp.Equal(cachedFw.InboundRules, inboundRules) && cmp.Equal(fw.InboundRules, inboundRules) {
		if isEqual {
			return nil
		}
	} else if !cmp.Equal(cachedFw.InboundRules, inboundRules) && cmp.Equal(fw.InboundRules, inboundRules) {
		fc.updateCache(fw, fm)
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

func (fc *FirewallController) onServiceChange(ctx context.Context, fm *firewallManagerOp) error {
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
	return fm.Set(ctx, nodePortInboundRules, fc)
}

func (fc *FirewallController) updateCache(firewall *godo.Firewall, fm *firewallManagerOp) {
	fm.fwCache.mu.Lock()
	defer fm.fwCache.mu.Unlock()
	if firewall != nil {
		fm.fwCache = &firewallCache{
			firewall: &cachedFirewall{
				state: firewall,
			},
		}
	}
}

func (fm *firewallManagerOp) cachedFirewallExists() bool {
	fm.fwCache.mu.RLock()
	defer fm.fwCache.mu.RUnlock()
	if fm.fwCache.firewall != nil {
		return true
	}
	return false
}

func (fm *firewallManagerOp) updateFirewallRules(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) error {
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
func (fm *firewallManagerOp) reconcileFirewall(ctx context.Context, targetState godo.Firewall, currentState godo.Firewall, fc *FirewallController) error {
	updateStateRequest := &godo.FirewallRequest{}
	if !cmp.Equal(targetState, currentState) {
		updateStateRequest.Name = targetState.Name
		updateStateRequest.InboundRules = targetState.InboundRules
		updateStateRequest.OutboundRules = targetState.OutboundRules
		updateStateRequest.DropletIDs = targetState.DropletIDs
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

func (fm *firewallManagerOp) createFirewallAndUpdateCache(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) (*godo.Firewall, error) {
	// make create request since firewall does not exist, then cache firewall state.
	fr := &godo.FirewallRequest{
		Name:         fc.workerFirewallName,
		InboundRules: inboundRules,
	}
	fwsvc := fm.client.Firewalls
	fw, resp, err := fwsvc.Create(ctx, fr)
	if err != nil {
		return nil, fmt.Errorf("failed to create firewall: %s", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Some value: %v", resp.StatusCode)
	}
	fc.updateCache(fw, fm)
	return fw, nil
}