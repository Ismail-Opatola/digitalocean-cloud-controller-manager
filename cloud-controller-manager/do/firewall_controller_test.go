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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

type stubCachedFirewall struct {
	state *godo.Firewall
}

type stubFirewallCache struct {
	mu       sync.RWMutex
	firewall *stubCachedFirewall
}

type stubFirewallManagerOp struct {
	client  *godo.Client
	fwCache *stubFirewallCache
}

// Set applies the given inbound rules to the CCM worker firewall when the current rules and target rules differ.
func (fm *stubFirewallManagerOp) Set(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) error {
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

func TestFirewallController_Run(t *testing.T) {
	// setup arguments
	ctx := context.TODO()
	fakeWorkerFirewallName := "myFirewallWorkerName"
	kclient := fake.NewSimpleClientset()
	inf := informers.NewSharedInformerFactory(kclient, 0)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"account":null}`))
	}))
	gclient, _ := godo.New(http.DefaultClient, godo.SetBaseURL(ts.URL))
	fwManagerOp := stubFirewallManagerOp{
		client:  gclient,
		fwCache: &stubFirewallCache{},
	}
	rule := &godo.InboundRule{}
	inboundRules := []godo.InboundRule{*rule}
	fc, err := NewFirewallController(fakeWorkerFirewallName, kclient, inf.Core().V1().Services(), []string{}, fwManagerOp, ctx)
	stop := make(chan struct{})

	// t.Logf to log output to the terminal
	// run actual tests
	fc.Run(ctx, inboundRules, &fwManagerOp, stop)
	select {
	case <-stop:
		// No-op: test succeeded
		assert.NoError(t, err)
		assert.NotNil(t, fc)
	case <-time.After(3 * time.Second):
		// Terminate goroutines just in case.
		close(stop)
	}
}

// Get returns the current CCM worker firewall representation.
func (fm *stubFirewallManagerOp) Get(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) (*godo.Firewall, error) {
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

func (fm *stubFirewallManagerOp) createFirewallAndUpdateCache(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) (*godo.Firewall, error) {
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

func (fm *stubFirewallManagerOp) updateCache(firewall *godo.Firewall) {
	fm.fwCache.mu.Lock()
	defer fm.fwCache.mu.Unlock()
	if firewall != nil {
		fm.fwCache.firewall.state = firewall
	}
}

func (fm *stubFirewallManagerOp) firewallCacheExists() bool {
	fm.fwCache.mu.RLock()
	defer fm.fwCache.mu.RUnlock()
	if fm.fwCache.firewall != nil {
		return true
	}
	return false
}
