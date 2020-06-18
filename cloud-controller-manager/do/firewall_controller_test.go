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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"sync"
	"testing"

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

// Get returns the current CCM worker firewall representation.
func (fm *stubFirewallManagerOp) Get(ctx context.Context, inboundRules []godo.InboundRule, fc *FirewallController) (godo.Firewall, error) {
	// return the firewall stored in the cache.
	if fm.firewallCacheExists() {
		fwsvc := fm.client.Firewalls
		fw, _, err := fwsvc.Get(ctx, fm.fwCache.firewall.state.ID)
		if err == nil && fw != nil {
			return *fw, nil
		}
	}
	// cached firewall does not exist, so iterate through firewall API provided list and return
	// the firewall with the matching firewall name.
	firewallList, err := allFirewallList(ctx, fm.client)
	if err == nil && firewallList != nil {
		for _, fw := range firewallList {
			if fw.Name == fc.workerFirewallName {
				return fw, nil
			}
		}
	}
	// firewall is not found via firewalls API, so we need to create it.
	fw, err := fm.createFirewallAndUpdateCache(ctx, inboundRules, fc)
	if err != nil {
		return godo.Firewall{}, fmt.Errorf("failed to create firewall: %s", err)
	} else if fw == nil {
		err = errors.New("DO API firewall creation unexpectedly failed")
		return godo.Firewall{}, fmt.Errorf("failed to create firewall: %s", err)
	}
	return *fw, nil
}

// Set applies the given inbound rules to the CCM worker firewall when the current rules and target rules differ.
func (fm *stubFirewallManagerOp) Set(ctx context.Context, inboundRules []godo.InboundRule, c *FirewallController) error {
	// retrieve the target firewall representation (CCM worker firewall from cache) and the
	// current firewall representation from the DO firewalls API. If there are any differences,
	// handle it.
	fw, err := fm.Get(ctx, inboundRules, c)
	if err != nil {
		return fmt.Errorf("failed to get firewall state: %s", err)
	}
	err = fm.checkFirewallEquality(ctx, &fw, inboundRules, c)
	if err != nil {
		return fmt.Errorf("failed to reconcile current firewall state with target firewall state: %v", err)
	}

	return nil
}

func (fm *stubFirewallManagerOp) checkFirewallEquality(ctx context.Context, fw *godo.Firewall, inboundRules []godo.InboundRule, fc *FirewallController) error {
	return nil
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

// fakeFirewallService concrete type that satisfies the FirewallsService interface.
type fakeFirewallService struct {
	getFunc            func(context.Context, string) (*godo.Firewall, *godo.Response, error)
	createFunc         func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
	updateFunc         func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
	deleteFunc         func(context.Context, string) (*godo.Response, error)
	listFunc           func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
	listByDropletFunc  func(context.Context, int, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
	addDropletsFunc    func(context.Context, string, ...int) (*godo.Response, error)
	removeDropletsFunc func(context.Context, string, ...int) (*godo.Response, error)
	addTagsFunc        func(context.Context, string, ...string) (*godo.Response, error)
	removeTagsFunc     func(context.Context, string, ...string) (*godo.Response, error)
	addRulesFunc       func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error)
	removeRulesFunc    func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error)
}

// Get an existing Firewall by its identifier.
func (f *fakeFirewallService) Get(ctx context.Context, fID string) (*godo.Firewall, *godo.Response, error) {
	return f.getFunc(ctx, fID)
}

// Create a new Firewall with a given configuration.
func (f *fakeFirewallService) Create(ctx context.Context, fr *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
	return f.createFunc(ctx, fr)
}

// Update an existing Firewall with new configuration.
func (f *fakeFirewallService) Update(ctx context.Context, fID string, fr *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
	return f.updateFunc(ctx, fID, fr)
}

// Delete a Firewall by its identifier.
func (f *fakeFirewallService) Delete(ctx context.Context, fID string) (*godo.Response, error) {
	return f.deleteFunc(ctx, fID)
}

// List Firewalls.
func (f *fakeFirewallService) List(ctx context.Context, opt *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
	return f.listFunc(ctx, opt)
}

// ListByDroplet Firewalls.
func (f *fakeFirewallService) ListByDroplet(ctx context.Context, dID int, opt *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
	return f.listByDropletFunc(ctx, dID, opt)
}

// AddDroplets to a Firewall.
func (f *fakeFirewallService) AddDroplets(ctx context.Context, fID string, dropletIDs ...int) (*godo.Response, error) {
	return f.addDropletsFunc(ctx, fID)
}

// RemoveDroplets from a Firewall.
func (f *fakeFirewallService) RemoveDroplets(ctx context.Context, fID string, dropletIDs ...int) (*godo.Response, error) {
	return f.removeDropletsFunc(ctx, fID, dropletIDs...)
}

// AddTags to a Firewall.
func (f *fakeFirewallService) AddTags(ctx context.Context, fID string, tags ...string) (*godo.Response, error) {
	return f.addTagsFunc(ctx, fID, tags...)
}

// RemoveTags from a Firewall.
func (f *fakeFirewallService) RemoveTags(ctx context.Context, fID string, tags ...string) (*godo.Response, error) {
	return f.removeTagsFunc(ctx, fID, tags...)
}

// AddRules to a Firewall.
func (f *fakeFirewallService) AddRules(ctx context.Context, fID string, rr *FirewallRulesRequest) (*godo.Response, error) {
	return f.addRulesFunc(ctx, fID, rr)
}

// RemoveRules from a Firewall.
func (f *fakeFirewallService) RemoveRules(ctx context.Context, fID string, rr *FirewallRulesRequest) (*godo.Response, error) {
	return f.removeRulesFunc(ctx, fID, rr)
}

// func newFakeFirewallNoInboundRules() *godo.Firewall {
// 	return &godo.Firewall{
// 		ID:   "123",
// 		Name: "test-firewall",
// 	}
// }

// func newFakeFirewallWithInboundRules() *godo.Firewall {
// 	return &godo.Firewall{
// 		ID:   "123",
// 		Name: "test-firewall",
// 		InboundRules: []godo.InboundRule{
// 			godo.InboundRule{
// 				Protocol:  "tcp",
// 				PortRange: "31200",
// 				Sources: &godo.Sources{
// 					Tags:       []string{"my-tag1", "my-tag2"},
// 					DropletIDs: []int{1, 2, 3},
// 				},
// 			},
// 		},
// 	}
// }

func newFakeFirewall(name string, inboundRule godo.InboundRule) *godo.Firewall {
	return &godo.Firewall{
		ID:           "123",
		Name:         "test-firewall",
		InboundRules: []godo.InboundRule{inboundRule},
	}
}

// func TestFirewallController_Run(t *testing.T) {
// 	// setup arguments
// 	ctx := context.TODO()
// 	fakeWorkerFirewallName := "myFirewallWorkerName"
// 	kclient := fake.NewSimpleClientset()
// 	inf := informers.NewSharedInformerFactory(kclient, 0)
// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte(`{"account":null}`))
// 	}))
// 	gclient, _ := godo.New(http.DefaultClient, godo.SetBaseURL(ts.URL))
// 	var fwManager FirewallManager
// 	fwManager = &stubFirewallManagerOp{
// 		client:  gclient,
// 		fwCache: &stubFirewallCache{},
// 	}
// 	rule := &godo.InboundRule{}
// 	inboundRules := []godo.InboundRule{*rule}
// 	fc, err := NewFirewallController(fakeWorkerFirewallName, kclient, gclient, inf.Core().V1().Services(), []string{}, &fwManager, ctx)
// 	stop := make(chan struct{})

// 	// run actual tests
// 	var fwManagerOp *firewallManagerOp
// 	fwManagerOp = &firewallManagerOp{
// 		client:  gclient,
// 		fwCache: &firewallCache{},
// 	}
// 	go fc.Run(ctx, inboundRules, &godo.Firewall{}, fwManagerOp, stop)
// 	select {
// 	case <-stop:
// 		// No-op: test succeeded
// 		assert.NoError(t, err)
// 		assert.NotNil(t, fc)
// 	case <-time.After(3 * time.Second):
// 		// Terminate goroutines just in case.
// 		close(stop)
// 	}
// }

var (
	mux *http.ServeMux

	ctx = context.TODO()

	fakeWorkerFirewallName = "myFirewallWorkerName"

	kclient = fake.NewSimpleClientset()

	inf = informers.NewSharedInformerFactory(kclient, 0)
)

func TestFirewallController_Get(t *testing.T) {
	// setup arguments
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"account":null}`))
	}))
	gclient, _ := godo.New(http.DefaultClient, godo.SetBaseURL(ts.URL))

	sources := &godo.Sources{
		Tags:       []string{"my-tag1", "my-tag2"},
		DropletIDs: []int{1, 2, 3},
	}
	// setup firewall manager
	rule := &godo.InboundRule{
		Protocol:  "tcp",
		PortRange: "31000",
		Sources:   sources,
	}
	inboundRules := []godo.InboundRule{*rule}
	expectedFirewall := &godo.Firewall{
		ID:           "123",
		Name:         fakeWorkerFirewallName,
		InboundRules: inboundRules,
	}
	cachedFw := &stubCachedFirewall{state: expectedFirewall}
	var fwManager FirewallManager
	fwManager = &stubFirewallManagerOp{
		client:  gclient,
		fwCache: &stubFirewallCache{firewall: cachedFw},
	}
	fc, err := NewFirewallController(fakeWorkerFirewallName, kclient, gclient, inf.Core().V1().Services(), []string{}, &fwManager, ctx)
	// handle godo http requests
	urlStr := "/v2/firewalls"
	fID := "fe6b88f2-b42b-4bf7-bbd3-5ae20208f0b0"
	urlStr = path.Join(urlStr, fID)

	mux.HandleFunc(urlStr, func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, firewallJSONResponse)
	})

	// run actual tests
	actualFirewall, err := fwManager.Get(ctx, inboundRules, fc)
	assert.NoError(t, err)
	assert.Equal(t, expectedFirewall, actualFirewall)
}
