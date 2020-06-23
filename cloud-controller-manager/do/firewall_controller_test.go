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
	"time"

	// "fmt"

	"testing"

	"github.com/digitalocean/godo"
	"gotest.tools/assert"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

var (
	ctx = context.TODO()

	kclient kubernetes.Interface

	inf = informers.NewSharedInformerFactory(kclient, 0)
)

func newFakeFirewallManagerOp(client *godo.Client, cache *firewallCache) *firewallManagerOp {
	return &firewallManagerOp{
		client:  client,
		fwCache: cache,
	}
}

func newFakeFirewallCache(workerFirewallName string, inboundRule godo.InboundRule) *firewallCache {
	return &firewallCache{
		firewall: &cachedFirewall{
			state: &godo.Firewall{
				ID:           "123",
				Name:         workerFirewallName,
				InboundRules: []godo.InboundRule{inboundRule},
			},
		},
	}
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
func (f *fakeFirewallService) AddRules(ctx context.Context, fID string, rr *godo.FirewallRulesRequest) (*godo.Response, error) {
	return f.addRulesFunc(ctx, fID, rr)
}

// RemoveRules from a Firewall.
func (f *fakeFirewallService) RemoveRules(ctx context.Context, fID string, rr *godo.FirewallRulesRequest) (*godo.Response, error) {
	return f.removeRulesFunc(ctx, fID, rr)
}

func newFakeFirewall(workerFirewallName string, inboundRule godo.InboundRule) *godo.Firewall {
	return &godo.Firewall{
		ID:           "123",
		Name:         workerFirewallName,
		InboundRules: []godo.InboundRule{inboundRule},
	}
}

func newFakeGodoClient(fakeFirewall *fakeFirewallService) *godo.Client {
	return &godo.Client{
		Firewalls: fakeFirewall,
	}
}

func TestFirewallController_Get(t *testing.T) {
	workerFirewallName := "test-worker-firewall"
	inboundRule := godo.InboundRule{
		Protocol:  "tcp",
		PortRange: "31000",
		Sources: &godo.Sources{
			Tags:       []string{"my-tag1"},
			DropletIDs: []int{1},
		},
	}

	testcases := []struct {
		name          string
		firewall      *godo.Firewall
		fwCache       *firewallCache
		godoResponse  *godo.Response
		expectedError error
	}{
		{
			name:          "retrieve from local firewall cache if it exists",
			firewall:      newFakeFirewall(workerFirewallName, inboundRule),
			fwCache:       newFakeFirewallCache(workerFirewallName, inboundRule),
			godoResponse:  nil,
			expectedError: nil,
		},
		{
			name:          "retrieve from API and update local cache",
			firewall:      newFakeFirewall(workerFirewallName, inboundRule),
			fwCache:       nil,
			godoResponse:  newFakeOKResponse(),
			expectedError: nil,
		},
		{
			name:          "fail to get worker firewall from cache or API and return error",
			firewall:      newFakeFirewall(workerFirewallName, inboundRule),
			fwCache:       nil,
			godoResponse:  newFakeNotOKResponse(),
			expectedError: errors.New("failed to retrieve firewall from DO firewall API"),
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			gclient := newFakeGodoClient(
				&fakeFirewallService{
					getFunc: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
						return test.firewall, test.godoResponse, test.expectedError
					},
					listFunc: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
						return []godo.Firewall{*test.firewall}, test.godoResponse, test.expectedError
					},
				},
			)
			fc, _ := NewFirewallController(workerFirewallName, kclient, gclient, inf.Core().V1().Services(), []string{}, ctx)
			fwManagerOp := newFakeFirewallManagerOp(fc.client, &firewallCache{})
			if test.fwCache != nil {
				fwManagerOp.fwCache = test.fwCache
			}

			fw, err := fwManagerOp.Get(ctx, []godo.InboundRule{inboundRule}, fc)
			if test.expectedError != nil {
				assert.ErrorContains(t, err, test.expectedError.Error())
			} else {
				// simple Equal checks on strings
				assert.Equal(t, fw.ID, test.firewall.ID)
				assert.Equal(t, fw.Name, test.firewall.Name)
				assert.Equal(t, fw.Status, test.firewall.Status)
				// DeepEqual check needed for slices
				assert.DeepEqual(t, fw.InboundRules, test.firewall.InboundRules)
				assert.DeepEqual(t, fw.DropletIDs, test.firewall.DropletIDs)
				// check that the Firewall Controller firewall name is what is expected
				assert.Equal(t, fc.workerFirewallName, test.firewall.Name)
				assert.NilError(t, err)
			}
		})
	}
}

func TestFirewallController_Set(t *testing.T) {
	workerFirewallName := "test-worker-firewall"
	inboundRule := godo.InboundRule{
		Protocol:  "tcp",
		PortRange: "31000",
		Sources: &godo.Sources{
			Tags:       []string{"my-tag1"},
			DropletIDs: []int{1},
		},
	}

	testcases := []struct {
		name          string
		firewall      *godo.Firewall
		fwCache       *firewallCache
		godoResponse  *godo.Response
		expectedError error
	}{
		{
			name:          "retrieve from local firewall cache if it exists and return nil",
			firewall:      newFakeFirewall(workerFirewallName, inboundRule),
			fwCache:       newFakeFirewallCache(workerFirewallName, inboundRule),
			godoResponse:  nil,
			expectedError: nil,
		},
		{
			name:          "fail to get firewall state and return error",
			firewall:      newFakeFirewall(workerFirewallName, inboundRule),
			fwCache:       nil,
			godoResponse:  newFakeNotOKResponse(),
			expectedError: errors.New("failed to get firewall state"),
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			gclient := newFakeGodoClient(
				&fakeFirewallService{
					getFunc: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
						return test.firewall, test.godoResponse, test.expectedError
					},
					listFunc: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
						return []godo.Firewall{*test.firewall}, test.godoResponse, test.expectedError
					},
				},
			)
			fc, _ := NewFirewallController(workerFirewallName, kclient, gclient, inf.Core().V1().Services(), []string{}, ctx)
			fwManagerOp := newFakeFirewallManagerOp(fc.client, &firewallCache{})
			if test.fwCache != nil {
				fwManagerOp.fwCache = test.fwCache
			}

			err := fwManagerOp.Set(ctx, []godo.InboundRule{inboundRule}, fc)
			if test.expectedError != nil {
				assert.ErrorContains(t, err, test.expectedError.Error())
			} else {
				assert.NilError(t, err)
				// check that the Firewall Controller firewall name is what is expected
				assert.Equal(t, fc.workerFirewallName, test.firewall.Name)
			}
		})
	}
}

func TestFirewallController_Run(t *testing.T) {
	fakeWorkerFirewallName := "myFirewallWorkerName"
	inboundRule := godo.InboundRule{
		Protocol:  "tcp",
		PortRange: "31000",
		Sources: &godo.Sources{
			Tags:       []string{"my-tag1"},
			DropletIDs: []int{1},
		},
	}
	fwCache := newFakeFirewallCache(fakeWorkerFirewallName, inboundRule)
	// setup
	gclient := newFakeGodoClient(
		&fakeFirewallService{
			getFunc: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return &godo.Firewall{}, newFakeOKResponse(), errors.New("failed to get worker firewall")
			},
			listFunc: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				fakeFirewall := godo.Firewall{}
				return []godo.Firewall{fakeFirewall}, newFakeOKResponse(), errors.New("failed to get worker firewall")
			},
		},
	)
	inboundRules := []godo.InboundRule{inboundRule}
	fc, err := NewFirewallController(fakeWorkerFirewallName, kclient, gclient, inf.Core().V1().Services(), []string{}, ctx)
	fc.serviceLister = inf.Core().V1().Services().Lister()

	stop := make(chan struct{})
	fwManagerOp := newFakeFirewallManagerOp(gclient, fwCache)

	// run actual tests
	go fc.Run(ctx, inboundRules, &godo.Firewall{}, fwManagerOp, stop)
	select {
	case <-stop:
		// No-op: test succeeded
		assert.NilError(t, err)
	case <-time.After(3 * time.Second):
		// Terminate goroutines just in case.
		close(stop)
	}
}

func TestFirewallController_createInboundRules(t *testing.T) {
	fakeWorkerFirewallName := "myFirewallWorkerName"
	inboundRule := godo.InboundRule{
		Protocol:  "tcp",
		PortRange: "31220",
	}
	nodePortService := &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
			Ports: []v1.ServicePort{
				{
					Protocol: "tcp",
					Port:     31220,
					NodePort: 31220,
				},
			},
		},
	}
	fakeServiceList := []*v1.Service{nodePortService}

	testcases := []struct {
		name          string
		firewall      *godo.Firewall
		fwCache       *firewallCache
		godoResponse  *godo.Response
		serviceList   []*v1.Service
		expectedError error
	}{
		{
			name:          "successfully updates port range",
			firewall:      nil,
			fwCache:       newFakeFirewallCache(fakeWorkerFirewallName, inboundRule),
			godoResponse:  newFakeOKResponse(),
			serviceList:   fakeServiceList,
			expectedError: nil,
		},
		{
			name:          "fail to get inbound rules when service list is nil",
			firewall:      newFakeFirewall(fakeWorkerFirewallName, inboundRule),
			fwCache:       newFakeFirewallCache(fakeWorkerFirewallName, inboundRule),
			godoResponse:  newFakeOKResponse(),
			serviceList:   nil,
			expectedError: errors.New("failed to retrieve services and their inbound rules"),
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			// setup
			gclient := newFakeGodoClient(
				&fakeFirewallService{
					getFunc: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
						return test.firewall, test.godoResponse, test.expectedError
					},
					listFunc: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
						return []godo.Firewall{*test.firewall}, test.godoResponse, test.expectedError
					},
				},
			)
			inboundRules := []godo.InboundRule{inboundRule}
			fc, err := NewFirewallController(fakeWorkerFirewallName, kclient, gclient, inf.Core().V1().Services(), []string{}, ctx)
			assert.NilError(t, err)
			fwManagerOp := newFakeFirewallManagerOp(gclient, test.fwCache)

			// run actual tests
			rules, err := fwManagerOp.createInboundRules(test.serviceList, fc)
			if test.expectedError != nil {
				assert.ErrorContains(t, err, test.expectedError.Error())
			} else {
				assert.Equal(t, rules[0].PortRange, inboundRules[0].PortRange)
				assert.Equal(t, rules[0].Protocol, inboundRules[0].Protocol)
				assert.NilError(t, err)
			}
		})
	}
}
