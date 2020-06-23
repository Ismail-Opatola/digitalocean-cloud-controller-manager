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
	// "fmt"

	"testing"

	"github.com/digitalocean/godo"
	"gotest.tools/assert"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

var (
	ctx = context.TODO()

	kclient = fake.NewSimpleClientset()

	inf = informers.NewSharedInformerFactory(kclient, 0)
)

type fakeFirewallManager struct {
	getFunc func(ctx context.Context, inboundRules []godo.InboundRule, c *FirewallController) (godo.Firewall, error)
	setFunc func(ctx context.Context, inboundRules []godo.InboundRule, c *FirewallController) error
}

// Get returns the current CCM worker firewall representation.
func (f *fakeFirewallManager) Get(ctx context.Context, inboundRules []godo.InboundRule, c *FirewallController) (godo.Firewall, error) {
	return f.getFunc(ctx, inboundRules, c)
}

// Set applies the given inbound rules to the CCM worker firewall when the current rules and target rules differ.
func (f *fakeFirewallManager) Set(ctx context.Context, inboundRules []godo.InboundRule, c *FirewallController) error {
	return f.setFunc(ctx, inboundRules, c)
}

// func newFakeFirewallManager(firewall godo.Firewall) *FirewallManager {
// 	return &FirewallManager{
// 		getFunc: func(ctx context.Context, inboundRules []godo.InboundRule, c *FirewallController) (godo.Firewall, error) {
// 			return firewall, nil
// 		},
// 		setFunc: func(ctx context.Context, inboundRules []godo.InboundRule, c *FirewallController) error {
// 			return nil
// 		},
// 	}
// }

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
			name:          "retrieve from DO firewall API and update local cache",
			firewall:      newFakeFirewall(workerFirewallName, inboundRule),
			fwCache:       newFakeFirewallCache(workerFirewallName, inboundRule),
			godoResponse:  newFakeOKResponse(),
			expectedError: nil,
		},
		{
			name:          "fails to get worker firewall from DO firewall API and returns error",
			firewall:      newFakeFirewall(workerFirewallName, inboundRule),
			fwCache:       nil,
			godoResponse:  newFakeNotOKResponse(),
			expectedError: errors.New("failed to retrieve firewall from DO firewall API:"),
		},
		// {
		// 	name:     "gets worker firewall from cache",
		// 	firewall: newFakeFirewall(workerFirewallName, inboundRule),
		// 	fwCache: &firewallCache{
		// 		firewall: &cachedFirewall{
		// 			state: &godo.Firewall{
		// 				ID:           "123",
		// 				Name:         "test-worker-firewall",
		// 				InboundRules: []godo.InboundRule{inboundRule},
		// 			},
		// 		},
		// 	},
		// 	godoResponse:  nil,
		// 	expectedError: errors.New("failed to retrieve firewall from DO firewall API"),
		// },
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
			}
		})
	}
}

// func TestFirewallController_Get(t *testing.T) {
// 	testcases := []struct {
// 		name               string
// 		workerFirewallName string
// 		inboundRule        godo.InboundRule
// 		fwCache            *firewallCache
// 		godoResponse       *godo.Response
// 		expectedError      error
// 	}{
// 		{
// 			name:               "fails to get worker firewall from cache",
// 			workerFirewallName: "test-worker-firewall",
// 			inboundRule: &godo.InboundRule{
// 				Protocol:  "tcp",
// 				PortRange: "31000",
// 				Sources: &godo.Sources{
// 					Tags:       []string{"my-tag1"},
// 					DropletIDs: []int{1},
// 				},
// 			},
// 			fwCache:       nil,
// 			godoResponse:  newFakeOKResponse(),
// 			expectedError: nil,
// 		},
// 		{
// 			name:               "fails to get worker firewall from DO firewall API",
// 			workerFirewallName: "test-worker-firewall",
// 			inboundRule: &godo.InboundRule{
// 				Protocol:  "tcp",
// 				PortRange: "31000",
// 				Sources: &godo.Sources{
// 					Tags:       []string{"my-tag1"},
// 					DropletIDs: []int{1},
// 				},
// 			},
// 			fwCache:       nil,
// 			godoResponse:  newFakeNotOkResponse(),
// 			expectedError: errors.New("failed to retrieve firewall from DO firewall API:"),
// 		},
// 		{
// 			name:               "gets worker firewall from cache",
// 			workerFirewallName: "test-worker-firewall",
// 			inboundRule: &godo.InboundRule{
// 				Protocol:  "tcp",
// 				PortRange: "31000",
// 				Sources: &godo.Sources{
// 					Tags:       []string{"my-tag1"},
// 					DropletIDs: []int{1},
// 				},
// 			},
// 			fwCache: &firewallCache{
// 				firewall: &cachedFirewall{
// 					state: &godo.Firewall{
// 						ID:   "123",
// 						Name: "test-worker-firewall",
// 						InboundRules: []godo.InboundRule{
// 							&godo.InboundRule{
// 								Protocol:  "tcp",
// 								PortRange: "31000",
// 								Sources: &godo.Sources{
// 									Tags:       []string{"my-tag1"},
// 									DropletIDs: []int{1},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 			godoResponse:  nil,
// 			expectedError: nil,
// 		},
// 	}

// 	for _, test := range testcases {
// 		gclient := newFakeClient{
// 			&fakeFirewallService{
// 				getFunc: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
// 					return newFakeFirewall(test.workerFirewallName, test.inboundRule), test.godoResponse, test.expectedError
// 				},
// 				listFunc: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
// 					return newFakeFirewall(test.workerFirewallName, test.inboundRule), test.godoResponse, test.expectedError
// 				},
// 			},
// 		},
// 	},
// }

// func TestFirewallController_Run(t *testing.T) {
// 	// setup arguments
// 	fakeWorkerFirewallName := "myFirewallWorkerName"
// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte(`{"account":null}`))
// 	}))
// 	gclient, _ := godo.New(http.DefaultClient, godo.SetBaseURL(ts.URL))
// 	var fwManager FirewallManager
// 	fwManager = FirewallManager{
// 		client:  gclient,
// 		fwCache: &firewallCache{},
// 	}
// 	rule := &godo.InboundRule{}
// 	inboundRules := []godo.InboundRule{*rule}
// 	fc, err := NewFirewallController(fakeWorkerFirewallName, kclient, gclient, inf.Core().V1().Services(), []string{}, &fwManager, ctx)
// 	stop := make(chan struct{})

// 	// run actual tests
// 	fwManagerOp := newFakeFirewallManagerOp()
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

// func TestFirewallController_Get(t *testing.T) {
// 	// setup arguments
// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte(`{"account":null}`))
// 	}))
// 	gclient, _ := godo.New(http.DefaultClient, godo.SetBaseURL(ts.URL))

// sources := &godo.Sources{
// 	Tags:       []string{"my-tag1", "my-tag2"},
// 	DropletIDs: []int{1, 2, 3},
// }
// 	// setup firewall manager
// 	rule := &godo.InboundRule{
// 		Protocol:  "tcp",
// 		PortRange: "31000",
// 		Sources:   sources,
// 	}
// 	inboundRules := []godo.InboundRule{*rule}
// 	expectedFirewall := &godo.Firewall{
// 		ID:           "123",
// 		Name:         fakeWorkerFirewallName,
// 		InboundRules: inboundRules,
// 	}
// 	cachedFw := &stubCachedFirewall{state: expectedFirewall}
// 	var fwManager FirewallManager
// 	fwManager = &stubFirewallManagerOp{
// 		client:  gclient,
// 		fwCache: &stubFirewallCache{firewall: cachedFw},
// 	}
// 	fc, err := NewFirewallController(fakeWorkerFirewallName, kclient, gclient, inf.Core().V1().Services(), []string{}, &fwManager, ctx)
// 	// handle godo http requests
// 	urlStr := "/v2/firewalls"
// 	fID := "fe6b88f2-b42b-4bf7-bbd3-5ae20208f0b0"
// 	urlStr = path.Join(urlStr, fID)

// 	mux.HandleFunc(urlStr, func(w http.ResponseWriter, r *http.Request) {
// 		testMethod(t, r, http.MethodGet)
// 		fmt.Fprint(w, firewallJSONResponse)
// 	})

// 	// run actual tests
// 	actualFirewall, err := fwManager.Get(ctx, inboundRules, fc)
// 	assert.NoError(t, err)
// 	assert.Equal(t, expectedFirewall, actualFirewall)
// }