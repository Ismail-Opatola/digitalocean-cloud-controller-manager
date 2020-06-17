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
	"testing"
	"time"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFirewallController_Run(t *testing.T) {
	// setup
	fakeWorkerFirewallName := "myFirewallWorkerName"
	kclient := fake.NewSimpleClientset()
	gclient := newFakeClient(
		&fakeDropletService{
			listFunc: func(ctx context.Context, opt *godo.ListOptions) ([]godo.Droplet, *godo.Response, error) {
				return []godo.Droplet{{ID: 2, Name: "two"}}, newFakeOKResponse(), nil
			},
		},
		&fakeLBService{
			listFn: func(context.Context, *godo.ListOptions) ([]godo.LoadBalancer, *godo.Response, error) {
				return []godo.LoadBalancer{{ID: "2", Name: "two"}}, newFakeOKResponse(), nil
			},
		},
		nil,
	)
	fwsvc := &gclient.Firewalls
	inf := informers.NewSharedInformerFactory(kclient, 0)
	tags := []string{"test-tag"}
	inboundRules := []godo.InboundRule{}

	res, err := NewFirewallController(fakeWorkerFirewallName, kclient, gclient, fwsvc, inf.Core().V1().Services(), tags, context.TODO())
	stop := make(chan struct{})
	res.Run(context.TODO(), inboundRules, stop)

	select {
	case <-stop:
		// No-op: test succeeded
	case <-time.After(3 * time.Second):
		// Terminate goroutines just in case.
		close(stop)
		// t.Errorf("got %d distinct sync(s) within timeout, want %d", syncer.synced, wantSyncs)
		assert.NoError(t, err)
		assert.NotNil(t, res)
	}
}
