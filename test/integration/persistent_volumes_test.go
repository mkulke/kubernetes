// +build integration,!no-etcd

/*
Copyright 2014 The Kubernetes Authors All rights reserved.

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

package integration

import (
	"testing"
	"time"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/resource"
	"k8s.io/kubernetes/pkg/api/testapi"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/controller/persistentvolume"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/watch"
)

func init() {
	requireEtcd()
}

func TestPersistentVolumeClaimBinder(t *testing.T) {
	_, s := runAMaster(t)
	defer s.Close()

	deleteAllEtcdKeys()
	binderClient := client.NewOrDie(&client.Config{Host: s.URL, Version: testapi.Default.Version()})
	testClient := client.NewOrDie(&client.Config{Host: s.URL, Version: testapi.Default.Version()})

	binder := volumeclaimbinder.NewPersistentVolumeClaimBinder(binderClient, 1*time.Second)
	binder.Run()
	defer binder.Stop()

	for _, volume := range createTestVolumes() {
		_, err := testClient.PersistentVolumes().Create(volume)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	volumes, err := testClient.PersistentVolumes().List(labels.Everything(), fields.Everything())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(volumes.Items) != 2 {
		t.Errorf("expected 2 PVs, got %#v", len(volumes.Items))
	}

	for _, claim := range createTestClaims() {
		_, err := testClient.PersistentVolumeClaims(api.NamespaceDefault).Create(claim)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	claims, err := testClient.PersistentVolumeClaims(api.NamespaceDefault).List(labels.Everything(), fields.Everything())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(claims.Items) != 3 {
		t.Errorf("expected 3 PVCs, got %#v", len(claims.Items))
	}

	// the binder will eventually catch up and set status on Claims
	watch, err := testClient.PersistentVolumeClaims(api.NamespaceDefault).Watch(labels.Everything(), fields.Everything(), "0")
	if err != nil {
		t.Fatalf("Couldn't subscribe to PersistentVolumeClaims: %v", err)
	}
	defer watch.Stop()

	// Wait for claim01 and claim02 to become bound
	claim01Pending := true
	claim02Pending := true
	for claim01Pending || claim02Pending {
		event := <-watch.ResultChan()
		claim := event.Object.(*api.PersistentVolumeClaim)
		if claim.Spec.VolumeName != "" && claim.Status.Phase != "Bound" {
			if claim.Name == "claim01" {
				claim01Pending = false
			} else if claim.Name == "claim02" {
				claim02Pending = false
			}
		}
	}

	for _, claim := range createTestClaims() {
		claim, err := testClient.PersistentVolumeClaims(api.NamespaceDefault).Get(claim.Name)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if (claim.Name == "claim01" || claim.Name == "claim02") && claim.Spec.VolumeName == "" {
			t.Errorf("Expected claim to be bound: %+v", claim)
		}
		if claim.Name == "claim03" && claim.Spec.VolumeName != "" {
			t.Errorf("Expected claim03 to be unbound: %v", claim)
		}
	}
}

func createTestClaims() []*api.PersistentVolumeClaim {
	return []*api.PersistentVolumeClaim{
		{
			ObjectMeta: api.ObjectMeta{
				Name:      "claim03",
				Namespace: api.NamespaceDefault,
			},
			Spec: api.PersistentVolumeClaimSpec{
				AccessModes: []api.PersistentVolumeAccessMode{api.ReadWriteOnce},
				Resources: api.ResourceRequirements{
					Requests: api.ResourceList{
						api.ResourceName(api.ResourceStorage): resource.MustParse("500G"),
					},
				},
			},
		},
		{
			ObjectMeta: api.ObjectMeta{
				Name:      "claim01",
				Namespace: api.NamespaceDefault,
			},
			Spec: api.PersistentVolumeClaimSpec{
				AccessModes: []api.PersistentVolumeAccessMode{api.ReadOnlyMany, api.ReadWriteOnce},
				Resources: api.ResourceRequirements{
					Requests: api.ResourceList{
						api.ResourceName(api.ResourceStorage): resource.MustParse("8G"),
					},
				},
			},
		},
		{
			ObjectMeta: api.ObjectMeta{
				Name:      "claim02",
				Namespace: api.NamespaceDefault,
			},
			Spec: api.PersistentVolumeClaimSpec{
				AccessModes: []api.PersistentVolumeAccessMode{api.ReadOnlyMany, api.ReadWriteOnce, api.ReadWriteMany},
				Resources: api.ResourceRequirements{
					Requests: api.ResourceList{
						api.ResourceName(api.ResourceStorage): resource.MustParse("5G"),
					},
				},
			},
		},
	}
}

func createTestVolumes() []*api.PersistentVolume {
	return []*api.PersistentVolume{
		{
			ObjectMeta: api.ObjectMeta{
				UID:  "gce-pd-10",
				Name: "gce003",
			},
			Spec: api.PersistentVolumeSpec{
				Capacity: api.ResourceList{
					api.ResourceName(api.ResourceStorage): resource.MustParse("10G"),
				},
				PersistentVolumeSource: api.PersistentVolumeSource{
					GCEPersistentDisk: &api.GCEPersistentDiskVolumeSource{
						PDName: "gce123123123",
						FSType: "foo",
					},
				},
				AccessModes: []api.PersistentVolumeAccessMode{
					api.ReadWriteOnce,
					api.ReadOnlyMany,
				},
			},
		},
		{
			ObjectMeta: api.ObjectMeta{
				UID:  "nfs-5",
				Name: "nfs002",
			},
			Spec: api.PersistentVolumeSpec{
				Capacity: api.ResourceList{
					api.ResourceName(api.ResourceStorage): resource.MustParse("5G"),
				},
				PersistentVolumeSource: api.PersistentVolumeSource{
					Glusterfs: &api.GlusterfsVolumeSource{
						EndpointsName: "andintheend",
						Path:          "theloveyoutakeisequaltotheloveyoumake",
					},
				},
				AccessModes: []api.PersistentVolumeAccessMode{
					api.ReadWriteOnce,
					api.ReadOnlyMany,
					api.ReadWriteMany,
				},
			},
		},
	}
}

func TestPersistentVolumeRecycler(t *testing.T) {
	_, s := runAMaster(t)
	defer s.Close()

	deleteAllEtcdKeys()
	binderClient := client.NewOrDie(&client.Config{Host: s.URL, Version: testapi.Default.Version()})
	recyclerClient := client.NewOrDie(&client.Config{Host: s.URL, Version: testapi.Default.Version()})
	testClient := client.NewOrDie(&client.Config{Host: s.URL, Version: testapi.Default.Version()})

	binder := volumeclaimbinder.NewPersistentVolumeClaimBinder(binderClient, 1*time.Second)
	binder.Run()
	defer binder.Stop()

	recycler, _ := volumeclaimbinder.NewPersistentVolumeRecycler(recyclerClient, 1*time.Second, []volume.VolumePlugin{&volume.FakeVolumePlugin{"plugin-name", volume.NewFakeVolumeHost("/tmp/fake", nil, nil)}})
	recycler.Run()
	defer recycler.Stop()

	// This PV will be claimed, released, and recycled.
	pv := &api.PersistentVolume{
		ObjectMeta: api.ObjectMeta{Name: "fake-pv"},
		Spec: api.PersistentVolumeSpec{
			PersistentVolumeSource:        api.PersistentVolumeSource{HostPath: &api.HostPathVolumeSource{Path: "foo"}},
			Capacity:                      api.ResourceList{api.ResourceName(api.ResourceStorage): resource.MustParse("10G")},
			AccessModes:                   []api.PersistentVolumeAccessMode{api.ReadWriteOnce},
			PersistentVolumeReclaimPolicy: api.PersistentVolumeReclaimRecycle,
		},
	}

	pvc := &api.PersistentVolumeClaim{
		ObjectMeta: api.ObjectMeta{Name: "fake-pvc"},
		Spec: api.PersistentVolumeClaimSpec{
			Resources:   api.ResourceRequirements{Requests: api.ResourceList{api.ResourceName(api.ResourceStorage): resource.MustParse("5G")}},
			AccessModes: []api.PersistentVolumeAccessMode{api.ReadWriteOnce},
		},
	}

	watch, _ := testClient.PersistentVolumes().Watch(labels.Everything(), fields.Everything(), "0")
	defer watch.Stop()

	_, _ = testClient.PersistentVolumes().Create(pv)
	_, _ = testClient.PersistentVolumeClaims(api.NamespaceDefault).Create(pvc)

	// wait until the binder pairs the volume and claim
	waitForPersistentVolumePhase(watch, api.VolumeBound)

	// deleting a claim releases the volume, after which it can be recycled
	if err := testClient.PersistentVolumeClaims(api.NamespaceDefault).Delete(pvc.Name); err != nil {
		t.Errorf("error deleting claim %s", pvc.Name)
	}

	waitForPersistentVolumePhase(watch, api.VolumeReleased)
	waitForPersistentVolumePhase(watch, api.VolumeAvailable)
}

func waitForPersistentVolumePhase(w watch.Interface, phase api.PersistentVolumePhase) {
	for {
		event := <-w.ResultChan()
		volume := event.Object.(*api.PersistentVolume)
		if volume.Status.Phase == phase {
			break
		}
	}
}

func TestPersistentVolumeDeleter(t *testing.T) {
	_, s := runAMaster(t)
	defer s.Close()

	deleteAllEtcdKeys()
	binderClient := client.NewOrDie(&client.Config{Host: s.URL, Version: testapi.Default.Version()})
	recyclerClient := client.NewOrDie(&client.Config{Host: s.URL, Version: testapi.Default.Version()})
	testClient := client.NewOrDie(&client.Config{Host: s.URL, Version: testapi.Default.Version()})

	binder := volumeclaimbinder.NewPersistentVolumeClaimBinder(binderClient, 1*time.Second)
	binder.Run()
	defer binder.Stop()

	recycler, _ := volumeclaimbinder.NewPersistentVolumeRecycler(recyclerClient, 1*time.Second, []volume.VolumePlugin{&volume.FakeVolumePlugin{"plugin-name", volume.NewFakeVolumeHost("/tmp/fake", nil, nil)}})
	recycler.Run()
	defer recycler.Stop()

	// This PV will be claimed, released, and recycled.
	pv := &api.PersistentVolume{
		ObjectMeta: api.ObjectMeta{Name: "fake-pv"},
		Spec: api.PersistentVolumeSpec{
			PersistentVolumeSource:        api.PersistentVolumeSource{HostPath: &api.HostPathVolumeSource{Path: "/tmp/foo"}},
			Capacity:                      api.ResourceList{api.ResourceName(api.ResourceStorage): resource.MustParse("10G")},
			AccessModes:                   []api.PersistentVolumeAccessMode{api.ReadWriteOnce},
			PersistentVolumeReclaimPolicy: api.PersistentVolumeReclaimDelete,
		},
	}

	pvc := &api.PersistentVolumeClaim{
		ObjectMeta: api.ObjectMeta{Name: "fake-pvc"},
		Spec: api.PersistentVolumeClaimSpec{
			Resources:   api.ResourceRequirements{Requests: api.ResourceList{api.ResourceName(api.ResourceStorage): resource.MustParse("5G")}},
			AccessModes: []api.PersistentVolumeAccessMode{api.ReadWriteOnce},
		},
	}

	w, _ := testClient.PersistentVolumes().Watch(labels.Everything(), fields.Everything(), "0")
	defer w.Stop()

	_, _ = testClient.PersistentVolumes().Create(pv)
	_, _ = testClient.PersistentVolumeClaims(api.NamespaceDefault).Create(pvc)

	// wait until the binder pairs the volume and claim
	waitForPersistentVolumePhase(w, api.VolumeBound)

	// deleting a claim releases the volume, after which it can be recycled
	if err := testClient.PersistentVolumeClaims(api.NamespaceDefault).Delete(pvc.Name); err != nil {
		t.Errorf("error deleting claim %s", pvc.Name)
	}

	waitForPersistentVolumePhase(w, api.VolumeReleased)

	for {
		event := <-w.ResultChan()
		if event.Type == watch.Deleted {
			break
		}
	}
}
