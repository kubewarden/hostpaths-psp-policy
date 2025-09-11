package main

import (
	"encoding/json"
	"testing"

	appsv1 "github.com/kubewarden/k8s-objects/api/apps/v1"
	batchv1 "github.com/kubewarden/k8s-objects/api/batch/v1"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func ptrString(s string) *string {
	return &s
}

func TestEmptySettingsLeadsToApproval(t *testing.T) {
	settings := Settings{}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/request-pod-hostpaths.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestApproval(t *testing.T) {
	for _, tcase := range []struct {
		name     string
		testData string
		settings Settings
	}{
		{
			name:     "pod without hostpaths",
			testData: "test_data/request-pod-no-hostpaths.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/foo",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/foo/bar",
						ReadOnly:   true,
					},
				},
			},
		},
		{
			name:     "/data hostpath as readOnly, no precedence",
			testData: "test_data/request-pod-hostpaths.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/data",
						ReadOnly:   true,
					},
					{
						PathPrefix: "/var",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/var/local/aaa",
						ReadOnly:   false,
					},
				},
			},
		},
		{
			name:     "precedence readonly most specific path",
			testData: "test_data/request-pod-precedence.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/var",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/var/local",
						ReadOnly:   true,
					},
				},
			},
		},
		{
			name:     "multiple containers precedence readonly most specific path",
			testData: "test_data/request-pod-multiple-containers.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/var",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/var/local",
						ReadOnly:   true,
					},
				},
			},
		},
	} {
		payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
			tcase.testData,
			&tcase.settings)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		responsePayload, err := validate(payload)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		var response kubewarden_protocol.ValidationResponse
		if err := json.Unmarshal(responsePayload, &response); err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		if response.Accepted != true {
			t.Errorf("on test %q, got unexpected rejection", tcase.name)
		}
	}
}

func TestRejection(t *testing.T) {
	for _, tcase := range []struct {
		name     string
		testData string
		settings Settings
		error    string
	}{
		{
			name:     "volumeMount /data is not in settings",
			testData: "test_data/request-pod-hostpaths.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/var",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/var/local/aaa",
						ReadOnly:   false,
					},
				},
			},
			error: "hostPath '/data' mounted as 'test-data' is not in the AllowedHostPaths list",
		},
		{
			name:     "volumeMount /data should be readWrite",
			testData: "test_data/request-pod-hostpaths.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						// testcase:
						PathPrefix: "/data",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/var",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/var/local/aaa",
						ReadOnly:   false,
					},
				},
			},
			error: "hostPath '/data' mounted as 'test-data' should be readOnly 'false'",
		},
		{
			name:     "volumeMount /var/local/aaa should be readOnly",
			testData: "test_data/request-pod-hostpaths.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/data",
						ReadOnly:   true,
					},
					{
						PathPrefix: "/var",
						ReadOnly:   false,
					},
					{
						// testcase:
						PathPrefix: "/var/local/aaa",
						ReadOnly:   true,
					},
				},
			},
			error: "hostPath '/var/local/aaa' mounted as 'test-var-local-aaa' should be readOnly 'true';" +
				" hostPath '/var/local/aaa' mounted as 'test-var-local-aaa' should be readOnly 'true'",
		},
		{
			name:     "precedence read only least specific path",
			testData: "test_data/request-pod-precedence-least.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/var",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/var/local",
						ReadOnly:   true,
					},
				},
			},
			error: "hostPath '/var/local/aaa' mounted as 'test-var-local-aaa' should be readOnly 'true'",
		},
		{
			name:     "disallow /data if prefix is /dat",
			testData: "test_data/request-pod-hostpaths.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						// testcase:
						PathPrefix: "/dat",
						ReadOnly:   true,
					},
					{
						PathPrefix: "/var",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/var/local/aaa",
						ReadOnly:   false,
					},
				},
			},
			error: "hostPath '/data' mounted as 'test-data' is not in the AllowedHostPaths list",
		},
		{
			name:     "several errors",
			testData: "test_data/request-pod-hostpaths.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/data",
						ReadOnly:   false,
					},
					{
						PathPrefix: "/va",
						ReadOnly:   true,
					},
					{
						PathPrefix: "/var/local/aaa",
						ReadOnly:   true,
					},
				},
			},
			error: "hostPath '/data' mounted as 'test-data' should be readOnly 'false';" +
				" hostPath '/var' mounted as 'test-var' is not in the AllowedHostPaths list;" +
				" hostPath '/var' mounted as 'test-var' is not in the AllowedHostPaths list;" +
				" hostPath '/var/local/aaa' mounted as 'test-var-local-aaa' should be readOnly 'true';" +
				" hostPath '/var/local/aaa' mounted as 'test-var-local-aaa' should be readOnly 'true'",
		},
	} {
		payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
			tcase.testData,
			&tcase.settings)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		responsePayload, err := validate(payload)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		var response kubewarden_protocol.ValidationResponse
		if err := json.Unmarshal(responsePayload, &response); err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		if response.Accepted != false {
			t.Errorf("on test %q, got unexpected approval", tcase.name)
		}

		if *response.Message != tcase.error {
			t.Errorf("on test %q, got '%s' instead of '%s'",
				tcase.name, *response.Message, tcase.error)
		}
	}
}

func TestWorkloadTypes(t *testing.T) {
	commonPodSpec := corev1.PodSpec{
		Volumes: []*corev1.Volume{
			{
				Name: ptrString("test-data"),
				HostPath: &corev1.HostPathVolumeSource{
					Path: ptrString("/data"),
					Type: "Directory",
				},
			},
			{
				Name: ptrString("test-var"),
				HostPath: &corev1.HostPathVolumeSource{
					Path: ptrString("/var"),
					Type: "Directory",
				},
			},
			{
				Name: ptrString("test-var-local-aaa"),
				HostPath: &corev1.HostPathVolumeSource{
					Path: ptrString("/var/local/aaa"),
					Type: "DirectoryOrCreate",
				},
			},
			{
				Name: ptrString("kube-api-access-kplj9"),
				Projected: &corev1.ProjectedVolumeSource{
					DefaultMode: 420,
					Sources: []*corev1.VolumeProjection{
						{
							ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
								ExpirationSeconds: 3607,
								Path:              ptrString("token"),
							},
						},
						{
							ConfigMap: &corev1.ConfigMapProjection{
								Name: "kube-root-ca.crt",
								Items: []*corev1.KeyToPath{
									{
										Key:  ptrString("ca.crt"),
										Path: ptrString("ca.crt"),
									},
								},
							},
						},
						{
							DownwardAPI: &corev1.DownwardAPIProjection{
								Items: []*corev1.DownwardAPIVolumeFile{
									{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  ptrString("metadata.namespace"),
										},
										Path: ptrString("namespace"),
									},
								},
							},
						},
					},
				},
			},
		},
		InitContainers: []*corev1.Container{
			{
				VolumeMounts: []*corev1.VolumeMount{
					{
						MountPath: ptrString("/test-data-init"),
						Name:      ptrString("test-data"),
						ReadOnly:  true,
					},
				},
			},
			{
				VolumeMounts: []*corev1.VolumeMount{
					{
						MountPath: ptrString("/test-var-init2"),
						Name:      ptrString("test-var"),
					},
				},
			},
		},
		Containers: []*corev1.Container{
			{
				VolumeMounts: []*corev1.VolumeMount{
					{
						MountPath: ptrString("/test-var"),
						Name:      ptrString("test-var"),
					},
					{
						MountPath: ptrString("/test-var-local-aaa"),
						Name:      ptrString("test-var-local-aaa"),
					},
					{
						MountPath: ptrString("/var/run/secrets/kubernetes.io/serviceaccount"),
						Name:      ptrString("kube-api-access-kplj9"),
						ReadOnly:  true,
					},
				},
			},
			{
				VolumeMounts: []*corev1.VolumeMount{
					{
						MountPath: ptrString("/test-var-local-aaa"),
						Name:      ptrString("test-var-local-aaa"),
					},
				},
			},
		},
	}
	commonSettings := Settings{
		AllowedHostPaths: []HostPath{
			{
				PathPrefix: "/data",
				ReadOnly:   false,
			},
			{
				PathPrefix: "/va",
				ReadOnly:   true,
			},
			{
				PathPrefix: "/var/local/aaa",
				ReadOnly:   true,
			},
		},
	}
	commontError := "hostPath '/data' mounted as 'test-data' should be readOnly 'false';" +
		" hostPath '/var' mounted as 'test-var' is not in the AllowedHostPaths list;" +
		" hostPath '/var' mounted as 'test-var' is not in the AllowedHostPaths list;" +
		" hostPath '/var/local/aaa' mounted as 'test-var-local-aaa' should be readOnly 'true';" +
		" hostPath '/var/local/aaa' mounted as 'test-var-local-aaa' should be readOnly 'true'"
	for _, tcase := range []struct {
		name     string
		kind     kubewarden_protocol.GroupVersionKind
		payload  any
		settings Settings
		error    string
	}{
		{
			name: "deployment",
			kind: kubewarden_protocol.GroupVersionKind{
				Group:   "apps",
				Version: "v1",
				Kind:    "Deployment",
			},
			payload: appsv1.Deployment{
				Spec: &appsv1.DeploymentSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &commonPodSpec,
					},
				},
			},
			settings: commonSettings,
			error:    commontError,
		},

		{
			name: "replicaset",
			kind: kubewarden_protocol.GroupVersionKind{
				Group:   "apps",
				Version: "v1",
				Kind:    "ReplicaSet",
			},
			payload: appsv1.ReplicaSet{
				Spec: &appsv1.ReplicaSetSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &commonPodSpec,
					},
				},
			},
			settings: commonSettings,
			error:    commontError,
		},
		{
			name: "statefulset",
			kind: kubewarden_protocol.GroupVersionKind{
				Group:   "apps",
				Version: "v1",
				Kind:    "StatefulSet",
			},
			payload: appsv1.StatefulSet{
				Spec: &appsv1.StatefulSetSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &commonPodSpec,
					},
				},
			},
			settings: commonSettings,
			error:    commontError,
		},
		{
			name: "daemonset",
			kind: kubewarden_protocol.GroupVersionKind{
				Group:   "apps",
				Version: "v1",
				Kind:    "DaemonSet",
			},
			payload: appsv1.DaemonSet{
				Spec: &appsv1.DaemonSetSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &commonPodSpec,
					},
				},
			},
			settings: commonSettings,
			error:    commontError,
		},
		{
			name: "cronjob",
			kind: kubewarden_protocol.GroupVersionKind{
				Group:   "batch",
				Version: "v1",
				Kind:    "CronJob",
			},
			payload: batchv1.CronJob{
				Spec: &batchv1.CronJobSpec{
					JobTemplate: &batchv1.JobTemplateSpec{
						Spec: &batchv1.JobSpec{
							Template: &corev1.PodTemplateSpec{
								Spec: &commonPodSpec,
							},
						},
					},
				},
			},
			settings: commonSettings,
			error:    commontError,
		},
		{
			name: "job",
			kind: kubewarden_protocol.GroupVersionKind{
				Group:   "batch",
				Version: "v1",
				Kind:    "Job",
			},
			payload: batchv1.Job{
				Spec: &batchv1.JobSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &commonPodSpec,
					},
				},
			},
			settings: commonSettings,
			error:    commontError,
		},
		{
			name: "replicationcontroller",
			kind: kubewarden_protocol.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "ReplicationController",
			},
			payload: corev1.ReplicationController{
				Spec: &corev1.ReplicationControllerSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &commonPodSpec,
					},
				},
			},
			settings: commonSettings,
			error:    commontError,
		},
	} {
		t.Run(tcase.name, func(t *testing.T) {
			objectRaw, err := json.Marshal(tcase.payload)
			if err != nil {
				t.Fatalf("on test %q, got unexpected error '%+v'", tcase.name, err)
			}

			kubeAdmissionReq := kubewarden_protocol.KubernetesAdmissionRequest{
				Kind:   tcase.kind,
				Object: objectRaw,
			}

			settingsRaw, err := json.Marshal(tcase.settings)
			if err != nil {
				t.Fatalf("on test %q, got unexpected error '%+v'", tcase.name, err)
			}

			validationRequest := kubewarden_protocol.ValidationRequest{
				Request:  kubeAdmissionReq,
				Settings: settingsRaw,
			}

			payload, err := json.Marshal(validationRequest)
			if err != nil {
				t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
			}

			responsePayload, err := validate(payload)
			if err != nil {
				t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
			}

			var response kubewarden_protocol.ValidationResponse
			if err := json.Unmarshal(responsePayload, &response); err != nil {
				t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
			}

			if response.Accepted != false {
				t.Fatalf("on test %q, got unexpected approval", tcase.name)
			}

			if *response.Message != tcase.error {
				t.Errorf("on test %q, got '%s' instead of '%s'",
					tcase.name, *response.Message, tcase.error)
			}
		})
	}
}
