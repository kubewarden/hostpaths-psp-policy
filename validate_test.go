package main

import (
	"encoding/json"
	"testing"

	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestEmptySettingsLeadsToApproval(t *testing.T) {
	settings := Settings{}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/request-pod-hostpaths.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
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
		payload, err := kubewarden_testing.BuildValidationRequest(
			tcase.testData,
			&tcase.settings)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		responsePayload, err := validate(payload)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		var response kubewarden_testing.ValidationResponse
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
			error: "hostPath '/data' is not in the AllowedHostPaths list",
		},
		{
			name:     "volumeMount /data should be readWrite",
			testData: "test_data/request-pod-hostpaths.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/data",
						ReadOnly:   false,
					},
				},
			},
			error: "hostPath '/data' should be readOnly 'false'",
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
			error: "hostPath '/var/local/aaa' should be readOnly 'true'",
		},
		{
			name:     "disallow /data if prefix is /dat",
			testData: "test_data/request-pod-hostpaths.json",
			settings: Settings{
				AllowedHostPaths: []HostPath{
					{
						PathPrefix: "/dat",
						ReadOnly:   true,
					},
				},
			},
			error: "hostPath '/data' is not in the AllowedHostPaths list",
		},
	} {
		payload, err := kubewarden_testing.BuildValidationRequest(
			tcase.testData,
			&tcase.settings)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		responsePayload, err := validate(payload)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		var response kubewarden_testing.ValidationResponse
		if err := json.Unmarshal(responsePayload, &response); err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		if response.Accepted != false {
			t.Errorf("on test %q, got unexpected approval", tcase.name)
		}

		if response.Message != tcase.error {
			t.Errorf("on test %q, got '%s' instead of '%s'",
				tcase.name, response.Message, tcase.error)
		}
	}
}
