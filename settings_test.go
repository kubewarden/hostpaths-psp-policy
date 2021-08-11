package main

import (
	"testing"
)

func TestParsingSettingsWithAllValuesProvidedFromValidationReq(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
			"allowedHostPaths": [
				{
					"pathPrefix": "/foo",
					"readOnly": true
				},
				{
					"pathPrefix": "/bar",
					"readOnly": false
				}
			]
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidationReq(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if settings.AllowedHostPaths[0].PathPrefix != "/foo" &&
		settings.AllowedHostPaths[0].ReadOnly != true &&
		settings.AllowedHostPaths[1].PathPrefix != "/bar" &&
		settings.AllowedHostPaths[1].ReadOnly != false {
		t.Errorf("Missing value")
	}
}

func TestParsingSettingsWithNoValueProvided(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidationReq(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if len(settings.AllowedHostPaths) != 0 {
		t.Errorf("Expected AllowedHostPaths to be empty")
	}
}

func TestParsingSettingsWithEntriesMissing(t *testing.T) {
	for _, tcase := range []struct {
		name    string
		request string
		error   string
	}{
		{
			name: "missing pathPrefix",
			request: `
			{
				"request": "doesn't matter here",
				"settings": {
					"allowedHostPaths": [
						{
							"readOnly": true
						}
					]
				}
			}
			`,
			error: "pathPrefix key is missing",
		},
		{
			name: "missing readOnly",
			request: `
			{
				"request": "doesn't matter here",
				"settings": {
					"allowedHostPaths": [
						{
							"readOnly": true
						},
						{
							"pathPrefix": "/foo"
						}
					]
				}
			}
			`,
			error: "pathPrefix key is missing; readOnly key for pathPrefix '/foo' is missing",
		},
	} {
		t.Run(tcase.name, func(t *testing.T) {
			rawRequest := []byte(tcase.request)

			_, err := NewSettingsFromValidationReq(rawRequest)
			if err == nil {
				t.Errorf("Wanted error, but no error was found")
			}
			if err.Error() != tcase.error {
				t.Errorf("Wanted error '%s', but got '%s' instead",
					tcase.error, err.Error())
			}
		})
	}
}

func TestEmptySettingsAreValid(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidateSettingsPayload(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if !settings.Valid() {
		t.Errorf("Settings are reported as not valid")
	}
}
