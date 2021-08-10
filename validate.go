package main

import (
	"fmt"
	"strings"

	onelog "github.com/francoispqt/onelog"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
)

func validate(payload []byte) ([]byte, error) {
	settings, err := NewSettingsFromValidationReq(payload)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	logger.Info("validating request")

	if len(settings.AllowedHostPaths) == 0 {
		// empty settings, accepting
		return kubewarden.AcceptRequest()
	}

	volumes := gjson.GetBytes(
		payload,
		"request.object.spec.volumes")
	if !volumes.Exists() {
		// pod defines no volumes, accepting
		return kubewarden.AcceptRequest()
	}

	var volumeMounts gjson.Result
	// workaround bug when obtaining array
	// request.object.spec.containers.volumeMounts
	for _, object := range gjson.GetBytes(payload,
		"request.object.spec.containers").Array() {
		if gjson.Get(object.String(), "volumeMounts").Exists() {
			volumeMounts = gjson.Get(object.String(), "volumeMounts")
		}
	}

	if !volumeMounts.Exists() {
		// pod defines no mounts, accepting
		return kubewarden.AcceptRequest()
	}

	logger.DebugWithFields("validating pod object", func(e onelog.Entry) {
		name := gjson.GetBytes(payload, "request.object.metadata.name").String()
		namespace := gjson.GetBytes(payload,
			"request.object.metadata.namespace").String()
		e.String("name", name)
		e.String("namespace", namespace)
	})

	for _, volume := range volumes.Array() {
		if gjson.Get(volume.String(), "hostPath").Exists() {
			volumeName := gjson.Get(volume.String(), "name").String()

			// obtain volumeMount object matching the 'volume.name'
			mount := gjson.Get(volumeMounts.String(),
				fmt.Sprintf("#(name==\"%s\")", volumeName))

			if mount.Exists() {
				// is a hostpath and is in use, validate against settings

				readOnly := false // volumeMount.readOnly missing means 'false'
				if gjson.Get(mount.String(), "readOnly").Exists() {
					readOnly = gjson.Get(mount.String(), "readOnly").Bool()
				}

				path := gjson.Get(volume.String(), "hostPath.path").String()

				match := false
				// readOnly attribute of most specific AllowedHostPath takes precendence:
				previousAllowedHostPath := ""
				for _, allowedHostPath := range settings.AllowedHostPaths {
					if hasPathPrefix(path, allowedHostPath.PathPrefix) {
						// current setting allowedHostPath matches path of volumeMount
						if hasPathPrefix(allowedHostPath.PathPrefix, previousAllowedHostPath) {
							// allowedHostPath is more specific (and has precendence over
							//	past allowedHostPath), or the same path
							match = true
							err = validatePath(path, readOnly, allowedHostPath)
							previousAllowedHostPath = allowedHostPath.PathPrefix
						}
					}
				}
				if !match {
					// path didn't match against any PathPrefix in settings
					err = fmt.Errorf("hostPath '%s' is not in the AllowedHostPaths list",
						path)
				}
				if err != nil {
					break // stop first for, a path was not allowed against all settings, reject
				}
			}
		}
	}

	if err != nil {
		logger.DebugWithFields("rejecting pod object", func(e onelog.Entry) {
			name := gjson.GetBytes(payload, "request.object.metadata.name").String()
			namespace := gjson.
				GetBytes(payload, "request.object.metadata.namespace").String()
			e.String("name", name)
			e.String("namespace", namespace)
		})
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}

// validatePath validates the path prefix and its readOnly state against the
// passed hostPath, and returns a matching error if failed.
func validatePath(path string, readOnly bool, hostPath HostPath) (err error) {
	if hasPathPrefix(path, hostPath.PathPrefix) {
		if readOnly != hostPath.ReadOnly {
			return fmt.Errorf("hostPath '%s' should be readOnly '%t'",
				path, hostPath.ReadOnly)
		}
	}
	return nil
}

func hasPathPrefix(path string, prefix string) bool {
	// allow "/foo", "/foo/", "/foo/bar", etc
	// disallow "/fool", "/etc/foo", etc
	// "/foo/../" is never valid.
	// Hence, ensure paths terminate in `/`:
	pathTerminated := path
	if !strings.HasSuffix(pathTerminated, "/") {
		pathTerminated = pathTerminated + "/"
	}
	prefixTerminated := prefix
	if !strings.HasSuffix(prefixTerminated, "/") {
		prefixTerminated = prefixTerminated + "/"
	}
	return strings.HasPrefix(pathTerminated, prefixTerminated)
}
