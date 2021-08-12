package main

import (
	"errors"
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

	logger.DebugWithFields("validating pod object", func(e onelog.Entry) {
		name := gjson.GetBytes(payload, "request.object.metadata.name").String()
		namespace := gjson.GetBytes(payload,
			"request.object.metadata.namespace").String()
		e.String("name", name)
		e.String("namespace", namespace)
	})

	// build list of volumeMounts from all the initContainers and containers:
	volumeMounts := make([]gjson.Result, 0)
	cases := []string{
		"request.object.spec.initContainers",
		"request.object.spec.containers",
	}
	for _, c := range cases {
		containers := gjson.GetBytes(payload, c)
		for _, container := range containers.Array() {
			containerVolumeMounts := gjson.Get(container.String(),
				"volumeMounts")
			volumeMounts = append(volumeMounts, containerVolumeMounts.Array()...)
		}
	}

	for _, volume := range volumes.Array() {
		if gjson.Get(volume.String(), "hostPath").Exists() {
			// volume is of type hostPath
			for _, mount := range volumeMounts {

				// if volumeMount object matches the 'volume.name':
				mountName := gjson.Get(mount.String(), "name").String()
				if mountName == gjson.Get(volume.String(), "name").String() { /* == volume name */
					// volume is a hostpath and it in use, validate against
					// settings

					readOnly := false // volumeMount.readOnly missing means 'false'
					if gjson.Get(mount.String(), "readOnly").Exists() {
						readOnly = gjson.Get(mount.String(), "readOnly").Bool()
					}

					path := gjson.Get(volume.String(), "hostPath.path").String()

					match := false
					var errsMount error // all errors of current mount
					// readOnly attribute of most specific AllowedHostPath takes precendence:
					previousAllowedHostPath := ""
					for _, allowedHostPath := range settings.AllowedHostPaths {
						if hasPathPrefix(path, allowedHostPath.PathPrefix) {
							// current setting allowedHostPath matches path of volumeMount
							if hasPathPrefix(allowedHostPath.PathPrefix, previousAllowedHostPath) {
								// allowedHostPath is more specific (and has precendence over
								//	past allowedHostPath), or the same path
								match = true
								errMount := validatePath(path, mountName, readOnly, allowedHostPath)
								// build all errors for this mount:
								if errMount == nil {
									// drop errors in errsMount, we found a more
									// specific path that validates the current
									// mount
									errsMount = nil
								} else {
									// we found even more errors for this specific mount, append
									if errsMount == nil {
										errsMount = errMount
									} else {
										errsMount = fmt.Errorf("%w; %s", errsMount, errMount)
									}
								}
								previousAllowedHostPath = allowedHostPath.PathPrefix
							}
						}
					}
					// concat to global err:
					if errsMount != nil {
						if err == nil {
							err = errsMount
						} else {
							err = fmt.Errorf("%w; %s", err, errsMount)
						}
					}
					if !match {
						// path didn't match against any PathPrefix in settings
						errMsg := fmt.Sprintf("hostPath '%s' mounted as '%s' is not in the AllowedHostPaths list",
							path, mountName)
						if err == nil {
							err = errors.New(errMsg)
						} else {
							err = fmt.Errorf("%w; %s", err, errMsg)
						}
					}
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
func validatePath(path, mountName string, readOnly bool, hostPath HostPath) (err error) {
	if hasPathPrefix(path, hostPath.PathPrefix) {
		if readOnly != hostPath.ReadOnly {
			return fmt.Errorf("hostPath '%s' mounted as '%s' should be readOnly '%t'",
				path, mountName, hostPath.ReadOnly)
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
