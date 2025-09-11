package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	onelog "github.com/francoispqt/onelog"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func validate(payload []byte) ([]byte, error) {
	// Create a ValidationRequest instance from the incoming payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	settings := Settings{}
	if err = json.Unmarshal(validationRequest.Settings, &settings); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	if len(settings.AllowedHostPaths) == 0 {
		// empty settings, accepting
		return kubewarden.AcceptRequest()
	}

	podSpec, err := kubewarden.ExtractPodSpecFromObject(validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	logger.DebugWithFields("validating pod object", func(e onelog.Entry) {
		e.String("name", validationRequest.Request.Name)
		e.String("namespace", validationRequest.Request.Namespace)
	})

	volumes := make([]*corev1.Volume, 0)
	for _, volume := range podSpec.Volumes {
		if volume.HostPath != nil {
			volumes = append(volumes, volume)
		}
	}

	volumeMounts := make([]*corev1.VolumeMount, 0)
	volumeMounts = append(volumeMounts, getVolumeMounts(podSpec.InitContainers)...)
	volumeMounts = append(volumeMounts, getVolumeMounts(podSpec.Containers)...)

	for _, volume := range volumes {
		for _, mount := range volumeMounts {
			if *volume.Name != *mount.Name {
				// volume and mount don't match, skip
				continue
			}
			match := false
			var errsMount error // all errors of current mount
			// readOnly attribute of most specific AllowedHostPath takes precendence:
			previousAllowedHostPath := ""
			for _, allowedHostPath := range settings.AllowedHostPaths {
				if hasPathPrefix(*volume.HostPath.Path, allowedHostPath.PathPrefix) {
					// current setting allowedHostPath matches path of volumeMount
					if hasPathPrefix(allowedHostPath.PathPrefix, previousAllowedHostPath) {
						// allowedHostPath is more specific (and has precendence over
						//	past allowedHostPath), or the same path
						match = true
						errMount := validatePath(*volume.HostPath.Path, *mount.Name, mount.ReadOnly, allowedHostPath)
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
					*volume.HostPath.Path, *mount.Name)
				if err == nil {
					err = errors.New(errMsg)
				} else {
					err = fmt.Errorf("%w; %s", err, errMsg)
				}
			}
		}
	}
	if err != nil {
		logger.DebugWithFields("rejecting pod object", func(e onelog.Entry) {
			e.String("name", validationRequest.Request.Name)
			e.String("namespace", validationRequest.Request.Namespace)
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

func getVolumeMounts(containers []*corev1.Container) []*corev1.VolumeMount {
	volumeMounts := make([]*corev1.VolumeMount, 0)
	for _, container := range containers {
		volumeMounts = append(volumeMounts, container.VolumeMounts...)
	}
	return volumeMounts
}
