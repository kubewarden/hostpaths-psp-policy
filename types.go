package main

type HostPath struct {
	PathPrefix string `json:"pathPrefix"`
	ReadOnly   bool   `json:"readOnly"`
}

type Settings struct {
	AllowedHostPaths []HostPath `json:"allowedHostPaths"`
}
