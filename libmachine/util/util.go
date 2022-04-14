package util

import (
	"fmt"
	"net/http"
	"os"
)

func FindEnvAny(names ...string) string {
	for _, n := range names {
		if val := os.Getenv(n); val != "" {
			return val
		}
	}
	return ""
}

func GetProxyHostnamePortForHost(hostname string) (string, error) {
	req, err := http.NewRequest("GET", "http://"+hostname, nil)
	if err != nil {
		return "", err
	}
	proxy, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return "", err
	}
	if proxy != nil {
		return fmt.Sprintf("%s:%s", proxy.Hostname(), proxy.Port()), nil
	}
	return "", nil
}
