package util

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/rancher/wrangler/pkg/slice"
)

func FindEnvAny(names ...string) string {
	for _, n := range names {
		if val := os.Getenv(n); val != "" {
			return val
		}
	}
	return ""
}

// GetProxyURL returns the URL of the proxy to use for this given hostIP and the scheme,
// as indicated by the environment variables HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or the lowercase versions thereof).
// HTTPS_PROXY takes precedence over HTTP_PROXY for https requests.
func GetProxyURL(hostIp, scheme string) (*url.URL, error) {
	validSchema := []string{"http", "https"}
	scheme = strings.ToLower(scheme)
	if !slice.ContainsString(validSchema, scheme) {
		return nil, fmt.Errorf("%s is not supported, supported schemes are http and https", scheme)
	}
	req, err := http.NewRequest(http.MethodGet, scheme+"://"+hostIp, nil)
	if err != nil {
		return nil, err
	}
	proxy, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return nil, err
	}
	return proxy, nil
}
