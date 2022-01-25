package util

import (
	"os"
	"strings"

	"github.com/rancher/machine/libmachine/log"
)

func FindEnvAny(names ...string) string {
	for _, n := range names {
		if val := os.Getenv(n); val != "" {
			return val
		}
	}
	return ""
}

func GetProxyURL() string {
	urlRaw := FindEnvAny("HTTP_PROXY", "HTTPS_PROXY")
	if urlRaw == "" {
		log.Debug("env var HTTP_PROXY or HTTPS_PROXY is not found")
		return ""
	}
	urlRaw = strings.ToLower(urlRaw)
	urlRaw = strings.TrimPrefix(urlRaw, "http://")
	urlRaw = strings.TrimPrefix(urlRaw, "https://")
	return urlRaw
}
