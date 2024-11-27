package azureutil

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rancher/machine/drivers/azure/logutil"
	"github.com/rancher/machine/libmachine/log"

	"github.com/Azure/go-autorest/autorest/azure"
)

const (
	findTenantIDTimeout = time.Second * 5
)

// loadOrFindTenantID figures out the AAD tenant ID of the subscription by first
// looking at the cache file, if not exists, makes a network call to load it and
// cache it for future use.
func loadOrFindTenantID(ctx context.Context, env azure.Environment, subscriptionID string) (string, error) {
	var tenantID string

	log.Debug("Looking up AAD Tenant ID.", logutil.Fields{
		"subs": subscriptionID})

	// Load from cache
	fp := tenantIDPath(subscriptionID)
	b, err := os.ReadFile(fp)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("Failed to load tenant ID file: %v", err)
		}
		log.Debugf("Tenant ID file not found: %s", fp)
	} else {
		tenantID = strings.TrimSpace(string(b))
		log.Debugf("Tenant ID loaded from file: %s", fp)
	}

	// Handle cache miss
	if tenantID == "" {
		log.Debug("Making API call to find tenant ID")
		t, err := FindTenantID(ctx, env, subscriptionID)
		if err != nil {
			return "", err
		}
		tenantID = t

		// Cache the result
		if err := saveTenantID(fp, tenantID); err != nil {
			return "", fmt.Errorf("Failed to save tenant ID: %v", err)
		}
		log.Debugf("Cached tenant ID to file: %s", fp)
	}
	log.Debug("Found AAD Tenant ID.", logutil.Fields{
		"tenant": tenantID,
		"subs":   subscriptionID})
	return tenantID, nil
}

// FindTenantID figures out the AAD tenant ID of the subscription by making an
// unauthenticated request to the Get Subscription Details endpoint and parses
// the value from WWW-Authenticate header.
func FindTenantID(ctx context.Context, env azure.Environment, subscriptionID string) (string, error) {
	goCtx, cancel := context.WithTimeout(ctx, findTenantIDTimeout)
	defer cancel()
	const hdrKey = "WWW-Authenticate"
	c := subscriptionsClient(env.ResourceManagerEndpoint)

	// we expect this request to fail (err != nil), but we are only interested
	// in headers, so surface the error if the Response is not present (i.e.
	// network error etc)
	subs, err := c.Get(goCtx, subscriptionID)
	if subs.Response.Response == nil {
		return "", fmt.Errorf("Request failed: %v", err)
	}

	// Expecting 401 StatusUnauthorized here, just read the header
	if subs.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("Unexpected response from Get Subscription: %v", err)
	}
	hdr := subs.Header.Get(hdrKey)
	if hdr == "" {
		return "", fmt.Errorf("Header %v not found in Get Subscription response", hdrKey)
	}

	// Example value for hdr:
	//   Bearer authorization_uri="https://login.windows.net/996fe9d1-6171-40aa-945b-4c64b63bf655", error="invalid_token", error_description="The authentication failed because of missing 'Authorization' header."
	r := regexp.MustCompile(`authorization_uri=".*/([0-9a-f\-]+)"`)
	m := r.FindStringSubmatch(hdr)
	if m == nil {
		return "", fmt.Errorf("Could not find the tenant ID in header: %s %q", hdrKey, hdr)
	}
	return m[1], nil
}

// saveTenantID performs an atomic write to the path with given tenantID contents.
func saveTenantID(path string, tenantID string) error {
	var perm os.FileMode = 0600

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("Failed to create directory %s: %v", dir, err)
	}

	f, err := os.CreateTemp(dir, "tenantid")
	if err != nil {
		return fmt.Errorf("Failed to create temp file: %v", err)
	}
	defer f.Close()

	fp := f.Name()
	if _, err := f.Write([]byte(tenantID)); err != nil {
		return fmt.Errorf("Failed to write tenant ID to file: %v", err)
	}
	f.Close()

	// atomic move by rename
	if err := os.Rename(fp, path); err != nil {
		return fmt.Errorf("Failed to rename file. src=%s dst=%s error=%v", fp, path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("Failed to chmod the file %s: %v", path, err)
	}
	return nil
}

// tenantIDPath returns the full path the tenant ID for the given subscription
// should be saved at.f
func tenantIDPath(subscriptionID string) string {
	return filepath.Join(azureCredsPath(), fmt.Sprintf("%s.tenantid", subscriptionID))
}
