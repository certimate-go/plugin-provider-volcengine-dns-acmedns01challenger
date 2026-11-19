package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/certimate-go/certimate/pkg/plugin"
)

func TestDNSChallengeSubprocess(t *testing.T) {
	const (
		domain     = "origin.example.test"
		zone       = "delegate.example.test"
		recordName = "_acme-challenge." + zone + "."
		accessJSON = `{"accessKeyId":"workflow-key","secretAccessKey":"workflow-secret"}`
	)
	type record struct {
		Host  string
		Type  string
		Value string
		TTL   int
		ZID   int
	}
	var mu sync.Mutex
	records := map[string]record{"existing-id": {Host: "_acme-challenge", Type: "TXT", Value: "existing-value"}}
	var createAttempts, deleteAttempts int
	lookup := func() map[string]record {
		mu.Lock()
		defer mu.Unlock()
		return maps.Clone(records)
	}
	failureHash := sha256.Sum256([]byte("key-auth-failure"))
	failureValue := base64.RawURLEncoding.EncodeToString(failureHash[:])
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		if !strings.Contains(request.Header.Get("Authorization"), "Credential=workflow-key/") {
			t.Error("request did not use the workflow's configured access key")
		}
		switch request.URL.Query().Get("Action") {
		case "ListZones":
			if request.URL.Query().Get("SearchMode") != "exact" {
				t.Error("zone search is not exact")
			}
			switch request.URL.Query().Get("Key") {
			case strings.TrimSuffix(recordName, "."):
				fmt.Fprint(writer, `{"Result":{"Total":0,"Zones":[]}}`)
			case zone:
				fmt.Fprintf(writer, `{"Result":{"Total":1,"Zones":[{"ZID":17,"ZoneName":%q}]}}`, zone)
			default:
				t.Errorf("unexpected zone lookup: %s", request.URL.Query().Get("Key"))
				fmt.Fprint(writer, `{"Result":{"Total":0,"Zones":[]}}`)
			}
		case "CreateRecord":
			var entry record
			if err := json.NewDecoder(request.Body).Decode(&entry); err != nil {
				t.Error(err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			createAttempts++
			if entry.Value == failureValue {
				fmt.Fprint(writer, `{"ResponseMetadata":{"Error":{"Code":"Forbidden","Message":"denied"}}}`)
				return
			}
			id := fmt.Sprintf("challenge-id-%d", createAttempts)
			records[id] = entry
			fmt.Fprintf(writer, `{"Result":{"RecordID":%q}}`, id)
		case "DeleteRecord":
			var payload struct{ RecordID string }
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Error(err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			deleteAttempts++
			if _, exists := records[payload.RecordID]; !exists || payload.RecordID == "existing-id" {
				t.Errorf("delete targeted an unknown or pre-existing ID: %q", payload.RecordID)
			}
			delete(records, payload.RecordID)
			fmt.Fprint(writer, `{"Result":{}}`)
		default:
			t.Errorf("unexpected DNS request: %s", request.URL.Path)
			writer.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer api.Close()
	t.Setenv("VOLC_HOST", strings.TrimPrefix(api.URL, "http://"))
	t.Setenv("VOLC_SCHEME", "http")
	t.Setenv("VOLC_TTL", "600")
	t.Setenv("VOLC_PROPAGATION_TIMEOUT", "310")
	t.Setenv("VOLC_POLLING_INTERVAL", "6")
	t.Setenv("VOLC_ACCESSKEY", "ambient-key")
	t.Setenv("VOLC_SECRETKEY", "ambient-secret")

	pluginDir := t.TempDir()
	installDir := filepath.Join(pluginDir, providerType)
	if err := os.Mkdir(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-mod=readonly", "-o", filepath.Join(installDir, providerType+".exe"), ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, output)
	}
	config := plugin.PluginConfig{PluginDir: pluginDir}
	manager := plugin.NewManager(config, nil)
	installed, failures := plugin.Discover(t.Context(), config)
	if len(installed) != 1 || len(failures) != 0 {
		t.Fatalf("discover plugin: got %d plugins, failures %v", len(installed), failures)
	}
	session, err := manager.StartSession(t.Context(), installed[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	meta, err := session.GetMetadata(t.Context())
	if err != nil || meta.ProviderType != providerType || meta.AccessProviderType != "volcengine" || meta.Capability != plugin.CapabilityDns {
		t.Fatalf("plugin metadata: %+v, %v", meta, err)
	}
	var timing struct {
		TimeoutSeconds  int `json:"propagation_timeout_seconds"`
		IntervalSeconds int `json:"propagation_polling_interval_seconds"`
	}
	if err := json.Unmarshal(meta.RuntimeConfigJSON, &timing); err != nil || timing.TimeoutSeconds != 310 || timing.IntervalSeconds != 6 {
		t.Fatalf("unexpected propagation timing: %+v, %v", timing, err)
	}
	schema, err := session.GetConfigSchema(t.Context())
	if err != nil || len(schema.AccessSchemaJSON) != 0 || len(schema.ProviderSchemaJSON) == 0 {
		t.Fatalf("plugin schema: %+v, %v", schema, err)
	}

	present := func(token string, ttl int) (*plugin.Request, string, error) {
		keyAuth := "key-auth-" + token
		hash := sha256.Sum256([]byte(keyAuth))
		value := base64.RawURLEncoding.EncodeToString(hash[:])
		req := &plugin.Request{
			Capability:         plugin.CapabilityDns,
			AccessConfigJSON:   accessJSON,
			ExtendedConfigJSON: fmt.Sprintf(`{"recordName":%q,"recordValue":%q,"ttl":%d}`, recordName, value, ttl),
			Dns:                &plugin.DnsPayload{Domain: domain, Token: token, KeyAuth: keyAuth},
		}
		_, err := session.Process(t.Context(), req, nil)
		return req, value, err
	}
	cleanup := func(req *plugin.Request) {
		t.Helper()
		key := plugin.DnsKey{Domain: req.Dns.Domain, Token: req.Dns.Token, KeyAuth: req.Dns.KeyAuth}
		if err := session.PostProcessDnsKey(t.Context(), key, nil); err != nil {
			t.Fatal(err)
		}
	}
	first, firstValue, err := present("first", 900)
	if err != nil {
		t.Fatal(err)
	}
	second, secondValue, err := present("second", 0)
	if err != nil {
		t.Fatal(err)
	}
	failed, _, err := present("failure", 900)
	if err == nil || !strings.Contains(err.Error(), "create DNS challenge record") {
		t.Fatalf("expected create failure, got %v", err)
	}
	cleanup(failed)
	created := lookup()
	if len(created) != 3 || created["challenge-id-1"] != (record{Host: "_acme-challenge", Type: "TXT", Value: firstValue, TTL: 900, ZID: 17}) ||
		created["challenge-id-2"] != (record{Host: "_acme-challenge", Type: "TXT", Value: secondValue, TTL: 600, ZID: 17}) {
		t.Fatalf("unexpected records after present: %+v", created)
	}
	cleanup(first)
	cleanup(first)
	remaining := lookup()
	if len(remaining) != 2 || remaining["challenge-id-2"].Value != secondValue || remaining["existing-id"].Value != "existing-value" {
		t.Fatalf("first cleanup changed unrelated records: %+v", remaining)
	}
	cleanup(second)
	remaining = lookup()
	mu.Lock()
	defer mu.Unlock()
	if len(remaining) != 1 || remaining["existing-id"].Value != "existing-value" || deleteAttempts != 2 {
		t.Fatalf("expected only the pre-existing record after two deletions: %+v (deletions: %d)", remaining, deleteAttempts)
	}
}
