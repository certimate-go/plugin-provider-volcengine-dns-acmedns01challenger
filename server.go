package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/certimate-go/certimate/pkg/plugin"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/providers/dns/volcengine"
	"github.com/miekg/dns"
	"github.com/volcengine/volc-sdk-golang/base"
	volcdns "github.com/volcengine/volc-sdk-golang/service/dns"
)

type server struct {
	mu      sync.Mutex
	records map[string]*challengeRecord
}

type challengeRecord struct {
	mu     sync.Mutex
	client *volcdns.Client
	id     string
}

type accessConfig struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
}

type challengeConfig struct {
	RecordName  string `json:"recordName"`
	RecordValue string `json:"recordValue"`
	TTL         int    `json:"ttl"`
}

func (s *server) Process(ctx context.Context, req *plugin.Request, _ *slog.Logger) (*plugin.Result, error) {
	if req.ExecutionID == "" {
		return nil, fmt.Errorf("missing DNS challenge execution ID")
	}
	var access accessConfig
	if err := json.Unmarshal([]byte(req.AccessConfigJSON), &access); err != nil {
		return nil, fmt.Errorf("invalid Volcano Engine access configuration: %w", err)
	}
	if strings.TrimSpace(access.AccessKeyID) == "" || strings.TrimSpace(access.SecretAccessKey) == "" {
		return nil, fmt.Errorf("missing Volcano Engine access credentials")
	}
	var challenge challengeConfig
	if err := json.Unmarshal([]byte(req.ExtendedConfigJSON), &challenge); err != nil {
		return nil, fmt.Errorf("invalid Volcano Engine DNS challenge configuration: %w", err)
	}
	if labels, valid := dns.IsDomainName(challenge.RecordName); !valid || labels < 2 || !dns.IsFqdn(challenge.RecordName) {
		return nil, fmt.Errorf("missing or invalid prepared DNS challenge name")
	}
	keyAuthHash := sha256.Sum256([]byte(req.Dns.KeyAuth))
	if challenge.RecordValue != base64.RawURLEncoding.EncodeToString(keyAuthHash[:]) {
		return nil, fmt.Errorf("invalid prepared DNS challenge value")
	}
	if challenge.TTL < 0 {
		return nil, fmt.Errorf("invalid negative DNS record TTL")
	}
	config := volcengine.NewDefaultConfig()
	if challenge.TTL == 0 {
		challenge.TTL = config.TTL
	}
	entry := &challengeRecord{client: newDNSClient(config, access)}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	s.mu.Lock()
	if _, exists := s.records[req.ExecutionID]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("DNS challenge execution already exists")
	}
	if s.records == nil {
		s.records = make(map[string]*challengeRecord)
	}
	s.records[req.ExecutionID] = entry
	s.mu.Unlock()

	recordID, err := createChallengeRecord(ctx, entry.client, challenge)
	if err != nil {
		s.forgetRecord(req.ExecutionID)
		return nil, err
	}
	entry.id = recordID
	return &plugin.Result{Dns: &plugin.DnsResult{}}, nil
}

func (s *server) PostProcess(ctx context.Context, req *plugin.Request, _ *slog.Logger) error {
	s.mu.Lock()
	entry := s.records[req.ExecutionID]
	s.mu.Unlock()
	if entry == nil {
		return nil
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.id == "" {
		return nil
	}
	if err := entry.client.DeleteRecord(ctx, &volcdns.DeleteRecordRequest{RecordID: new(entry.id)}); err != nil {
		return fmt.Errorf("volcengine: delete DNS challenge record: %w", err)
	}
	entry.id = ""
	s.forgetRecord(req.ExecutionID)
	return nil
}

func (s *server) forgetRecord(executionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, executionID)
}

func newDNSClient(config *volcengine.Config, access accessConfig) *volcdns.Client {
	serviceInfo := &base.ServiceInfo{
		Timeout: config.HTTPTimeout,
		Host:    config.Host,
		Header:  http.Header{"Accept": []string{"application/json"}},
		Scheme:  config.Scheme,
		Credentials: base.Credentials{
			Service:         volcdns.ServiceName,
			Region:          config.Region,
			AccessKeyID:     access.AccessKeyID,
			SecretAccessKey: access.SecretAccessKey,
		},
	}
	client := base.NewClient(serviceInfo, nil)
	client.SetAccessKey(access.AccessKeyID)
	client.SetSecretKey(access.SecretAccessKey)
	return volcdns.NewClient(&volcdns.VolcCaller{Volc: client})
}

func createChallengeRecord(ctx context.Context, client *volcdns.Client, challenge challengeConfig) (string, error) {
	name := strings.ToLower(challenge.RecordName)
	for suffix := range dns01.UnFqdnDomainsSeq(name) {
		zones, err := client.ListZones(ctx, &volcdns.ListZonesRequest{Key: new(suffix), SearchMode: new("exact")})
		if err != nil {
			return "", fmt.Errorf("volcengine: list DNS zones: %w", err)
		}
		if zones == nil || len(zones.Zones) > 1 || (zones.Total != nil && *zones.Total != int64(len(zones.Zones))) {
			return "", fmt.Errorf("volcengine: invalid or ambiguous DNS zone response for %q", suffix)
		}
		if len(zones.Zones) == 0 {
			continue
		}
		zone := zones.Zones[0]
		if zone.ZID == nil || *zone.ZID <= 0 || zone.ZoneName == nil || !strings.EqualFold(dns.Fqdn(*zone.ZoneName), dns.Fqdn(suffix)) {
			return "", fmt.Errorf("volcengine: invalid DNS zone for %q", suffix)
		}
		host := "@"
		if name != dns.Fqdn(suffix) {
			host, err = dns01.ExtractSubDomain(name, suffix)
			if err != nil {
				return "", fmt.Errorf("volcengine: determine DNS challenge host: %w", err)
			}
		}
		record, err := client.CreateRecord(ctx, &volcdns.CreateRecordRequest{
			Host: new(host), Type: new("TXT"), Value: new(challenge.RecordValue), TTL: new(int64(challenge.TTL)), ZID: zone.ZID,
		})
		if err != nil {
			return "", fmt.Errorf("volcengine: create DNS challenge record: %w", err)
		}
		if record == nil || record.RecordID == nil || *record.RecordID == "" {
			return "", fmt.Errorf("volcengine: create DNS challenge record returned no record ID; check the DNS zone for an orphaned record")
		}
		return *record.RecordID, nil
	}
	return "", fmt.Errorf("volcengine: no DNS zone found for %q", name)
}
