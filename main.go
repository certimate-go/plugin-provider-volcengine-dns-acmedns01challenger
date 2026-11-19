package main

import (
	"context"
	"embed"
	"encoding/json"
	"time"

	"github.com/certimate-go/certimate/pkg/plugin"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/providers/dns/volcengine"
	githubplugin "github.com/hashicorp/go-plugin"
)

//go:embed schema
var schemaFS embed.FS

const providerType = "volcengine-dns"

func main() {
	githubplugin.Serve(&githubplugin.ServeConfig{
		HandshakeConfig: plugin.HandshakeConfig,
		Plugins: plugin.PluginSet{
			plugin.PluginName: &plugin.GRPCPlugin{Impl: &server{}},
		},
		GRPCServer: githubplugin.DefaultGRPCServer,
	})
}

func (*server) GetMetadata(context.Context) (*plugin.Metadata, error) {
	return &plugin.Metadata{
		ProviderType:       providerType,
		AccessProviderType: "volcengine",
		ProtocolVersion:    plugin.ProtocolVersion,
		Capability:         plugin.CapabilityDns,
		DisplayNameKey:     "plugin." + providerType + ".name",
	}, nil
}

func (*server) RuntimeConfig(context.Context) (json.RawMessage, error) {
	config := volcengine.NewDefaultConfig()
	timeout, interval := config.PropagationTimeout, config.PollingInterval
	if timeout <= 0 {
		timeout = dns01.DefaultPropagationTimeout
	}
	if interval <= 0 {
		interval = dns01.DefaultPollingInterval
	}
	return json.Marshal(map[string]int64{
		"propagation_timeout_seconds":          int64(timeout / time.Second),
		"propagation_polling_interval_seconds": int64(interval / time.Second),
	})
}

func (*server) GetConfigSchema(context.Context) (*plugin.ConfigSchema, error) {
	config, err := plugin.LoadProviderSchema(schemaFS)
	if err != nil {
		return nil, err
	}
	i18n, err := plugin.LoadI18n(schemaFS)
	if err != nil {
		return nil, err
	}
	return &plugin.ConfigSchema{ProviderSchemaJSON: config, I18n: i18n}, nil
}
