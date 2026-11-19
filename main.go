package main

import (
	"context"
	"embed"

	"github.com/certimate-go/certimate/pkg/plugin"
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
