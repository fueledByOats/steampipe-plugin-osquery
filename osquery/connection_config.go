package osquery

import (
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/schema"
)

type osqueryConfig struct {
	OsqueryCommand          *string `cty:"osquery_command"`
	OsqueryExtensionCommand *string `cty:"osquery_extension_command"`
}

var ConfigSchema = map[string]*schema.Attribute{
	"osquery_command": {
		Type: schema.TypeString,
	},
	"osquery_extension_command": {
		Type: schema.TypeString,
	},
}

func ConfigInstance() interface{} {
	return &osqueryConfig{}
}

// GetConfig :: retrieve and cast connection config from query data
func GetConfig(connection *plugin.Connection) osqueryConfig {
	if connection == nil || connection.Config == nil {
		return osqueryConfig{}
	}
	config, _ := connection.Config.(osqueryConfig)
	return config
}
