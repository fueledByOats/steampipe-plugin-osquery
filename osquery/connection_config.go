package osquery

import (
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/schema"
)

type osqueryConfig struct {
	Token        *string `cty:"test"`
}

var ConfigSchema = map[string]*schema.Attribute{
	"test": {
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
