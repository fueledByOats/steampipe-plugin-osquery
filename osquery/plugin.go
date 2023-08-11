package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name:             "steampipe-plugin-osquery",
		DefaultTransform: transform.FromGo().NullIfZero(),
		SchemaMode:       plugin.SchemaModeDynamic,
		TableMapFunc:     PluginTables,
	}
	return p
}

func PluginTables(ctx context.Context, d *plugin.TableMapData) (map[string]*plugin.Table, error) {
	tables := map[string]*plugin.Table{}

	// retrieve all osquery table names
	osqueryTableNames := retrieveOsqueryTableNames(ctx)

	// Create a table for each osquery table
	for _, tablename := range osqueryTableNames {
		tables[tablename] = tableOsquery(ctx, tablename)
	}

	plugin.Logger(ctx).Info("PluginTablesDebug, ctx:", ctx)

	return tables, nil
}
