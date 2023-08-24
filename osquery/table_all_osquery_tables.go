package osquery

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableOsquery(ctx context.Context, tablename string) *plugin.Table {

	// Retrieve table schema
	tableSchema, err := retrieveTableDefinition(ctx, tablename)
	if err != nil {
		plugin.Logger(ctx).Error("Error retrieving table definition:", "err", err)
		panic(err)
	}

	// Dynamically generate columns based on the table schema
	cols := []*plugin.Column{}
	for _, column := range tableSchema {
		columnName, ok := column["name"].(string)
		if !ok {
			plugin.Logger(ctx).Error("Failed to assert column name as string", "column", column)
			continue
		}

		columnTypeStr, ok := column["type"].(string)
		if !ok {
			plugin.Logger(ctx).Error("Failed to assert column type as string", "column", column)
			continue
		}

		columnType, exists := typeMapping[columnTypeStr]
		if !exists {
			plugin.Logger(ctx).Error("Column type not found in mapping. Defaulting to UNKNOWN", "column", column)
			columnType = proto.ColumnType_UNKNOWN // Default to UNKNOWN if type is not in the mapping
		}

		cols = append(cols, &plugin.Column{Name: columnName, Type: columnType, Transform: transform.FromField(columnName)})
	}

	return &plugin.Table{
		Name:        tablename,
		Description: fmt.Sprintf("osquery table: %s", tablename),
		List: &plugin.ListConfig{
			Hydrate: listOsqueryTable(tablename),
		},
		Columns: cols,
	}
}

func listOsqueryTable(tablename string) func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	return func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

		plugin.Logger(ctx).Error("keycolquals:", d.QueryContext.UnsafeQuals)

		jsonData := retrieveJSONDataForTable(ctx, tablename)

		var rows []map[string]interface{}
		err := json.Unmarshal([]byte(jsonData), &rows)
		if err != nil {
			plugin.Logger(ctx).Error("Error parsing JSON data:", "err", err)
			panic(err)
		}

		for _, row := range rows {
			d.StreamListItem(ctx, row)
		}

		return nil, nil
	}
}
