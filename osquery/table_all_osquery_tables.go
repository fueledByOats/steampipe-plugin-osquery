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
	// retrieve the JSON data for the given tablename
	//jsonData := retrieveJSONDataForTable(ctx, tablename)
	jsonData := retrieveJSONDataForTable(ctx, tablename)

	return tableJSON(ctx, tablename, jsonData)
}

func tableJSON(ctx context.Context, tablename string, jsonData string) *plugin.Table {
	var rows []map[string]interface{}
	err := json.Unmarshal([]byte(jsonData), &rows)
	if err != nil {
		plugin.Logger(ctx).Error("Error parsing JSON data:", "err", err)
		panic(err)
	}

	// Dynamically generate columns based on the first entry's keys
	cols := []*plugin.Column{}
	for key := range rows[0] {
		cols = append(cols, &plugin.Column{Name: key, Type: proto.ColumnType_STRING, Transform: transform.FromField(key)})
	}

	return &plugin.Table{
		Name:        tablename,
		Description: fmt.Sprintf("osquery table: %s", tablename),
		List: &plugin.ListConfig{
			Hydrate: func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
				for _, row := range rows {
					d.StreamListItem(ctx, row)
				}
				return nil, nil
			},
		},
		Columns: cols,
	}
}

// For debugging purposes
