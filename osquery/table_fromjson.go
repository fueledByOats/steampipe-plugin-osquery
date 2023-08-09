package osquery

import (
	"context"
	"encoding/json"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableJSON(ctx context.Context, jsonData string) *plugin.Table {
	var users []map[string]interface{}
	err := json.Unmarshal([]byte(jsonData), &users)
	if err != nil {
		plugin.Logger(ctx).Error("Error parsing JSON data:", "err", err)
		panic(err)
	}

	// Dynamically generate columns based on the first user's keys
	cols := []*plugin.Column{}
	for key := range users[0] {
		cols = append(cols, &plugin.Column{Name: key, Type: proto.ColumnType_STRING, Transform: transform.FromField(key)})
	}

	return &plugin.Table{
		Name:        "users",
		Description: "Dynamic table for JSON users data.",
		List: &plugin.ListConfig{
			Hydrate: func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
				for _, user := range users {
					d.StreamListItem(ctx, user)
				}
				return nil, nil
			},
		},
		Columns: cols,
	}
}
