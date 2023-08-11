package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

func tableOsqueryTest(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "helloworld_test",
		Description: "Test table for osquery.",
		List: &plugin.ListConfig{
			Hydrate: listTest,
		},
		Columns: []*plugin.Column{
			{Name: "some_col", Type: proto.ColumnType_STRING, Description: "Test column.", Hydrate: listTest},
		},
	}
}

type TestStruct struct {
	SomeCol string
}

func listTest(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	testInstance := TestStruct{SomeCol: "Another value"}

	// Create a map to hold the column name and value
	item := testInstance

	plugin.Logger(ctx).Info("listTest: Streaming item", item)

	// Stream the item to the table
	d.StreamListItem(ctx, &item)

	return nil, nil
}
