package osquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/turbot/steampipe-plugin-sdk/v5/connection"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableOsquery(ctx context.Context, c *plugin.Connection, cc *connection.ConnectionCache, tablename string) (*plugin.Table, error) {

	conn, err := connect(ctx, c, cc)
	if err != nil {
		return nil, err
	}

	// retrieve table schema
	tableSchema, err := conn.RetrieveTableDefinition(ctx, tablename)
	if err != nil {
		plugin.Logger(ctx).Error("Error retrieving table definition:", "err", err)
		return nil, err
	}

	primaryKeyColumn := ""

	// dynamically generate columns based on the table schema
	cols := []*plugin.Column{}
	for i, column := range tableSchema {
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
		// default to UNKNOWN if type is not in the mapping
		if !exists {
			plugin.Logger(ctx).Error("Column type not found in mapping. Defaulting to UNKNOWN", "column", column)
			columnType = proto.ColumnType_UNKNOWN
		}

		// get column description
		columnDescription, exists := getTableOrColumnDescription(ctx, cc, tablename, columnName)
		if !exists || columnDescription == "" {
			columnDescription = fmt.Sprintf("No description available.")
		}

		cols = append(cols, &plugin.Column{Name: columnName, Type: columnType, Description: columnDescription, Transform: transform.FromField(columnName)})

		// use the first col in case no primary key is set
		if i == 0 {
			primaryKeyColumn = columnName
		}

		pkVal, ok := column["pk"].(string)
		if ok {
			if pkVal == "1" {
				primaryKeyColumn = columnName
			}
		}
	}

	// get table description
	tableDescription, exists := getTableOrColumnDescription(ctx, cc, tablename, "")
	if !exists || tableDescription == "" {
		tableDescription = fmt.Sprintf("osquery table: %s", tablename)
	}

	return &plugin.Table{
		Name:        tablename,
		Description: tableDescription,
		List: &plugin.ListConfig{
			Hydrate: listOsqueryTable,
		},
		Get: &plugin.GetConfig{
			KeyColumns: plugin.SingleColumn(primaryKeyColumn),
			Hydrate:    getOsqueryTable,
		},
		Columns: cols,
	}, nil
}

func listOsqueryTable(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {

	conn, err := connect(ctx, d.Connection, d.ConnectionCache)
	if err != nil {
		return nil, err
	}

	jsonData := conn.RetrieveJSONDataForTable(ctx, d)

	var rows []map[string]interface{}
	err = json.Unmarshal([]byte(jsonData), &rows)
	if err != nil {
		plugin.Logger(ctx).Error("Error parsing JSON data:", "err", err)
		return nil, err
	}

	for _, row := range rows {
		d.StreamListItem(ctx, row)
	}

	return nil, nil
}

func getOsqueryTable(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {

	conn, err := connect(ctx, d.Connection, d.ConnectionCache)
	if err != nil {
		return nil, err
	}

	jsonData := conn.RetrieveJSONDataForTable(ctx, d)

	var rows []map[string]interface{}
	err = json.Unmarshal([]byte(jsonData), &rows)
	if err != nil {
		plugin.Logger(ctx).Error("Error parsing JSON data:", "err", err)
		return nil, err
	}
	if len(rows) == 0 {
		plugin.Logger(ctx).Error("row is nil")
		return nil, errors.New("Row data is nil")
	}

	row := rows[0]

	return row, nil
}
