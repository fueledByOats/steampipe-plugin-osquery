package osquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc"
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

	primaryKeyColumn := ""

	// Dynamically generate columns based on the table schema
	cols := []*plugin.Column{}
	for i, column := range tableSchema {
		columnName, ok := column["name"].(string)
		if !ok {
			plugin.Logger(ctx).Error("Failed to assert column name as string", "column", column)
			continue
		}

		if i == 0 {
			primaryKeyColumn = columnName
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

		pkVal, ok := column["pk"].(string)
		if ok {
			if pkVal == "1" {
				primaryKeyColumn = columnName
			}
		}
	}

	plugin.Logger(ctx).Info("PK Col set:", primaryKeyColumn)

	return &plugin.Table{
		Name:        tablename,
		Description: fmt.Sprintf("osquery table: %s", tablename),
		/*List: &plugin.ListConfig{
			Hydrate: listOsqueryTable(tablename),
		},*/
		Get: &plugin.GetConfig{
			KeyColumns: plugin.SingleColumn(primaryKeyColumn),
			Hydrate:    getOsqueryTable(tablename, primaryKeyColumn),
		},
		Columns: cols,
	}
}

func listOsqueryTable(tablename string) func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	return func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

		var jsonData string
		if len(d.QueryContext.UnsafeQuals) > 0 {
			qualString := qualMapToString(d.QueryContext.UnsafeQuals)
			jsonData = retrieveJSONDataForTable(ctx, tablename, qualString)
		} else {
			jsonData = retrieveJSONDataForTable(ctx, tablename, "")
		}

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

func getOsqueryTable(tablename string, pkCol string) func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	return func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

		var jsonData string
		if len(d.Quals) > 0 {
			qualString, err := equalQualsTransform(d.EqualsQuals.String())
			if err == nil {
				jsonData = retrieveJSONDataForTable(ctx, tablename, qualString)
			}
		} else {
			jsonData = retrieveJSONDataForTable(ctx, tablename, "")
		}

		var rows []map[string]interface{}
		err := json.Unmarshal([]byte(jsonData), &rows)
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
}

func qualMapToString(qualMap map[string]*proto.Quals) string {
	if len(qualMap) == 0 {
		return ""
	}

	var sb strings.Builder

	firstKey := true
	for _, quals := range qualMap {
		if !firstKey {
			sb.WriteString(" and ")
		} else {
			firstKey = false
		}

		var qb strings.Builder
		for i, q := range quals.GetQuals() {
			str := qualToString(q)
			qb.WriteString(str)
			// if it's not the last qual, append "and"
			if i < len(quals.GetQuals())-1 {
				qb.WriteString(" and ")
			}
		}
		sb.WriteString(qb.String())
	}

	return sb.String()
}

func qualToString(q *proto.Qual) string {
	fieldName := q.FieldName
	operator := q.GetStringValue()
	value := grpc.GetQualValue(q.Value)

	return "\"" + fieldName + "\" " + operator + " \"" + fmt.Sprintf("%v", value) + "\""
}

func equalQualsTransform(input string) (string, error) {
	parts := strings.Split(input, "=")
	if len(parts) != 2 {
		return input, errors.New("Invalid String") // return the original string if it doesn't match the expected format
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	return fmt.Sprintf(`"%s" = "%s"`, key, value), nil
}
