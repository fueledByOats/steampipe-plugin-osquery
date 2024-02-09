package osquery

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	osquery "steampipe-plugin-osquery/internal"

	"github.com/turbot/steampipe-plugin-sdk/v5/connection"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

// maps the osquery column type to the steampipe columntype
var typeMapping = map[string]proto.ColumnType{
	"TEXT":            proto.ColumnType_STRING,
	"INTEGER":         proto.ColumnType_INT,
	"BIGINT":          proto.ColumnType_INT,
	"UNSIGNED BIGINT": proto.ColumnType_INT,
	"DOUBLE":          proto.ColumnType_DOUBLE,
}

//go:embed osquery_schemas.json
var jsonData []byte

// column represents the structure of the columns in the JSON file
type Column struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// table represents the structure of the tables in the JSON file
type Table struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Examples    []string `json:"examples"`
	Columns     []Column `json:"columns"`
}

func connect(ctx context.Context, c *plugin.Connection, cc *connection.ConnectionCache) (*osquery.Client, error) {
	// load client from cache if a client was already initialized for this connection
	cacheKey := c.Name
	if cachedData, ok := cc.Get(ctx, cacheKey); ok {
		return cachedData.(*osquery.Client), nil
	}

	// prefer config settings
	osqueryConfig := GetConfig(c)

	// error if the minimum config is not set
	if *osqueryConfig.OsqueryCommand == "" {
		return nil, errors.New("osquery_command must be configured")
	}
	if *osqueryConfig.OsqueryExtensionCommand == "" {
		return nil, errors.New("osquery_extension_command must be configured")
	}

	osqueryCommand := *osqueryConfig.OsqueryCommand
	osqueryExtensionCommand := *osqueryConfig.OsqueryExtensionCommand

	cfg := &osquery.ClientConfig{
		OsqueryCommand:   osqueryCommand,
		ExtensionCommand: osqueryExtensionCommand,
	}

	conn, err := osquery.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	// save to cache
	cc.Set(ctx, cacheKey, conn)
	return conn, nil
}

// retrieves the description for a given column in a table or the table itself.
// if the table description is to be returned, set columnName to "table-description"
func getTableOrColumnDescription(ctx context.Context, cc *connection.ConnectionCache, tablename string, columnName string) (string, bool) {
	tablesMap, err := getTablesMap(ctx, cc)
	if err != nil {
		plugin.Logger(ctx).Error("Error retrieving tables map:", "err", err)
		return "", false
	}

	// check if the table exists
	table, tableExists := tablesMap[tablename]
	if !tableExists {
		return "", false
	}

	if columnName == "table-description" {
		return table.Description, true
	}

	// search for the column and its description
	for _, column := range table.Columns {
		if column.Name == columnName {
			return column.Description, true
		}
	}

	return "", false
}

// retrieves the tablesMap from the cache or loads it if not present
func getTablesMap(ctx context.Context, cc *connection.ConnectionCache) (map[string]Table, error) {
	cacheKey := "tablesMap"
	if cachedData, ok := cc.Get(ctx, cacheKey); ok {
		return cachedData.(map[string]Table), nil
	}

	tablesMap, err := LoadJSON()
	if err != nil {
		return nil, err
	}

	cc.Set(ctx, cacheKey, tablesMap)
	return tablesMap, nil
}

// loads and parses the JSON file into tablesMap
func LoadJSON() (map[string]Table, error) {
	if jsonData == nil {
		return nil, errors.New("embedded JSON data is nil")
	}

	var tables []Table
	if err := json.Unmarshal(jsonData, &tables); err != nil {
		return nil, err
	}

	tablesMap := make(map[string]Table)
	for _, table := range tables {
		tablesMap[table.Name] = table
	}

	return tablesMap, nil
}
