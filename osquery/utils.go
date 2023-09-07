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

// Table represents the structure of the table in the JSON file
type Table struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Examples    []string `json:"examples"`
}

func connect(ctx context.Context, c *plugin.Connection, cc *connection.ConnectionCache) (*osquery.Client, error) {
	// Load connection from cache if a client was already initialized
	cacheKey := c.Name
	if cachedData, ok := cc.Get(ctx, cacheKey); ok {
		return cachedData.(*osquery.Client), nil
	}

	// Prefer config settings
	osqueryConfig := GetConfig(c)

	// Error if the minimum config is not set
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

	// Save to cache
	cc.Set(ctx, cacheKey, conn)
	return conn, nil
}

// retrieves the description for a given table name
func getTableDescription(ctx context.Context, cc *connection.ConnectionCache, name string) (string, bool) {
	tablesMap, err := getTablesMap(ctx, cc)
	if err != nil {
		plugin.Logger(ctx).Error("Error retrieving tables map:", "err", err)
		return "", false
	}

	description, exists := tablesMap[name]
	return description, exists
}

// getTablesMap retrieves the tablesMap from the cache or loads it if not present
func getTablesMap(ctx context.Context, cc *connection.ConnectionCache) (map[string]string, error) {
	cacheKey := "tablesMap"
	if cachedData, ok := cc.Get(ctx, cacheKey); ok {
		return cachedData.(map[string]string), nil
	}

	// Load the JSON data
	tablesMap, err := LoadJSON()
	if err != nil {
		return nil, err
	}

	// Save to cache
	cc.Set(ctx, cacheKey, tablesMap)
	return tablesMap, nil
}

// LoadJSON loads and parses the JSON file into tablesMap
func LoadJSON() (map[string]string, error) {
	if jsonData == nil {
		return nil, errors.New("embedded JSON data is nil")
	}

	// Parse the embedded JSON data
	var tables []Table
	if err := json.Unmarshal(jsonData, &tables); err != nil {
		return nil, err
	}

	// Store the parsed data in tablesMap
	tablesMap := make(map[string]string)
	for _, table := range tables {
		tablesMap[table.Name] = table.Description
	}

	return tablesMap, nil
}
