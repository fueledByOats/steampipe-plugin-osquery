package osquery

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	osquery "steampipe-plugin-osquery/internal"
	"sync"

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

var (
	once            sync.Once
	singletonClient *osquery.Client
	clientMutex     sync.Mutex
	clientInitErr   error
	// tablesMap is used to store parsed json table schema data
	tablesMap map[string]string
	isLoaded  bool
	loadOnce  sync.Once
	// Embed the data.json file
	//go:embed osquery_schemas.json
	jsonData []byte
)

// Table represents the structure of the table in the JSON file
type Table struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Examples    []string `json:"examples"`
}

func retrieveJSONDataForTable(ctx context.Context, tablename string, quals string) string {
	clientMutex.Lock()

	client := getClient(ctx)

	query := fmt.Sprintf("SELECT * FROM %s", tablename)
	if quals != "" {
		query = fmt.Sprintf("SELECT * FROM %s WHERE %s", tablename, quals)
	}
	result, err := client.SendQuery(query)

	clientMutex.Unlock()

	if err != nil {
		fmt.Println("Error:", err)
		return ""
	} else {
		return string(result.Data)
	}
}

func retrieveOsqueryTableNames(ctx context.Context) []string {
	client := getClient(ctx)

	result, err := client.SendQuery("SELECT name FROM osquery_registry WHERE registry='table'")
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}

	var tables []map[string]string
	err = json.Unmarshal(result.Data, &tables)
	if err != nil {
		fmt.Println("Error unmarshalling:", err)
		return nil
	}

	var tableNames []string
	for _, table := range tables {
		tableNames = append(tableNames, table["name"])
	}

	return tableNames
}

func retrieveTableDefinition(ctx context.Context, tablename string) ([]map[string]interface{}, error) {
	jsonData := ""

	clientMutex.Lock()

	client := getClient(ctx)

	query := fmt.Sprintf("PRAGMA table_info(%s);", tablename)
	result, err := client.SendQuery(query)

	clientMutex.Unlock()

	if err != nil {
		jsonData = "{\"data\":[{\"name\":\"error\"}]"
	} else {
		jsonData = string(result.Data)
	}

	var tableDef []map[string]string
	err = json.Unmarshal([]byte(jsonData), &tableDef)
	if err != nil {
		plugin.Logger(ctx).Error("Error unmarshalling:", "err", err)
		return nil, err
	}

	var colDefs []map[string]interface{}
	for _, table := range tableDef {
		col := make(map[string]interface{})
		if name, ok := table["name"]; ok {
			col["name"] = name
		}
		if colType, ok := table["type"]; ok {
			col["type"] = colType
		}
		if pk, ok := table["pk"]; ok {
			if err == nil {
				col["pk"] = pk
			}
		}
		colDefs = append(colDefs, col)
	}

	return colDefs, nil
}

// retrieves the description for a given table name
func getTableDescription(ctx context.Context, name string) (string, bool) {
	// Ensure LoadJSON is called only once
	loadOnce.Do(func() {
		if !isLoaded {
			if err := LoadJSON(); err != nil {
				panic("Error loading JSON: " + err.Error())
			}
			isLoaded = true
		}
	})

	description, exists := tablesMap[name]
	return description, exists
}

// LoadJSON loads and parses the JSON file into tablesMap
func LoadJSON() error {
	if jsonData == nil {
		return errors.New("embedded JSON data is nil")
	}

	// Parse the embedded JSON data
	var tables []Table
	if err := json.Unmarshal(jsonData, &tables); err != nil {
		return err
	}

	// Store the parsed data in tablesMap
	tablesMap = make(map[string]string)
	for _, table := range tables {
		tablesMap[table.Name] = table.Description
	}

	return nil
}

func getClient(ctx context.Context) *osquery.Client {
	once.Do(func() {
		singletonClient = &osquery.Client{}
		clientInitErr = singletonClient.Start("/home/sven/go/src/osquery-extension/extension --socket /home/sven/.osquery/shell.em")
		if clientInitErr != nil {
			plugin.Logger(ctx).Info("Error initializing client:", clientInitErr)
		}
	})

	if clientInitErr != nil {
		return nil
	}
	return singletonClient
}
