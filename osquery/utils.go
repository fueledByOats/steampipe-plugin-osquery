package osquery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/creack/pty"
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
	once sync.Once
	//singletonClient *client.Client
	singletonClient *Client
	clientMutex     sync.Mutex
	clientInitErr   error
)

const (
	ExitString = "exit"
)

type Query struct {
	SQL string `json:"query"`
}

type Result struct {
	Data json.RawMessage `json:"data"`
}

type Client struct {
	ptmx0  *os.File
	ptmx1  *os.File
	ptmx2  *os.File
	ctx    context.Context
	cancel context.CancelFunc
}

func retrieveJSONDataForTable(ctx context.Context, tablename string, quals string) string {
	clientMutex.Lock()

	client := getClient(ctx)

	query := fmt.Sprintf("SELECT * FROM %s", tablename)
	if quals != "" {
		query = fmt.Sprintf("SELECT * FROM %s WHERE %s", tablename, quals)
	}
	result, err := client.SendQuery(ctx, query)

	clientMutex.Unlock()

	if err != nil {
		fmt.Println("Error:", err)
		return ""
	} else {
		return string(result.Data)
	}
}

func retrieveOsqueryTableNames(ctx context.Context) []string {
	client := Client{}
	err := client.Start(ctx, "/home/sven/go/src/osquery-extension/extension --socket /home/sven/.osquery/shell.em")
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}

	result, err := client.SendQuery(ctx, "SELECT name FROM osquery_registry WHERE registry='table'")
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}

	client.Stop()

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
	result, err := client.SendQuery(ctx, query)

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

func (c *Client) Start(ctx context.Context, command string) error {

	c.ctx, c.cancel = context.WithCancel(context.Background())

	// needed to create osquery socket
	cmd1 := exec.Command("osqueryi", "--nodisable_extensions")
	var err error
	c.ptmx1, err = startCommandWithPty(cmd1)
	if err != nil {
		return fmt.Errorf("failed to start cmd1: %v", err)
	}

	// Split the command string into command and arguments
	cmdArgs := strings.Split(command, " ")
	cmd2 := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	c.ptmx2, err = startCommandWithPty(cmd2)
	if err != nil {
		return fmt.Errorf("failed to start cmd2: %v", err)
	}

	return nil
}

func (c *Client) SendQuery(ctx context.Context, sql string) (*Result, error) {
	query := &Query{SQL: sql}
	encoder := json.NewEncoder(c.ptmx2)
	if err := encoder.Encode(query); err != nil {
		return nil, err
	}

	_, err := c.ptmx2.Write([]byte("\n"))
	if err != nil {
		return nil, err
	}

	// Wait for the response
	var response string
	scanner := bufio.NewScanner(c.ptmx2)
	for scanner.Scan() {
		line := scanner.Text()
		plugin.Logger(ctx).Info("Received:", line)
		if strings.HasPrefix(line, "{\"data\"") {
			response = line
			break
		}
	}

	if err := scanner.Err(); err != nil {
		// Log the error but don't immediately return if you have a valid response
		fmt.Println("Scanner error:", err)
	}

	if response != "" {
		return parseOsqueryResult(strings.NewReader(response)), nil
	}

	return nil, fmt.Errorf("no valid response received")
}

func (c *Client) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	if c.ptmx1 != nil {
		c.ptmx1.Close()
	}
	if c.ptmx2 != nil {
		c.ptmx2.Close()
	}
}

func parseOsqueryResult(r io.Reader) *Result {
	decoder := json.NewDecoder(r)
	result := &Result{}
	if err := decoder.Decode(result); err != nil {
		fmt.Println("Error decoding osquery result:", err)
		return nil
	}

	return result
}

func startCommandWithPty(cmd *exec.Cmd) (*os.File, error) {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}

	return ptmx, nil
}

func getClient(ctx context.Context) *Client {
	once.Do(func() {
		singletonClient = &Client{}
		//singletonClient = &client.Client{}
		clientInitErr = singletonClient.Start(ctx, "/home/sven/go/src/osquery-extension/extension --socket /home/sven/.osquery/shell.em")
		if clientInitErr != nil {
			plugin.Logger(ctx).Info("Error initializing client:", clientInitErr)
		}
	})

	if clientInitErr != nil {
		return nil
	}
	return singletonClient
}
