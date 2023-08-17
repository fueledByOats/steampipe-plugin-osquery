package osquery

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"

	//debugging
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// debugging definition start

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
	ptmx0     *os.File
	ptmx1     *os.File
	ptmx2     *os.File
	ctx       context.Context
	cancel    context.CancelFunc
	origState *term.State
}

// debugging definition end

func tableOsquery(ctx context.Context, tablename string) *plugin.Table {
	// retrieve the JSON data for the given tablename
	//jsonData := retrieveJSONDataForTable(ctx, tablename)
	jsonData := retrieveJSONDataForTableTest(ctx, tablename)

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

func retrieveJSONDataForTableTest(ctx context.Context, tablename string) string {
	client := Client{}

	err := client.Start(ctx, "/home/sven/go/src/osquery-extension/extension --socket /home/sven/.osquery/shell.em")
	if err != nil {
		fmt.Println("Error:", err)
		return "[{\"error\":\"error starting client\"}]"
	}

	// Query for users
	result, err := client.SendQuery(ctx, "select * from users")
	client.Stop()
	if err != nil {
		fmt.Println("Error:", err)
		return fmt.Sprintf("[{\"error\":\"%s\"}]", err)
	} else {
		return string(result.Data)
	}

	//return "[{\"error\":\"error2\"}]"
}

func (c *Client) Start(ctx context.Context, command string) error {
	/*cmd1 := exec.Command("osqueryi", "--nodisable_extensions")
	err := cmd1.Start()
	if err != nil {
		return fmt.Errorf("failed to start cmd1: %v", err)
	}*/

	c.ctx, c.cancel = context.WithCancel(context.Background())

	/*// needed to create osquery socket
	cmd0 := exec.Command("pwd")
	var err0 error
	cmd0.Dir = "/home/sven/go"
	c.ptmx0, err0 = startCommandWithPty(cmd0)
	if err0 != nil {
		return fmt.Errorf("failed to start cmd1: %v", err0)
	}

	// Wait for the response
	scanner := bufio.NewScanner(c.ptmx0)
	for scanner.Scan() {
		line := scanner.Text()
		plugin.Logger(ctx).Info("Received go env:", line)
	}*/

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
	//cmd2.Dir = "/home/sven/go/src/osquery-extension/"
	c.ptmx2, err = startCommandWithPty(cmd2)
	if err != nil {
		return fmt.Errorf("failed to start cmd2: %v", err)
	}

	// Set stdin in raw mode and store the original state.
	/*c.origState, err = term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to set stdin in raw mode: %v", err)
	}*/
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
	if c.origState != nil {
		term.Restore(int(os.Stdin.Fd()), c.origState)
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
