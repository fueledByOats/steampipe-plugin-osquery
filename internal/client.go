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

	"github.com/creack/pty"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

const maxBufferSize = 512 * 1024 // 512KB

type Query struct {
	SQL string `json:"query"`
}

type Result struct {
	Data json.RawMessage `json:"data"`
}

type ClientConfig struct {
	OsqueryCommand   string
	ExtensionCommand string
}

type Client struct {
	config *ClientConfig
	ptmx1  *os.File
	ptmx2  *os.File
	ctx    context.Context
}

func NewClient(cfg *ClientConfig) (*Client, error) {

	c := &Client{
		config: cfg,
	}

	c.ctx = context.Background()

	cmd1Args := strings.Split(cfg.OsqueryCommand, " ")
	cmd1 := exec.Command(cmd1Args[0], cmd1Args[1:]...)
	var err error
	c.ptmx1, err = pty.Start(cmd1)
	if err != nil {
		return nil, fmt.Errorf("failed to start cmd1: %v", err)
	}

	cmd2Args := strings.Split(cfg.ExtensionCommand, " ")
	cmd2 := exec.Command(cmd2Args[0], cmd2Args[1:]...)
	c.ptmx2, err = pty.Start(cmd2)
	if err != nil {
		return nil, fmt.Errorf("failed to start cmd2: %v", err)
	}

	return c, nil
}

func (c *Client) SendQuery(sql string) (*Result, error) {
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

	// Increase the buffer size
	buf := make([]byte, 0, maxBufferSize)
	scanner.Buffer(buf, maxBufferSize)

	for scanner.Scan() {
		line := scanner.Text()
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

func (c *Client) RetrieveJSONDataForTable(ctx context.Context, d *plugin.QueryData) string {
	tablename := d.Table.Name
	qualString := ""

	if len(d.QueryContext.UnsafeQuals) > 0 {
		qualString = qualMapToString(d.QueryContext.UnsafeQuals)
	}

	if len(d.Quals) > 0 {
		qualString = equalQualsTransform(d.EqualsQuals.String())
	}

	query := fmt.Sprintf("SELECT * FROM %s", tablename)
	if qualString != "" {
		query = fmt.Sprintf("SELECT * FROM %s WHERE %s", tablename, qualString)
	}
	result, err := c.SendQuery(query)

	if err != nil {
		fmt.Println("Error:", err)
		return ""
	} else {
		return string(result.Data)
	}
}

func (c *Client) RetrieveOsqueryTableNames(ctx context.Context) []string {
	result, err := c.SendQuery("SELECT name FROM osquery_registry WHERE registry='table'")
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

func (c *Client) RetrieveTableDefinition(ctx context.Context, tablename string) ([]map[string]interface{}, error) {
	jsonData := ""

	query := fmt.Sprintf("PRAGMA table_info(%s);", tablename)
	result, err := c.SendQuery(query)

	if err != nil {
		jsonData = "{\"data\":[{\"name\":\"error\"}]"
	} else {
		jsonData = string(result.Data)
	}

	var tableDef []map[string]interface{} // Change the type to interface{} for more generality
	err = json.Unmarshal([]byte(jsonData), &tableDef)
	if err != nil {
		plugin.Logger(ctx).Error("Error unmarshalling:", "err", err)
		return nil, err
	}

	return tableDef, nil
}

func (c *Client) Stop() {
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

// transform 'ab = cd' to '"ab" = "cd"'
func equalQualsTransform(input string) string {
	parts := strings.Split(input, "=")
	if len(parts) != 2 {
		return ""
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	return fmt.Sprintf(`"%s" = "%s"`, key, value)
}
