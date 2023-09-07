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

type ClientConfig struct {
	OsqueryCommand   string
	ExtensionCommand string
}

type Client struct {
	config *ClientConfig
	ptmx1  *os.File
	ptmx2  *os.File
	ctx    context.Context
	cancel context.CancelFunc
}

func NewClient(cfg *ClientConfig) (*Client, error) {

	c := &Client{
		config: cfg,
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())

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
