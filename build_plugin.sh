#!/bin/sh

go build -gcflags=all="-N -l" -o "/home/sven/.steampipe/plugins/local/osquery/osquery.plugin"
