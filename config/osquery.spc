connection "osquery" {
  plugin = "steampipe-plugin-osquery"

  # needed to create the osqueryi extension socket
  osquery_command = "osqueryi --nodisable-extensions"

  # needed to run the extension
  osquery_extension_command = "/home/sven/go/src/osquery-extension/extension --socket /home/sven/.osquery/shell.em"
}