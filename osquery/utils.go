package osquery

import (
	"context"
	"fmt"
	"sync"

	"github.com/fueledByOats/osquery-extension-stdio-json/client"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

var (
	once            sync.Once
	singletonClient *client.Client
)

func retrieveOsqueryTableNames(ctx context.Context) []string {
	/*client := &client.Client{}
	err := client.Start("go run /home/sven/go/src/osquery-extension-ssh-json/server/extension.go --socket /home/sven/.osquery/shell.em")
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	defer client.Stop()

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

	return tableNames*/
	return []string{"users"}
}

func getClient(ctx context.Context) *client.Client {
	once.Do(func() {
		singletonClient = &client.Client{}
		err := singletonClient.Start("go run /home/sven/go/src/osquery-extension-stdio-json/server/extension.go --socket /home/sven/.osquery/shell.em")
		if err != nil {
			plugin.Logger(ctx).Info("Error initializing client:", err)
		}
	})

	return singletonClient
}

func retrieveJSONDataForTable(ctx context.Context, tablename string) string {
	client := getClient(ctx)
	query := fmt.Sprintf("SELECT * FROM %s", tablename)
	result, err := client.SendQuery(query)
	if err != nil {
		plugin.Logger(ctx).Info("Error retrieving json data:", err)
		return ""
	}

	return string(result.Data)
	/*return "[{\"description\":\"root\",\"directory\":\"/root\",\"gid\":\"0\",\"gid_signed\":\"0\",\"shell\":\"/bin/zsh\",\"uid\":\"0\",\"uid_signed\":\"0\",\"username\":\"root\",\"uuid\":\"\"},{\"description\":\"bin\",\"directory\":\"/bin\",\"gid\":\"1\",\"gid_signed\":\"1\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"1\",\"uid_signed\":\"1\",\"username\":\"bin\",\"uuid\":\"\"},{\"description\":\"daemon\",\"directory\":\"/\",\"gid\":\"2\",\"gid_signed\":\"2\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"2\",\"uid_signed\":\"2\",\"username\":\"daemon\",\"uuid\":\"\"},{\"description\":\"mail\",\"directory\":\"/var/spool/mail\",\"gid\":\"12\",\"gid_signed\":\"12\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"8\",\"uid_signed\":\"8\",\"username\":\"mail\",\"uuid\":\"\"},{\"description\":\"ftp\",\"directory\":\"/srv/ftp\",\"gid\":\"11\",\"gid_signed\":\"11\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"14\",\"uid_signed\":\"14\",\"username\":\"ftp\",\"uuid\":\"\"},{\"description\":\"http\",\"directory\":\"/srv/http\",\"gid\":\"33\",\"gid_signed\":\"33\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"33\",\"uid_signed\":\"33\",\"username\":\"http\",\"uuid\":\"\"},{\"description\":\"uuidd\",\"directory\":\"/\",\"gid\":\"68\",\"gid_signed\":\"68\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"68\",\"uid_signed\":\"68\",\"username\":\"uuidd\",\"uuid\":\"\"},{\"description\":\"dbus\",\"directory\":\"/\",\"gid\":\"81\",\"gid_signed\":\"81\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"81\",\"uid_signed\":\"81\",\"username\":\"dbus\",\"uuid\":\"\"},{\"description\":\"nobody\",\"directory\":\"/\",\"gid\":\"99\",\"gid_signed\":\"99\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"99\",\"uid_signed\":\"99\",\"username\":\"nobody\",\"uuid\":\"\"},{\"description\":\"systemd-journal-gateway\",\"directory\":\"/\",\"gid\":\"191\",\"gid_signed\":\"191\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"191\",\"uid_signed\":\"191\",\"username\":\"systemd-journal-gateway\",\"uuid\":\"\"},{\"description\":\"systemd-timesync\",\"directory\":\"/\",\"gid\":\"192\",\"gid_signed\":\"192\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"192\",\"uid_signed\":\"192\",\"username\":\"systemd-timesync\",\"uuid\":\"\"},{\"description\":\"systemd-network\",\"directory\":\"/\",\"gid\":\"193\",\"gid_signed\":\"193\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"193\",\"uid_signed\":\"193\",\"username\":\"systemd-network\",\"uuid\":\"\"},{\"description\":\"systemd-bus-proxy\",\"directory\":\"/\",\"gid\":\"194\",\"gid_signed\":\"194\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"194\",\"uid_signed\":\"194\",\"username\":\"systemd-bus-proxy\",\"uuid\":\"\"},{\"description\":\"systemd-resolve\",\"directory\":\"/\",\"gid\":\"195\",\"gid_signed\":\"195\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"195\",\"uid_signed\":\"195\",\"username\":\"systemd-resolve\",\"uuid\":\"\"},{\"description\":\"systemd Journal Upload\",\"directory\":\"/\",\"gid\":\"999\",\"gid_signed\":\"999\",\"shell\":\"/sbin/nologin\",\"uid\":\"999\",\"uid_signed\":\"999\",\"username\":\"systemd-journal-upload\",\"uuid\":\"\"},{\"description\":\"systemd Journal Remote\",\"directory\":\"/\",\"gid\":\"998\",\"gid_signed\":\"998\",\"shell\":\"/sbin/nologin\",\"uid\":\"998\",\"uid_signed\":\"998\",\"username\":\"systemd-journal-remote\",\"uuid\":\"\"},{\"description\":\"\",\"directory\":\"/home/sven\",\"gid\":\"1000\",\"gid_signed\":\"1000\",\"shell\":\"/bin/zsh\",\"uid\":\"1000\",\"uid_signed\":\"1000\",\"username\":\"sven\",\"uuid\":\"\"},{\"description\":\"Simple Desktop Display Manager\",\"directory\":\"/var/lib/sddm\",\"gid\":\"997\",\"gid_signed\":\"997\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"997\",\"uid_signed\":\"997\",\"username\":\"sddm\",\"uuid\":\"\"},{\"description\":\"Policy Kit Daemon\",\"directory\":\"/\",\"gid\":\"102\",\"gid_signed\":\"102\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"102\",\"uid_signed\":\"102\",\"username\":\"polkitd\",\"uuid\":\"\"},{\"description\":\"avahi\",\"directory\":\"/\",\"gid\":\"84\",\"gid_signed\":\"84\",\"shell\":\"/bin/nologin\",\"uid\":\"84\",\"uid_signed\":\"84\",\"username\":\"avahi\",\"uuid\":\"\"},{\"description\":\"RealtimeKit\",\"directory\":\"/proc\",\"gid\":\"133\",\"gid_signed\":\"133\",\"shell\":\"/bin/false\",\"uid\":\"133\",\"uid_signed\":\"133\",\"username\":\"rtkit\",\"uuid\":\"\"},{\"description\":\"\",\"directory\":\"/var/lib/colord\",\"gid\":\"124\",\"gid_signed\":\"124\",\"shell\":\"/bin/false\",\"uid\":\"124\",\"uid_signed\":\"124\",\"username\":\"colord\",\"uuid\":\"\"},{\"description\":\"git daemon user\",\"directory\":\"/\",\"gid\":\"996\",\"gid_signed\":\"996\",\"shell\":\"/bin/bash\",\"uid\":\"996\",\"uid_signed\":\"996\",\"username\":\"git\",\"uuid\":\"\"},{\"description\":\"systemd Core Dumper\",\"directory\":\"/\",\"gid\":\"995\",\"gid_signed\":\"995\",\"shell\":\"/sbin/nologin\",\"uid\":\"995\",\"uid_signed\":\"995\",\"username\":\"systemd-coredump\",\"uuid\":\"\"},{\"description\":\"MariaDB\",\"directory\":\"/var/lib/mysql\",\"gid\":\"89\",\"gid_signed\":\"89\",\"shell\":\"/sbin/nologin\",\"uid\":\"89\",\"uid_signed\":\"89\",\"username\":\"mysql\",\"uuid\":\"\"},{\"description\":\"usbmux user\",\"directory\":\"/\",\"gid\":\"140\",\"gid_signed\":\"140\",\"shell\":\"/sbin/nologin\",\"uid\":\"140\",\"uid_signed\":\"140\",\"username\":\"usbmux\",\"uuid\":\"\"},{\"description\":\"Geoinformation service\",\"directory\":\"/var/lib/geoclue\",\"gid\":\"992\",\"gid_signed\":\"992\",\"shell\":\"/sbin/nologin\",\"uid\":\"992\",\"uid_signed\":\"992\",\"username\":\"geoclue\",\"uuid\":\"\"},{\"description\":\"cups helper user\",\"directory\":\"/\",\"gid\":\"209\",\"gid_signed\":\"209\",\"shell\":\"/sbin/nologin\",\"uid\":\"209\",\"uid_signed\":\"209\",\"username\":\"cups\",\"uuid\":\"\"},{\"description\":\"dhcpcd privilege separation\",\"directory\":\"/var/lib/dhcpcd\",\"gid\":\"991\",\"gid_signed\":\"991\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"991\",\"uid_signed\":\"991\",\"username\":\"dhcpcd\",\"uuid\":\"\"},{\"description\":\"BIND DNS Server\",\"directory\":\"/\",\"gid\":\"40\",\"gid_signed\":\"40\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"40\",\"uid_signed\":\"40\",\"username\":\"named\",\"uuid\":\"\"},{\"description\":\"systemd Userspace OOM Killer\",\"directory\":\"/\",\"gid\":\"989\",\"gid_signed\":\"989\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"989\",\"uid_signed\":\"989\",\"username\":\"systemd-oom\",\"uuid\":\"\"},{\"description\":\"OpenVPN\",\"directory\":\"/\",\"gid\":\"988\",\"gid_signed\":\"988\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"988\",\"uid_signed\":\"988\",\"username\":\"openvpn\",\"uuid\":\"\"},{\"description\":\"tss user for tpm2\",\"directory\":\"/\",\"gid\":\"986\",\"gid_signed\":\"986\",\"shell\":\"/usr/bin/nologin\",\"uid\":\"986\",\"uid_signed\":\"986\",\"username\":\"tss\",\"uuid\":\"\"}]"*/
}
