package main

import (
	"flag"

	"github.com/danos/vci"
	pd "github.com/danos/vci-dhcpv6-pd"
)

var notif, iface, prefix string

func init() {
	flag.StringVar(&notif, "notif", "", "The notification to emit")
	flag.StringVar(&iface, "interface", "",
		"The interface on which the event was seen")
	flag.StringVar(&prefix, "prefix", "",
		"The ipv6 prefix of the event")
}
func main() {
	flag.Parse()
	client, err := vci.Dial()
	if err != nil {
		panic(err)
	}
	defer client.Close()

	switch notif {
	case "prefix-assigned":
		pd.EmitPrefixAssigned(client, iface, prefix)
	case "prefix-removed":
		pd.EmitPrefixRemoved(client, iface, prefix)
	}
}
