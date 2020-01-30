package dhcpv6pd

import (
	"log"
	"net"
	"os/exec"
	"strings"

	"github.com/danos/encoding/rfc7951/data"
	"jsouthworth.net/go/etm/agent"
	"jsouthworth.net/go/etm/atom"
	"jsouthworth.net/go/immutable/hashmap"
)

type DHCPv6PD struct {
	config        *atom.Atom
	knownPrefixes *agent.Agent

	cfgObj   *Config
	stateObj *State
}

func New(initialConfig *data.Tree, w ConfigWriter) *DHCPv6PD {
	config := atom.New(data.TreeNew())
	knownPrefixes := agent.New(hashmap.Empty())
	knownPrefixes.Watch("debug", func(key, _, _, new interface{}) {
		log.Println(key, "known-prefixes updated to", new)
	})
	ds := desiredState(config, knownPrefixes)
	systemUpdater(ds)
	config.Reset(initialConfig)
	return &DHCPv6PD{
		config:        config,
		knownPrefixes: knownPrefixes,
		cfgObj:        newConfig(config, w),
		stateObj:      newState(ds),
	}
}

func (s *DHCPv6PD) Config() *Config {
	return s.cfgObj
}

func (s *DHCPv6PD) State() *State {
	return s.stateObj
}

func (s *DHCPv6PD) HandlePrefixAssigned(in *data.Tree) {
	s.knownPrefixes.Send(
		(*hashmap.Map).Assoc,
		in.At("/vyatta-dhcpv6pd-v1:interface").ToNative(),
		in.At("/vyatta-dhcpv6pd-v1:prefix").ToNative(),
	)
}

func (s *DHCPv6PD) HandlePrefixRemoved(in *data.Tree) {
	s.knownPrefixes.Send(
		(*hashmap.Map).Delete,
		in.At("/vyatta-dhcpv6pd-v1:interface").ToNative(),
	)
}

type Emitter interface {
	Emit(moduleName, notificationName string, object interface{}) error
}

func EmitPrefixAssigned(emitter Emitter, iface, prefix string) error {
	return emitter.Emit("vyatta-dhcpv6pd-v1", "prefix-assigned",
		data.TreeNew().
			Assoc("/vyatta-dhcpv6pd-v1:interface", iface).
			Assoc("/vyatta-dhcpv6pd-v1:prefix", prefix))
}

func EmitPrefixRemoved(emitter Emitter, iface, prefix string) error {
	return emitter.Emit("vyatta-dhcpv6pd-v1", "prefix-removed",
		data.TreeNew().
			Assoc("/vyatta-dhcpv6pd-v1:interface", iface).
			Assoc("/vyatta-dhcpv6pd-v1:prefix", prefix))
}

type ConfigWriter interface {
	WriteConfig(config *data.Tree) error
}

type Config struct {
	tree *atom.Atom

	w ConfigWriter
}

func newConfig(config *atom.Atom, w ConfigWriter) *Config {
	config.Watch("debug", func(key, _, _, new interface{}) {
		log.Println(key, "config updated to:", new)
	})
	return &Config{
		tree: config,
		w:    w,
	}
}

func (c *Config) Set(new *data.Tree) error {
	c.tree.Reset(new)
	return c.w.WriteConfig(new)
}

func (c *Config) Get() *data.Tree {
	return c.tree.Deref().(*data.Tree)
}

func (c *Config) Check(tree *data.Tree) error {
	return nil
}

type State struct {
	desiredState *agent.Agent
}

func newState(state *agent.Agent) *State {
	return &State{
		desiredState: state,
	}
}

func (s *State) Get() *data.Tree {
	//todo: convert desired state to data.Tree and model in YANG
	return data.TreeNew()
}

func desiredState(config *atom.Atom, knownPrefixes *agent.Agent) *agent.Agent {
	DS := agent.New(hashmap.New())
	config.Watch("desiredState", func(_, _, _, new interface{}) {
		DS.Send((*hashmap.Map).Assoc,
			"config",
			transformConfigToDesiredState(new.(*data.Tree)))
	})
	knownPrefixes.Watch("desiredState", func(_, _, _, new interface{}) {
		DS.Send((*hashmap.Map).Assoc, "known-prefixes", new)
	})
	DS.Watch("debug", func(key, _, _, new interface{}) {
		log.Println(key, "desired state updated to:", new)
	})
	return DS
}

func systemUpdater(desiredState *agent.Agent) {
	K := agent.New(hashmap.Empty())
	desiredState.Watch("systemUpdater", func(_, _, old, new interface{}) {
		K.Send(updateKernel, new)
	})
}

func updateKernel(old, new *hashmap.Map) *hashmap.Map {
	log.Println("updating system from:", old, "to:", new)

	removeLines := getIPBatchRemove(old, new)
	log.Println("removing the following addresses", removeLines)
	/*err := runIPBatch(removeLines)
	if err != nil {
		log.Println("error while removing addresses", err)
	}*/

	addLines := getIPBatchAdd(old, new)
	log.Println("adding the following addresses", addLines)
	/*err = runIPBatch(addLines)
	if err != nil {
		log.Println("error while adding addresses", err)
	}*/

	return new
}

func runIPBatch(input []string) error {
	if len(input) == 0 {
		return nil
	}
	cmd := exec.Command("ip", "-force", "-batch", "-")
	cmd.Stdin = strings.NewReader(strings.Join(input, "\n"))
	return cmd.Run()
}

func getIPBatchRemove(old, new *hashmap.Map) []string {
	removedPrefixes := make(map[string]string)
	val, found := old.Find("known-prefixes")
	if !found {
		return nil
	}
	pfxs := val.(*hashmap.Map)
	pfxs.Range(func(key, val string) {
		if !new.Contains(key) {
			removedPrefixes[key] = val
		}
	})
	var out []string
	conf := old.At("config").(*hashmap.Map)
	for intf, prefix := range removedPrefixes {
		conf.Range(func(targetIntf string, targetConf *hashmap.Map) {
			if targetConf.At("dhcpv6-client-interface") != intf {
				return
			}
			address := calculateAddress(
				targetIntf, targetConf, prefix)
			if address == "" {
				log.Printf("failed to calculate address",
					targetIntf, targetConf, prefix)
				return
			}
			out = append(out,
				"address del "+address+" dev "+targetIntf)
		})
	}
	return out
}

func getIPBatchAdd(old, new *hashmap.Map) []string {
	addedPrefixes := make(map[string]string)
	val, found := new.Find("known-prefixes")
	if !found {
		return nil
	}
	pfxs := val.(*hashmap.Map)
	pfxs.Range(func(key, val string) {
		if !old.Contains(key) {
			addedPrefixes[key] = val
		}
	})
	var out []string
	conf := new.At("config").(*hashmap.Map)
	for intf, prefix := range addedPrefixes {
		conf.Range(func(targetIntf string, targetConf *hashmap.Map) {
			if targetConf.At("dhcpv6-client-interface") != intf {
				return
			}
			address := calculateAddress(
				targetIntf, targetConf, prefix)
			if address == "" {
				log.Printf("failed to calculate address",
					targetIntf, targetConf, prefix)
				return
			}
			out = append(out,
				"address add "+address+" dev "+targetIntf)
		})
	}
	return out
}

func transformConfigToDesiredState(tree *data.Tree) *hashmap.Map {
	// This is kind of gross but the model is kind of gross so there
	// is no avoiding it. Maps configuration model to a map from
	// interface name to dhcpv6pd address info.
	return hashmap.Empty().Transform(func(m *hashmap.TMap) *hashmap.TMap {
		ifaceTypes := tree.At("/vyatta-interfaces-v1:interfaces").AsObject()
		ifaceTypes.Range(func(ifaceType string, val *data.Value) {
			listKey, found := getIfaceKey(ifaceType)
			if !found {
				log.Println("unknown interface type", ifaceType)
				return
			}
			val.AsArray().Range(func(val *data.Value) {
				obj := val.AsObject()
				out := hashmap.Empty().AsTransient()
				obj.At("ipv6").ToTree().
					At("/vyatta-ipv6-rtradv-v1:address/vyatta-dhcpv6pd-v1:dhcpv6pd").
					AsObject().
					Range(func(key string, val *data.Value) {

						out.Assoc(stripKey(key), val.ToNative())
					})
				m.Assoc(
					obj.At(listKey).ToNative(),
					out.AsPersistent(),
				)
			})
		})
		return m
	})
}

func getIfaceKey(ifaceType string) (string, bool) {
	switch ifaceType {
	case "vyatta-interfaces-dataplane-v1:dataplane":
		return "tagnode", true
	default:
		return "", false
	}
}

func stripKey(key string) string {
	elems := strings.SplitN(key, ":", 2)
	switch len(elems) {
	case 1:
		return elems[0]
	default:
		return elems[1]
	}
}

func calculateAddress(
	targetIntf string,
	targetConf *hashmap.Map,
	prefix string,
) string {
	_, ipv6Net, err := net.ParseCIDR(prefix)
	if err != nil {
		log.Println("error calculating ipv6Addr from", prefix)
		return ""
	}

	switch targetConf.At("address-type") {
	case "eui64":
		if len, _ := ipv6Net.Mask.Size(); len > 64 {
			log.Println(prefix, "invalid prefix size", len,
				"for eui64 calculation on", targetIntf)
			return ""
		}
		return calculateEUI64(getMACAddress(targetIntf), ipv6Net)
	case "template":
		return calculateTemplate(targetConf.At("template").(string),
			ipv6Net)
	}
	return ""
}

func getMACAddress(intf string) net.HardwareAddr {
	iface, err := net.InterfaceByName(intf)
	if err != nil {
		log.Println("failed to retrieve information about interface",
			intf)
		return nil
	}
	return iface.HardwareAddr
}

func calculateEUI64(mac net.HardwareAddr, prefix *net.IPNet) string {
	eui64 := make([]byte, 8)
	mid := len(mac) / 2
	copy(eui64, mac[0:mid])
	eui64[mid] = 0xff
	eui64[mid+1] = 0xfe
	copy(eui64[mid+2:], mac[mid:])

	ip := make([]byte, 16)
	masklen := 64 / 8
	copy(ip, prefix.IP)
	copy(ip[masklen:], eui64)

	prefix.IP = ip
	prefix.Mask = net.CIDRMask(64, 128)
	return prefix.String()
}

func calculateTemplate(template string, prefix *net.IPNet) string {
	return ""
}
