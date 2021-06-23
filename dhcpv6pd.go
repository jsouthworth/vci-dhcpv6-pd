// Copyright (c) 2020-2021, ATT Intellectual Property. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
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
	"jsouthworth.net/go/seq"
	"jsouthworth.net/go/transduce"
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
	err := runIPBatch(removeLines)
	if err != nil {
		log.Println("error while removing addresses", err)
	}

	addLines := getIPBatchAdd(old, new)
	log.Println("adding the following addresses", addLines)
	err = runIPBatch(addLines)
	if err != nil {
		log.Println("error while adding addresses", err)
	}

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

func getAddresses(state *hashmap.Map) *hashmap.Map {
	prefixesV, found := state.Find("known-prefixes")
	if !found {
		return hashmap.Empty()
	}
	prefixes := prefixesV.(*hashmap.Map)
	configV, found := state.Find("config")
	if !found {
		return nil
	}
	config := configV.(*hashmap.Map)

	return seq.TransformInto(
		hashmap.Empty(),
		transduce.Compose(
			transduce.Map(func(in interface{}) interface{} {
				ent := in.(hashmap.Entry)
				sourceIntf, targetIntfs := ent.Key(), ent.Value()
				prefixV, found := prefixes.Find(sourceIntf)
				if !found {
					return nil
				}
				prefix := prefixV.(string)
				out := seq.TransformInto(
					hashmap.Empty(),
					transduce.Compose(
						transduce.Map(func(in interface{}) interface{} {
							ent := in.(hashmap.Entry)
							targetIntf, targetConf :=
								ent.Key().(string), ent.Value().(*hashmap.Map)
							address := calculateAddress(
								targetIntf, targetConf, prefix)
							if address == "" {
								log.Printf("failed to calculate address",
									targetIntf, targetConf, prefix)
								return nil
							}
							return hashmap.EntryNew(targetIntf, address)

						}),
						transduce.Remove(func(in interface{}) bool {
							return in == nil
						}),
					),
					targetIntfs,
				)
				return hashmap.EntryNew(sourceIntf, out)
			}),
			transduce.Remove(func(in interface{}) bool {
				return in == nil
			}),
		),
		config,
	).(*hashmap.Map)
}

func getIPBatchCommand(action, address, dev string) string {
	return "address " + action + " " + address + " dev " + dev
}

func getIPBatchCommandsFromAction(action string, new, old *hashmap.Map) []string {
	newAddresses := getAddresses(new)
	oldAddresses := getAddresses(old)
	log.Println("computing differences between new:", newAddresses, "old:", oldAddresses)
	var out []string
	newAddresses.Range(func(sourceIntf, targetIntfs interface{}) {
		oldTargetIntfsV, found := oldAddresses.Find(sourceIntf)
		if found {
			oldTargetIntfs := oldTargetIntfsV.(*hashmap.Map)
			targetIntfs.(*hashmap.Map).Range(func(targetIntf, address interface{}) {
				if !oldTargetIntfs.Contains(targetIntf) {
					out = append(out,
						getIPBatchCommand(action,
							address.(string), targetIntf.(string)))
				} else {
					oldAddress := oldTargetIntfs.At(targetIntf).(string)
					if address != oldAddress {
						out = append(out,
							getIPBatchCommand(action,
								address.(string), targetIntf.(string)))
					}
				}
			})
		} else {
			targetIntfs.(*hashmap.Map).Range(func(targetIntf, address interface{}) {
				out = append(out,
					getIPBatchCommand(action, address.(string), targetIntf.(string)))
			})
		}
	})
	return out
}
func getIPBatchRemove(old, new *hashmap.Map) []string {
	return getIPBatchCommandsFromAction("del", old, new)
}

func getIPBatchAdd(old, new *hashmap.Map) []string {
	return getIPBatchCommandsFromAction("add", new, old)
}

func transformConfigToDesiredState(tree *data.Tree) *hashmap.Map {
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
					At("/vyatta-dhcpv6pd-v1:dhcpv6pd/target-interface").
					AsArray().
					Range(func(val *data.Value) {
						obj := val.AsObject()
						key := obj.At("name").ToNative()
						value := hashmap.Empty().AsTransient()
						obj.Range(func(key string, val *data.Value) {
							value.Assoc(stripKey(key), val.ToNative())
						})
						out = out.Assoc(key, value.AsPersistent())
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
		return calculateEUI64(ipv6Net,
			uint16(targetConf.At("sla-id").(uint32)),
			getMACAddress(targetIntf))
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

func calculateEUI64(prefix *net.IPNet, slaID uint16, mac net.HardwareAddr) string {
	eui64 := make([]byte, 8)
	mid := len(mac) / 2
	copy(eui64, mac[0:mid])
	eui64[mid] = 0xff
	eui64[mid+1] = 0xfe
	copy(eui64[mid+2:], mac[mid:])

	ip := make([]byte, 16)
	masklen := 64 / 8
	copy(ip, prefix.IP)
	ip[masklen-2] = (uint8(slaID>>8) & ^prefix.Mask[masklen-2]) |
		(prefix.Mask[masklen-2] & prefix.IP[masklen-2])
	ip[masklen-1] = (uint8(slaID&0xff) & ^prefix.Mask[masklen-1]) |
		(prefix.Mask[masklen-1] & prefix.IP[masklen-1])
	copy(ip[masklen:], eui64)

	prefix.IP = ip
	prefix.Mask = net.CIDRMask(64, 128)
	return prefix.String()
}
