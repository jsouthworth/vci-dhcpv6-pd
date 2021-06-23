// Copyright (c) 2020-2021, ATT Intellectual Property. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"bufio"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/danos/encoding/rfc7951"
	"github.com/danos/encoding/rfc7951/data"
	"github.com/danos/vci"
	pd "github.com/danos/vci-dhcpv6-pd"
)

const CONFFILE = "/run/vci-dhcpv6-pd/config.cache"
const LEASEDIR = "/var/lib/dhcp/"
const LEASETMPL = `dhclient_v6_(.*)\.leases`

func readCachedConfig(conf string) (*data.Tree, error) {
	f, err := os.Open(conf)
	if os.IsNotExist(err) {
		return data.TreeNew(), nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	out := data.TreeNew()
	dec := rfc7951.NewDecoder(f)
	err = dec.Decode(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func writeCachedConfig(conf string, t *data.Tree) error {
	err := os.MkdirAll(filepath.Dir(conf), 0644)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(conf, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := rfc7951.NewEncoder(f)
	return enc.Encode(t)
}

func readExistingLeases(dir, tmpl string) {
	client, err := vci.Dial()
	if err != nil {
		log.Println(err)
	}
	defer client.Close()
	// Treat existing leases as renews and emit the prefix
	// assigned message again since we don't know if dhclient has
	// done this previously. A better mechanism is needed for this...
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Println(err)
		return
	}
	re := regexp.MustCompile(tmpl)
	for _, file := range files {
		matches := re.FindStringSubmatch(file.Name())
		if len(matches) != 2 {
			continue
		}
		iface := matches[1]
		prefixes := readLeaseFile(filepath.Join(dir, file.Name()))
		for _, prefix := range prefixes {
			log.Println("Emitting prefix-assigned", iface, prefix)
			err := pd.EmitPrefixAssigned(client, iface, prefix)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func readLeaseFile(file string) []string {
	re := regexp.MustCompile("iaprefix (.*) {")
	f, err := os.Open(file)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var prefixes []string
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			break
		}
		matches := re.FindStringSubmatch(l)
		if len(matches) < 2 {
			continue
		}
		prefixes = append(prefixes, matches[1])
	}
	var uniquePrefixes []string
	seen := make(map[string]struct{})
	for _, prefix := range prefixes {
		if _, ok := seen[prefix]; ok {
			continue
		}
		uniquePrefixes = append(uniquePrefixes, prefix)
		seen[prefix] = struct{}{}
	}
	log.Println("unique prefixes:", uniquePrefixes)
	return uniquePrefixes
}

type cachedConfigWriter func(t *data.Tree) error

func (w cachedConfigWriter) WriteConfig(t *data.Tree) error {
	return w(t)
}

func main() {
	t, err := readCachedConfig(CONFFILE)
	if err != nil {
		log.Fatal(err)
	}

	comp := vci.NewComponent("net.vyatta.vci.dhcpv6pd")
	service := pd.New(
		t,
		cachedConfigWriter(func(t *data.Tree) error {
			return writeCachedConfig(CONFFILE, t)
		}),
	)
	client := comp.Client()
	client.Subscribe("vyatta-dhcpv6pd-v1", "prefix-assigned",
		service.HandlePrefixAssigned).Run()
	client.Subscribe("vyatta-dhcpv6pd-v1", "prefix-removed",
		service.HandlePrefixRemoved).Run()
	comp.Model("net.vyatta.vci.dhcpv6pd.v1").
		Config(service.Config()).
		State(service.State())
	comp.Run()
	go readExistingLeases(LEASEDIR, LEASETMPL)
	comp.Wait()
	log.Println("vci-dhcpv6-pd", "shutting down")
	os.Exit(0)
}
