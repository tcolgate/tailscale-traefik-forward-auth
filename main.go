// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
//go:build linux

// Command nginx-auth is a tool that allows users to use Tailscale Whois
// authentication with NGINX as a reverse proxy. This allows users that
// already have a bunch of services hosted on an internal NGINX server
// to point those domains to the Tailscale IP of the NGINX server and
// then seamlessly use Tailscale for authentication.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"tailscale.com/client/tailscale"
)

var (
	addr = flag.String("addr", "127.0.0.1:6666", "address to listen on")
)

func main() {
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("headers: %#v", r.Header)
		remoteHost := r.Header.Get("X-Forwarded-For")
		remotePort := r.Header.Get("X-Forwarded-Port")
		if remoteHost == "" || remotePort == "" {
			w.WriteHeader(http.StatusBadRequest)
			log.Println("set Remote-Addr to $remote_addr and Remote-Port to $remote_port in your nginx config")
			return
		}

		remoteAddrStr := net.JoinHostPort(remoteHost, remotePort)
		remoteAddr, err := netip.ParseAddrPort(remoteAddrStr)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("remote address and port are not valid: %v", err)
			return
		}

		tsc := &tailscale.LocalClient{}
		info, err := tsc.WhoIs(r.Context(), remoteAddr.String())
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("can't look up %s: %v", remoteAddr, err)
			return
		}

		if info.Node.IsTagged() {
			w.WriteHeader(http.StatusForbidden)
			log.Printf("node %s is tagged", info.Node.Hostinfo.Hostname())
			return
		}

		// tailnet of connected node. When accessing shared nodes, this
		// will be empty because the tailnet of the sharee is not exposed.
		var tailnet string

		if !info.Node.Hostinfo.ShareeNode() {
			var ok bool
			_, tailnet, ok = strings.Cut(info.Node.Name, info.Node.ComputedName+".")
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				log.Printf("can't extract tailnet name from hostname %q", info.Node.Name)
				return
			}
			tailnet = strings.TrimSuffix(tailnet, ".beta.tailscale.net")
		}

		if expectedTailnet := r.Header.Get("Expected-Tailnet"); expectedTailnet != "" && expectedTailnet != tailnet {
			w.WriteHeader(http.StatusForbidden)
			log.Printf("user is part of tailnet %s, wanted: %s", tailnet, url.QueryEscape(expectedTailnet))
			return
		}

		h := w.Header()
		h.Set("Tailscale-Login", strings.Split(info.UserProfile.LoginName, "@")[0])
		h.Set("Tailscale-User", info.UserProfile.LoginName)
		h.Set("X-Webauth-User", info.UserProfile.LoginName)
		h.Set("Tailscale-Name", info.UserProfile.DisplayName)
		h.Set("Tailscale-Profile-Picture", info.UserProfile.ProfilePicURL)
		h.Set("Tailscale-Tailnet", tailnet)
		w.WriteHeader(http.StatusNoContent)
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("can't listen on %s: %v", *addr, err)
	}
	defer ln.Close()

	go func(ln net.Listener) {
		log.Printf("listening on %s", ln.Addr())
		log.Fatal(http.Serve(ln, mux))
	}(ln)

	for {
		select {}
	}
}
