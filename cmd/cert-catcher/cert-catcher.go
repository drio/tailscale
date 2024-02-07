// This tool stores certs and links them to nodes in the tailnet.
//
// It uses tsnet so we can query the tailnet to extract the name of
// the host that makes the request and link the cert to it.
//
// Run the tool and then, from a node in the tailnet you can use
// tailscale cert to generate a cert and then you can send it for
// storage with:
//
// $ curl  --data-binary @/path/to/host.cert http://cert-cacher:9191/
// $ curl  --data-binary @/path/to/host.pem http://cert-cacher:9191/
//
// The tool looks for the first line in the file to determine if the file
// is a the cert or the private key.
//
// Other requests of the same type will update the cert.
//
// To retrieve the context of the cert:
//
// $ curl http://cert-cacher:9191/key
// $ curl http://cert-cacher:9191/cert
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"tailscale.com/tsnet"
)

var (
	addr     = flag.String("addr", ":9191", "address to listen on")
	hostname = flag.String("hostname", "cert-cacher", "hostname to use on the tailnet (cert-cacher)")
	mu       sync.Mutex
	store    map[string]map[string]string
)

func main() {
	flag.Parse()
	s := new(tsnet.Server)
	s.Hostname = *hostname
	defer s.Close()

	store = make(map[string]map[string]string)

	ln, err := s.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		if r.Method == http.MethodGet {
			path := r.URL.Path
			if path != "/cert" && path != "/key" {
				http.Error(w, fmt.Sprintf("invalid path=[%s] use /cert or /key paths", path), http.StatusBadGateway)
				return
			}

			nn := who.Node.Name
			m, hasEntries := store[nn]
			if !hasEntries {
				fmt.Fprintf(w, "no entries for %s", nn)
			} else {
				k := strings.Replace(path, "/", "", 1)
				if value, ok := m[k]; ok {
					fmt.Fprintf(w, "%s", value)
				} else {
					fmt.Fprintf(w, "no %s for %s", path, nn)
				}
			}

		} else if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			defer r.Body.Close()
			if err != nil {
				http.Error(w, fmt.Sprintf("Error reading content: %v", err), http.StatusInternalServerError)
				return
			}

			lines := strings.Split(string(body), "\n")
			nn := who.Node.Name
			if lines[0] == "-----BEGIN CERTIFICATE-----" {
				if store[nn] == nil {
					store[nn] = make(map[string]string)
					store[nn]["cert"] = string(body)
				}
				fmt.Fprintf(w, "%s %s", nn, "cert saved")
			} else if lines[0] == "-----BEGIN PRIVATE KEY-----" {
				if store[nn] == nil {
					store[nn] = make(map[string]string)
					store[nn]["key"] = string(body)
				}
				fmt.Fprintf(w, "%s %s", nn, "key!")
			} else {
				http.Error(w, "Please, provide a cert or a key", http.StatusInternalServerError)
			}
		} else {
			// Optionally handle other methods or return an error
			http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		}
	})))
}
