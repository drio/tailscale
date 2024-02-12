// This tool stores certs and links them to nodes in the tailnet.
// Each cert has a key (private key) and a cert (signed public key)
//
// You can either store them in memory (default) or in disk (use -disk)
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
	"os"
	"strings"
	"sync"

	"tailscale.com/tsnet"
)

var (
	addr       = flag.String("addr", ":9191", "address to listen on")
	hostname   = flag.String("hostname", "cert-cacher", "hostname to use on the tailnet (cert-cacher)")
	saveToDisk = flag.Bool("disk", false, "store certs in disk")
	mu         sync.Mutex
)

func main() {
	flag.Parse()
	s := new(tsnet.Server)
	s.Hostname = *hostname
	defer s.Close()

	var store Store
	if *saveToDisk == true {
	} else {
		store = MemStore{}
	}
	store.Init()

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
		nn := who.Node.Name

		if r.Method == http.MethodGet {
			path := r.URL.Path
			if path != "/cert" && path != "/key" {
				http.Error(w, fmt.Sprintf("invalid path=[%s] use /cert or /key paths", path), http.StatusBadGateway)
				return
			}

			contents, found := store.Get(nn, path)
			if found {
				fmt.Fprintf(w, "%s", contents)
				return
			}
			fmt.Fprintf(w, "no %s for %s", path, nn)
		} else if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			defer r.Body.Close()
			if err != nil {
				http.Error(w, fmt.Sprintf("Error reading content: %v", err), http.StatusInternalServerError)
				return
			}

			contents, certOrKey := processBody(string(body))
			if certOrKey == "" {
				http.Error(w, "Please, provide a cert or a key", http.StatusInternalServerError)
				return
			}
			store.Upset(nn, contents, certOrKey)
			fmt.Fprintf(w, "%s %s saved.", nn, certOrKey)
		} else {
			// Optionally handle other methods or return an error
			http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		}
	})))
}

type Store interface {
	Init()
	Get(string, string) (string, bool)
	Upset(string, string, string) error
}

type DiskStore struct{}

func (d DiskStore) Init() {
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return
	}

	// Check write permission by trying to create a temporary file
	tmpFile, err := os.CreateTemp(currentDir, "tempfile_")
	if err != nil {
		log.Fatalf("Cannot write in current dir")
	}
	defer os.Remove(tmpFile.Name())

	// Check read permission by trying to open the temporary file for reading
	_, err = os.Open(tmpFile.Name())
	if err != nil {
		log.Fatalf("Cannot read in current dir")
	}
}

// Try to find a nodeName.[cert/key] file and return it
func (d DiskStore) Get(nodeName, path string) (string, bool) {
	filename := fmt.Sprintf("%s.%s", cleanNodeName((nodeName)), pathToCertOrKey(path))

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return "", false
	}

	return string(data), true
}

func (d DiskStore) Upset(nodeName, contents, certOrKey string) error {
	tmpFile, err := os.CreateTemp("", "tempfile_")
	if err != nil {
		return fmt.Errorf("Failed to create temporary file: %s", err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(contents)
	if err != nil {
		return fmt.Errorf("Failed to write to temporary file: %s", err)
	}
	tmpFile.Close() // Close the temporary file

	err = os.Rename(tmpFile.Name(), genFileName(nodeName, certOrKey))
	if err != nil {
		log.Fatalf("Failed to replace the original file with the new content: %s", err)
	}

	return nil
}

// Simple in memory MemStore to store the cert bits
// nodeName -> [key/cert] -> contents
type MemStore map[string]map[string]string

func (m MemStore) Init() {
	m = make(map[string]map[string]string)
}

// Try to find a cert piece (key or cert) given a nodeName and Path request
func (m MemStore) Get(nodeName, path string) (string, bool) {
	m2, hasEntries := m[nodeName]
	if !hasEntries {
		return "", false
	} else {
		if value, ok := m2[pathToCertOrKey(path)]; ok {
			return value, true
		} else {
			return "", false
		}
	}
}

func (m MemStore) Upset(nodeName, contents, certOrKey string) error {
	if m[nodeName] == nil {
		m[nodeName] = make(map[string]string)
	}
	m[nodeName][certOrKey] = string(contents)
	return nil
}

// Remove the suffix '.' in the node name if necessary
func cleanNodeName(nn string) string {
	if strings.HasSuffix(nn, ".") {
		return nn[:len(nn)-1]
	}
	return nn
}

func pathToCertOrKey(path string) string {
	return strings.Replace(path, "/", "", 1)
}

// Read the body and determine if it is a valid key or cert
// If it is valid return its contents and what it is.
// What it is can be: cert, key or "" in case it is not valid
func processBody(body string) (string, string) {
	lines := strings.Split(string(body), "\n")
	if lines[0] == "-----BEGIN CERTIFICATE-----" {
		return body, "cert"
	} else if lines[0] == "-----BEGIN PRIVATE KEY-----" {
		return body, "key"
	} else {
		return "", ""
	}
}

// Given a nodename and a path generate a filename
// m3.tailnetfoo.net, /cert -> m3.tailnetfoo.net.cert
func genFileName(nodeName, path string) string {
	return fmt.Sprintf("%s.%s", cleanNodeName((nodeName)), pathToCertOrKey(path))
}
