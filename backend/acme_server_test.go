package backend

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type testingWriter struct {
	t *testing.T
}

func (tw *testingWriter) Write(p []byte) (int, error) {
	tw.t.Log(string(p))
	return len(p), nil
}

type acmeServer struct {
	t            *testing.T
	DirectoryURL string
	listener     net.Listener
	dnsListener  net.PacketConn

	txtRecords     map[string][]string
	txtRecordsLock sync.RWMutex
}

// create an in-memory ACME server for testing using pebble
func (b *testBackend) startACMEServer(t *testing.T) *acmeServer {

	as := &acmeServer{
		t: t,
	}

	// start an in-process DNS resolver for pebble
	var err error
	as.dnsListener, err = net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	dnsHandler := dns.NewServeMux()
	dnsHandler.HandleFunc(".", as.HandleDNS)

	dnsServer := &dns.Server{
		PacketConn: as.dnsListener,
		Handler:    dnsHandler,
	}
	go dnsServer.ActivateAndServe()

	dnsAddr, ok := as.dnsListener.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	logger := log.New(&testingWriter{t}, "Pebble ", log.LstdFlags)

	// generate self-signed certificate for TLS
	localIPs := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	expiration := time.Now().Add(365 * 24 * time.Hour)
	cert, key := generateSelfSignedCert(t, "localhost", localIPs, expiration)

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  key.PrivateKey,
			},
		},
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	rootCAs.AddCert(cert)

	b.tlsConfig = &tls.Config{
		RootCAs: rootCAs,
	}

	// create a local listener
	as.listener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := as.listener.Addr().(*net.TCPAddr).Port

	// wrap listener with TLS
	as.listener = tls.NewListener(as.listener, tlsConfig)

	const (
		oscpResponderURL               = ""
		alternateRoots                 = 0
		chainLength                    = 1
		strictMode                     = false
		externalAccountBindingRequired = false
		retryAuthz                     = 3
		retryOrder                     = 5
	)

	resolverAddress := dnsAddr.String()
	b.dnsResolvers = []string{
		dnsAddr.String(),
	}

	profiles := map[string]ca.Profile{
		"default": {
			Description:    "The default profile",
			ValidityPeriod: 7776000,
		},
	}

	db := db.NewMemoryStore()
	ca := ca.New(logger, db, oscpResponderURL, alternateRoots, chainLength, profiles)
	va := va.New(logger, port, port, strictMode, resolverAddress, db)

	wfeHandler := wfe.New(logger, db, va, ca,
		strictMode, externalAccountBindingRequired,
		retryAuthz, retryOrder)

	// start listening with TLS
	go func() {
		server := &http.Server{
			Handler: wfeHandler.Handler(),
		}
		server.Serve(as.listener)
	}()

	as.DirectoryURL = fmt.Sprintf("https://127.0.0.1:%d/dir", port)
	return as
}

func (as *acmeServer) HandleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		fqdn := normalizeFQDN(q.Name)

		switch q.Qtype {
		case dns.TypeTXT:
			as.txtRecordsLock.RLock()
			records, ok := as.txtRecords[fqdn]
			as.txtRecordsLock.RUnlock()
			if ok {
				rr := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: records,
				}

				msg.Answer = append(msg.Answer, rr)
			}
		}
	}

	if len(msg.Answer) == 0 && len(r.Question) > 0 {
		msg.Rcode = dns.RcodeSuccess
	}
	w.WriteMsg(msg)
}

func normalizeFQDN(fqdn string) string {
	if !strings.HasSuffix(fqdn, ".") {
		return fqdn + "."
	}
	return fqdn
}

func (as *acmeServer) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := normalizeFQDN(info.EffectiveFQDN)

	as.txtRecordsLock.Lock()
	if as.txtRecords == nil {
		as.txtRecords = make(map[string][]string)
	}
	as.txtRecords[fqdn] = append(as.txtRecords[fqdn], info.Value)
	as.txtRecordsLock.Unlock()

	return nil
}

func (as *acmeServer) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := normalizeFQDN(info.EffectiveFQDN)

	as.txtRecordsLock.Lock()
	if original, ok := as.txtRecords[fqdn]; ok {
		updated := original[:0]
		for _, v := range original {
			if v != info.Value {
				updated = append(updated, v)
			}
		}
		as.txtRecords[fqdn] = updated
	}
	if len(as.txtRecords[fqdn]) == 0 {
		delete(as.txtRecords, fqdn)
	}
	as.txtRecordsLock.Unlock()

	return nil
}

func (as *acmeServer) Close() {
	as.listener.Close()
	as.dnsListener.Close()
}
