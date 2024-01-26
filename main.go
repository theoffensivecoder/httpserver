package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/4armed/httpserver/pkg/certs/selfsigned"
	"github.com/caddyserver/certmagic"
)

var (
	hostname = flag.String("hostname", "localhost.localdomain", "Hostname for HTTP server")
	useAcme  = flag.Bool("acme", false, "Use ACME to get TLS certificate")
	email    = flag.String("email", "httpserver@4armed.com", "Email address for certificate")
	useTLS   = flag.Bool("tls", false, "Use TLS")
	// flag.StringVar(&o.PrivateKeyFile, "private-key-file", "server.key", "Private key file")
	// flag.StringVar(&o.CertFile, "cert-file", "server.crt", "Certificate file")
	listenAddr   = flag.String("listen-addr", "127.0.0.1:8081", "Listen address")
	useDodgyCors = flag.Bool("dodgy-cors", false, "Enable dodgy CORS")
	staticDir    = flag.String("static-dir", ".", "Serve static files from this directory")
	quiet        = flag.Bool("quiet", false, "Quiet mode")
)

func main() {
	flag.Parse()

	mux := http.NewServeMux()
	mux.Handle("/", loggingMiddleware(dodgyCorsMiddleware(http.FileServer(http.Dir(*staticDir)))))

	if *useTLS {
		if *useAcme {
			err := certmagic.HTTPS(([]string{*hostname}), mux)
			if err != nil {
				panic(err)
			}
		} else {
			tlsCert, err := selfsigned.New(*hostname, *email)
			if err != nil {
				panic(err)
			}

			config := &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			}

			ln, err := net.Listen("tcp", *listenAddr)
			if err != nil {
				panic(err)
			}

			defer ln.Close()

			tlsListener := tls.NewListener(ln, config)

			if !*quiet {
				fmt.Printf("Listening on https://%s\n", *listenAddr)
			}
			err = http.Serve(tlsListener, mux)
			if err != nil {
				panic(err)
			}
		}
	} else {
		if !*quiet {
			fmt.Printf("Listening on http://%s\n", *listenAddr)
		}
		err := http.ListenAndServe(*listenAddr, mux)
		if err != nil {
			panic(err)
		}
	}
}

func dodgyCorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !*useDodgyCors {
			next.ServeHTTP(w, r)
			return
		}

		if r.Method == "OPTIONS" {
			w.Header().Add("Access-Control-Allow-Origin", "*")
			w.Header().Add("Access-Control-Allow-Credentials", "true")

			corsRequestHeaders := r.Header.Get("Access-Control-Request-Headers")
			if corsRequestHeaders != "" {
				w.Header().Add("Access-Control-Allow-Headers", corsRequestHeaders)
			}

			w.WriteHeader(http.StatusOK)
			return
		}

		originHeader := r.Header.Get("Origin")
		if originHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Add("Access-Control-Allow-Origin", originHeader)
		w.Header().Add("Access-Control-Allow-Credentials", "true")
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request received", "method", r.Method, "uri", r.URL, "remote_addr", r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}
