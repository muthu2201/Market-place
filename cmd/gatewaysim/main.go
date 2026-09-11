// Command gatewaysim runs the Razorpay-protocol gateway simulator as a
// standalone process, for the end-to-end and load suites.
//
// It is a test double at the network boundary. Production code cannot reach it:
// cmd/archcheck refuses any non-test file that imports the simulator package,
// and the payment adapters refuse a non-https base URL unless a test explicitly
// opts in to a loopback host.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/muthu2201/market-place/internal/testsupport/gatewaysim"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	keyID := flag.String("key-id", gatewaysim.DefaultConfig().KeyID, "expected API key id")
	keySecret := flag.String("key-secret", gatewaysim.DefaultConfig().KeySecret, "API key secret used for checkout signatures")
	webhookSecret := flag.String("webhook-secret", gatewaysim.DefaultConfig().WebhookSecret, "secret used to sign webhooks")
	portFile := flag.String("port-file", "", "write the bound address to this file")
	latency := flag.Duration("latency", 0, "artificial per-call latency")
	flag.Parse()

	handler := gatewaysim.New(gatewaysim.Config{
		KeyID: *keyID, KeySecret: *keySecret, WebhookSecret: *webhookSecret, Latency: *latency,
	})
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("gatewaysim: listen: %v", err)
	}
	if *portFile != "" {
		if err := os.WriteFile(*portFile, []byte(ln.Addr().String()), 0o600); err != nil {
			log.Fatalf("gatewaysim: write port file: %v", err)
		}
	}
	fmt.Printf("gatewaysim listening on http://%s\n", ln.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("gatewaysim: serve: %v", err)
	}
}
