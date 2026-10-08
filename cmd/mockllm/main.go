// Command mockllm is a fake OpenAI-compatible backend for demos and tests.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/bredda/tavian/internal/mockllm"
)

func main() {
	addr := flag.String("addr", ":8000", "listen address")
	flag.Parse()
	srv := &http.Server{Addr: *addr, Handler: mockllm.Handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("mockllm listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
