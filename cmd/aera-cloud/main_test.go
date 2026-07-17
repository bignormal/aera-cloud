package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeStopsCleanlyAfterContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, listener, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}))
	}()

	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatalf("GET server error = %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		cancel()
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve() did not stop after context cancellation")
	}
}
