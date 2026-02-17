package bpfloader

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

func TestInitBPF(t *testing.T) {

	t.Log("Loading BPF")
	bpf := InitBPF()

	if err := bpf.Load(bpf.Objects, nil); err != nil {
		t.Fatal(err)
	}
	defer bpf.Objects.Close()

	// Wait for Ctrl+C / SIGTERM
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	t.Log("BPF loaded. Press Ctrl+C to exit test.")
	t.Log("run: bpftool prog show")
	<-ctx.Done()

	t.Log("Signal received, cleaning up")
}
