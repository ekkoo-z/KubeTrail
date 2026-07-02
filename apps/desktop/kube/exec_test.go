package kube

import (
	"testing"

	"k8s.io/client-go/tools/remotecommand"
)

func TestExecSessionResizeKeepsLatestSize(t *testing.T) {
	s := &ExecSession{sizes: make(chan remotecommand.TerminalSize, 4)}

	s.Resize(80, 24)
	s.Resize(120, 40)

	got := <-s.sizes
	if got.Width != 120 || got.Height != 40 {
		t.Fatalf("expected latest size 120x40, got %dx%d", got.Width, got.Height)
	}
	select {
	case extra := <-s.sizes:
		t.Fatalf("expected one queued resize, got extra %dx%d", extra.Width, extra.Height)
	default:
	}
}

func TestExecSessionResizeIgnoresZeroSize(t *testing.T) {
	s := &ExecSession{sizes: make(chan remotecommand.TerminalSize, 4)}

	s.Resize(0, 24)
	s.Resize(80, 0)

	select {
	case got := <-s.sizes:
		t.Fatalf("expected zero sizes to be ignored, got %dx%d", got.Width, got.Height)
	default:
	}
}
