package kube

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func newExecutor(cfg *rest.Config, u *url.URL) (remotecommand.Executor, error) {
	exec, err := remotecommand.NewSPDYExecutor(cfg, "POST", u)
	if err != nil {
		return nil, fmt.Errorf("spdy executor: %w", err)
	}
	return exec, nil
}

type ExecCallbacks struct {
	OnData func([]byte)
	OnExit func(error)
}

type ExecSession struct {
	stdin  chan []byte
	sizes  chan remotecommand.TerminalSize
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	closed bool
}

func (s *ExecSession) Write(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	b := make([]byte, len(data))
	copy(b, data)
	select {
	case s.stdin <- b:
	default:
		go func() { s.stdin <- b }()
	}
}

func (s *ExecSession) Resize(cols, rows uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if cols == 0 || rows == 0 {
		return
	}
	size := remotecommand.TerminalSize{Width: cols, Height: rows}
	for {
		select {
		case <-s.sizes:
		default:
			select {
			case s.sizes <- size:
			default:
			}
			return
		}
	}
}

func (s *ExecSession) Stop() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.cancel()
}

func (s *ExecSession) Done() <-chan struct{} { return s.done }

func (c *Client) StartExec(parent context.Context, ns, pod, container string, cmd []string, tty bool, cb ExecCallbacks) (*ExecSession, error) {
	opts := &corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdin:     true,
		Stdout:    true,
		Stderr:    !tty,
		TTY:       tty,
	}
	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ns).Name(pod).SubResource("exec").
		VersionedParams(opts, scheme.ParameterCodec)
	exec, err := newExecutor(c.Config, req.URL())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	sess := &ExecSession{
		stdin:  make(chan []byte, 32),
		sizes:  make(chan remotecommand.TerminalSize, 4),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	stdinR := &chanReader{ch: sess.stdin, ctx: ctx}
	stdoutW := &cbWriter{fn: cb.OnData}
	streamOpts := remotecommand.StreamOptions{
		Stdin:  stdinR,
		Stdout: stdoutW,
		Tty:    tty,
	}
	if !tty {
		streamOpts.Stderr = stdoutW
	}
	if tty {
		streamOpts.TerminalSizeQueue = &chanSizeQueue{ch: sess.sizes, ctx: ctx}
	}
	go func() {
		err := exec.StreamWithContext(ctx, streamOpts)
		if cb.OnExit != nil {
			cb.OnExit(err)
		}
		close(sess.done)
	}()
	return sess, nil
}

func (c *Client) ExecSimple(ctx context.Context, ns, pod, container string, cmd []string) (stdout, stderr []byte, err error) {
	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ns).Name(pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)
	exec, err := newExecutor(c.Config, req.URL())
	if err != nil {
		return nil, nil, err
	}
	var outBuf, errBuf bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &outBuf,
		Stderr: &errBuf,
	})
	return outBuf.Bytes(), errBuf.Bytes(), err
}

func (c *Client) execWithStdin(ctx context.Context, ns, pod, container string, cmd []string, stdin io.Reader, stdout, stderr io.Writer) error {
	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ns).Name(pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   cmd,
			Stdin:     stdin != nil,
			Stdout:    stdout != nil,
			Stderr:    stderr != nil,
		}, scheme.ParameterCodec)
	exec, err := newExecutor(c.Config, req.URL())
	if err != nil {
		return err
	}
	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})
}

type chanReader struct {
	ch  chan []byte
	buf []byte
	ctx context.Context
}

func (r *chanReader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		select {
		case b, ok := <-r.ch:
			if !ok {
				return 0, io.EOF
			}
			r.buf = b
		case <-r.ctx.Done():
			return 0, io.EOF
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

type cbWriter struct {
	fn func([]byte)
	mu sync.Mutex
}

func (w *cbWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fn != nil {
		b := make([]byte, len(p))
		copy(b, p)
		w.fn(b)
	}
	return len(p), nil
}

type chanSizeQueue struct {
	ch  chan remotecommand.TerminalSize
	ctx context.Context
}

func (q *chanSizeQueue) Next() *remotecommand.TerminalSize {
	select {
	case s := <-q.ch:
		return &s
	case <-q.ctx.Done():
		return nil
	}
}
