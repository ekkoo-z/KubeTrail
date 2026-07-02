package kube

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"

	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

type PFCallbacks struct {
	OnReady func(localPort int)
	OnError func(error)
	OnLog   func(string)
}

type PFSession struct {
	LocalPort int
	PodPort   int
	stop      chan struct{}
	done      chan struct{}
	mu        sync.Mutex
	closed    bool
}

func (s *PFSession) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.stop)
}

func (s *PFSession) Done() <-chan struct{} { return s.done }

func (c *Client) StartPortForward(_ context.Context, ns, pod string, localPort, podPort int, cb PFCallbacks) (*PFSession, error) {
	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ns).Name(pod).SubResource("portforward")
	transport, upgrader, err := spdy.RoundTripperFor(c.Config)
	if err != nil {
		return nil, fmt.Errorf("spdy roundtripper: %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", req.URL())
	stopCh := make(chan struct{})
	readyCh := make(chan struct{})
	var outBuf, errBuf bytes.Buffer
	ports := []string{fmt.Sprintf("%d:%d", localPort, podPort)}
	fw, err := portforward.New(dialer, ports, stopCh, readyCh, &outBuf, &errBuf)
	if err != nil {
		return nil, fmt.Errorf("portforward new: %w", err)
	}
	sess := &PFSession{
		LocalPort: localPort,
		PodPort:   podPort,
		stop:      stopCh,
		done:      make(chan struct{}),
	}
	go func() {
		defer close(sess.done)
		err := fw.ForwardPorts()
		if err != nil && cb.OnError != nil {
			cb.OnError(err)
		}
		if cb.OnLog != nil {
			if outBuf.Len() > 0 {
				cb.OnLog(outBuf.String())
			}
			if errBuf.Len() > 0 {
				cb.OnLog(errBuf.String())
			}
		}
	}()
	go func() {
		<-readyCh
		actual, perr := fw.GetPorts()
		if perr == nil && len(actual) > 0 {
			sess.LocalPort = int(actual[0].Local)
		}
		if cb.OnReady != nil {
			cb.OnReady(sess.LocalPort)
		}
	}()
	return sess, nil
}
