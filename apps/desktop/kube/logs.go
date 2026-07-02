package kube

import (
	"bufio"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type LogsCallbacks struct {
	OnLine func(string)
	OnEnd  func(error)
}

type LogSession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *LogSession) Stop()                 { s.cancel() }
func (s *LogSession) Done() <-chan struct{} { return s.done }

func (c *Client) StartLogs(parent context.Context, ns, pod, container string, follow bool, tail int64, sinceSeconds int64, cb LogsCallbacks) (*LogSession, error) {
	opts := &corev1.PodLogOptions{
		Container:  container,
		Follow:     follow,
		Timestamps: false,
	}
	if tail > 0 {
		opts.TailLines = &tail
	}
	if sinceSeconds > 0 {
		opts.SinceSeconds = &sinceSeconds
	}
	req := c.Clientset.CoreV1().Pods(ns).GetLogs(pod, opts)
	ctx, cancel := context.WithCancel(parent)
	stream, err := req.Stream(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open log stream: %w", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer stream.Close()
		scanner := bufio.NewScanner(stream)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			if cb.OnLine != nil {
				cb.OnLine(scanner.Text())
			}
		}
		if cb.OnEnd != nil {
			cb.OnEnd(scanner.Err())
		}
	}()
	return &LogSession{cancel: cancel, done: done}, nil
}
