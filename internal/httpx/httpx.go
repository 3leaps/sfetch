// Package httpx holds sfetch's shared HTTP timeout policy.
//
// sfetch downloads release assets that range from a few KB to hundreds of MB.
// A whole-request deadline (http.Client.Timeout) also bounds reading the
// response body, so it fails large downloads on ordinary connections. This
// package instead bounds each phase that can hang without making progress:
//
//   - connection setup (dial + TLS handshake),
//   - waiting for response headers on every request and redirect hop,
//   - body streaming, via an idle timeout that resets whenever bytes arrive.
//
// A transfer that keeps making progress is never cut off; one that stops
// receiving data fails with ErrStalled.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// DialTimeout bounds establishing the TCP connection.
	DialTimeout = 30 * time.Second
	// TLSHandshakeTimeout bounds the TLS handshake.
	TLSHandshakeTimeout = 30 * time.Second
	// ResponseHeaderTimeout bounds waiting for response headers after the
	// request is written. Applies to each redirect hop.
	ResponseHeaderTimeout = 30 * time.Second
	// StallTimeout is the longest the response body may go without
	// delivering any bytes before the request is cancelled.
	StallTimeout = 60 * time.Second
)

// ErrStalled reports that a response body stopped delivering data for longer
// than the stall timeout.
var ErrStalled = errors.New("download stalled")

var (
	transportOnce sync.Once
	transport     *http.Transport
)

// Transport returns the shared transport configured with sfetch's connection
// and header timeouts. It preserves the default transport's proxy and
// HTTP/2 behavior.
func Transport() *http.Transport {
	transportOnce.Do(func() {
		base, ok := http.DefaultTransport.(*http.Transport)
		if ok {
			transport = base.Clone()
		} else {
			transport = &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}
		}
		dialer := &net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}
		transport.DialContext = dialer.DialContext
		transport.TLSHandshakeTimeout = TLSHandshakeTimeout
		transport.ResponseHeaderTimeout = ResponseHeaderTimeout
	})
	return transport
}

// NewClient returns a client with no whole-request deadline whose every
// response body, on every hop, is guarded by StallTimeout.
func NewClient() *http.Client {
	return NewClientWithStall(StallTimeout)
}

// NewClientWithStall is NewClient with an explicit stall timeout (tests).
func NewClientWithStall(stall time.Duration) *http.Client {
	return &http.Client{Transport: &stallTransport{base: Transport(), stall: stall}}
}

// Do sends req with client. Kept as the single send point for sfetch
// requests; body stall protection comes from the client's transport.
func Do(client *http.Client, req *http.Request) (*http.Response, error) {
	return client.Do(req) // #nosec G704 -- SDR-007: caller-chosen URL; callers enforce scheme/redirect/auth policy
}

// stallTransport guards each response body it returns with an idle-stall
// timeout. It works per round trip, so redirect responses whose bodies
// net/http drains internally are bounded as well as the final response.
type stallTransport struct {
	base  http.RoundTripper
	stall time.Duration
}

func (t *stallTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(req.Context())
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel(nil)
		return nil, err
	}
	resp.Body = newStallBody(ctx, resp.Body, t.stall, cancel)
	return resp, nil
}

type stallBody struct {
	ctx    context.Context
	rc     io.ReadCloser
	stall  time.Duration
	timer  *time.Timer
	cancel context.CancelCauseFunc
}

func newStallBody(ctx context.Context, rc io.ReadCloser, stall time.Duration, cancel context.CancelCauseFunc) *stallBody {
	b := &stallBody{ctx: ctx, rc: rc, stall: stall, cancel: cancel}
	b.timer = time.AfterFunc(stall, func() {
		cancel(fmt.Errorf("%w: no data received for %s", ErrStalled, stall))
	})
	return b
}

func (b *stallBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.timer.Reset(b.stall)
	}
	if err != nil && err != io.EOF {
		if cause := context.Cause(b.ctx); cause != nil && errors.Is(cause, ErrStalled) {
			return n, cause
		}
	}
	return n, err
}

func (b *stallBody) Close() error {
	b.timer.Stop()
	err := b.rc.Close()
	b.cancel(nil)
	return err
}
