package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// slowServer writes chunks bytes, sleeping gap between each, then optionally
// hangs (without closing) for hang before returning.
func slowServer(t *testing.T, chunks int, gap, hang time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		for i := 0; i < chunks; i++ {
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(gap):
			}
		}
		if hang > 0 {
			select {
			case <-r.Context().Done():
			case <-time.After(hang):
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNewClientHasNoWholeRequestDeadline(t *testing.T) {
	c := NewClient()
	if c.Timeout != 0 {
		t.Fatalf("Client.Timeout = %s, want 0 (whole-request deadlines break large downloads)", c.Timeout)
	}
	if _, ok := c.Transport.(*stallTransport); !ok {
		t.Fatalf("client transport %T, want *stallTransport", c.Transport)
	}
	tr := Transport()
	if tr.ResponseHeaderTimeout != ResponseHeaderTimeout || tr.TLSHandshakeTimeout != TLSHandshakeTimeout {
		t.Fatalf("transport timeouts not applied: header=%s tls=%s", tr.ResponseHeaderTimeout, tr.TLSHandshakeTimeout)
	}
	if tr.Proxy == nil {
		t.Fatal("transport dropped proxy-from-environment")
	}
}

// A body that keeps delivering bytes must complete even though its total
// duration far exceeds the stall timeout.
func TestSteadyBodyOutlivesStallTimeout(t *testing.T) {
	const stall = 150 * time.Millisecond
	srv := slowServer(t, 12, 50*time.Millisecond, 0) // ~600ms total, 4x stall

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	start := time.Now()
	resp, err := NewClientWithStall(stall).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 12 {
		t.Fatalf("got %d bytes, want 12", len(body))
	}
	if elapsed := time.Since(start); elapsed < 3*stall {
		t.Fatalf("transfer took %s; test did not exercise a body longer than the stall timeout", elapsed)
	}
}

// A body that stops delivering bytes must fail with ErrStalled, promptly.
func TestStalledBodyFails(t *testing.T) {
	const stall = 150 * time.Millisecond
	srv := slowServer(t, 2, 10*time.Millisecond, 5*time.Second)

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := NewClientWithStall(stall).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	start := time.Now()
	_, err = io.ReadAll(resp.Body)
	if !errors.Is(err, ErrStalled) {
		t.Fatalf("err = %v, want ErrStalled", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stall detected after %s; want close to %s", elapsed, stall)
	}
}

// Closing the body early must stop the timer and not leak a cancellation
// error into a later, unrelated request.
func TestCloseStopsTimer(t *testing.T) {
	srv := slowServer(t, 1, 0, 0)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := NewClientWithStall(50 * time.Millisecond).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, ok := resp.Body.(*stallBody)
	if !ok {
		t.Fatalf("body type %T, want *stallBody", resp.Body)
	}
	if b.timer.Stop() {
		t.Fatal("timer still armed after Close")
	}
}

// redirectServer serves /redirect as a 302 to /final. With stallRedirect the
// 302 advertises a body (Content-Length: 100) and never sends it. /final
// streams finalChunks bytes, one per gap.
func redirectServer(t *testing.T, stallRedirect bool, finalChunks int, gap time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "/final")
			if stallRedirect {
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(http.StatusFound)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
				return
			}
			w.WriteHeader(http.StatusFound)
		case "/final":
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			for i := 0; i < finalChunks; i++ {
				if _, err := w.Write([]byte("y")); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
				select {
				case <-r.Context().Done():
					return
				case <-time.After(gap):
				}
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A redirect whose body never arrives must not hang: net/http drains
// redirect bodies inside Client.Do, so the stall guard has to apply per hop.
func TestStalledRedirectBodyIsBounded(t *testing.T) {
	const stall = 50 * time.Millisecond
	srv := redirectServer(t, true, 1, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/redirect", nil)
	start := time.Now()
	resp, err := NewClientWithStall(stall).Do(req)
	if err != nil {
		t.Fatalf("Do: %v (after %s)", err, time.Since(start))
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read final body: %v", err)
	}
	if string(body) != "y" {
		t.Fatalf("final body %q, want %q", body, "y")
	}
	if ctx.Err() != nil {
		t.Fatal("parent deadline hit; stalled redirect body was not bounded by the stall guard")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("redirect took %s; want close to the %s stall timeout", elapsed, stall)
	}
}

// When redirects are not followed, the caller reads the redirect body
// itself; a stalled one must fail with ErrStalled.
func TestStalledUnfollowedRedirectBodyFails(t *testing.T) {
	const stall = 50 * time.Millisecond
	srv := redirectServer(t, true, 0, 0)

	c := NewClientWithStall(stall)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/redirect", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	_, err = io.ReadAll(resp.Body)
	if !errors.Is(err, ErrStalled) {
		t.Fatalf("err = %v, want ErrStalled", err)
	}
}

// Control: a prompt redirect followed by a final body that streams for
// longer than the stall timeout, with steady progress, must succeed.
func TestProgressingRedirectedBodyCompletes(t *testing.T) {
	const stall = 150 * time.Millisecond
	srv := redirectServer(t, false, 12, 50*time.Millisecond)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/redirect", nil)
	start := time.Now()
	resp, err := NewClientWithStall(stall).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 12 {
		t.Fatalf("got %d bytes, want 12", len(body))
	}
	if elapsed := time.Since(start); elapsed < 3*stall {
		t.Fatalf("transfer took %s; control did not outlast the stall timeout", elapsed)
	}
}
