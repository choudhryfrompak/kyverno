package dclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// RawAbsPath's real implementation (RawAbsPath) used client-go's
// rest.Request.DoRaw, which buffers the entire upstream response body into
// memory with no size limit of its own. RawAbsPath is reachable with an
// arbitrary path, including Pod/Service ".../proxy" subresources that proxy
// to a backend outside the caller's control, so a large or attacker-sized
// proxied response could make the calling process buffer an unbounded
// amount of data in memory.
func newTestRESTClient(t *testing.T, srv *httptest.Server) rest.Interface {
	t.Helper()
	cfg := &rest.Config{
		Host: srv.URL,
		ContentConfig: rest.ContentConfig{
			NegotiatedSerializer: serializer.NewCodecFactory(scheme.Scheme).WithoutConversion(),
			GroupVersion:         &scheme.Scheme.PrioritizedVersionsAllGroups()[0],
		},
	}
	rc, err := rest.RESTClientFor(cfg)
	if err != nil {
		t.Fatalf("failed to build REST client: %v", err)
	}
	return rc
}

func TestRawAbsPathRejectsOversizedResponse(t *testing.T) {
	const oversizeLen = 50 * 1000 * 1000 // 50MB, far above the 10MiB cap
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 1<<16)
		written := 0
		for written < oversizeLen {
			n := len(buf)
			if written+n > oversizeLen {
				n = oversizeLen - written
			}
			w.Write(buf[:n])
			written += n
		}
	}))
	defer srv.Close()

	c := &client{rest: newTestRESTClient(t, srv)}

	body, err := c.RawAbsPath(context.Background(), "/api/v1/namespaces/victim-ns/services/attacker-svc:80/proxy/", "GET", nil)
	if err == nil {
		t.Fatalf("expected an error for a %d-byte response exceeding the cap, got %d bytes with no error", oversizeLen, len(body))
	}
	t.Logf("CONFIRMED: oversized response correctly rejected: %v", err)
}

func TestRawAbsPathAllowsReasonableResponse(t *testing.T) {
	const reasonableLen = 1024 // well within the 10MiB cap
	payload := make([]byte, reasonableLen)
	for i := range payload {
		payload[i] = 'A'
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
	}))
	defer srv.Close()

	c := &client{rest: newTestRESTClient(t, srv)}

	body, err := c.RawAbsPath(context.Background(), "/api/v1/namespaces/default/pods/x/proxy/", "GET", nil)
	if err != nil {
		t.Fatalf("expected a reasonable response to succeed, got error: %v", err)
	}
	if len(body) != reasonableLen {
		t.Fatalf("expected %d bytes, got %d", reasonableLen, len(body))
	}
}
