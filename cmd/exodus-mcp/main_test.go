package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

type responseRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
}

func TestHealth(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://example.test/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &responseRecorder{header: make(http.Header)}

	health(recorder, request)

	if recorder.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.status, http.StatusOK)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}
	if !strings.Contains(recorder.body.String(), `"status":"scaffold"`) {
		t.Fatalf("body = %s, want scaffold status", recorder.body.String())
	}
}
