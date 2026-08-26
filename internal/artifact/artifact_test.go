package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestPutGetRoundtrip(t *testing.T) {
	store := newTestStore(t)
	data := []byte("m68k memory bytes")
	stored, err := store.Put("ctx_a", "memory-dump", "application/octet-stream", data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored.ID, "art_") || stored.SizeBytes != int64(len(data)) {
		t.Fatalf("descriptor wrong: %+v", stored)
	}
	sum := sha256.Sum256(data)
	if stored.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha mismatch: %s", stored.SHA256)
	}
	got, meta, err := store.Bytes(stored.ID, "ctx_a")
	if err != nil || string(got) != string(data) || meta.ID != stored.ID {
		t.Fatalf("roundtrip failed: %v %v", err, meta)
	}
}

func TestContextScoping(t *testing.T) {
	store := newTestStore(t)
	stored, err := store.Put("ctx_a", "memory-dump", "application/octet-stream", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Bytes(stored.ID, "ctx_other"); err == nil {
		t.Fatal("cross-context access must fail")
	}
	if _, err := store.Metadata(stored.ID, "ctx_other"); err == nil {
		t.Fatal("cross-context metadata must fail")
	}
	if _, _, err := store.Bytes("art_invalid", "ctx_a"); err == nil {
		t.Fatal("malformed id must fail")
	}
}

func TestPreviewCapsAndModes(t *testing.T) {
	store := newTestStore(t)
	stored, _ := store.Put("ctx_a", "cpu-trace", "text/plain; charset=utf-8", []byte("trace line\nsecond line"))
	if _, err := store.Preview(stored.ID, "ctx_a", 0, maxPreviewBytes+1, "hex"); err == nil {
		t.Fatal("preview over cap must be rejected")
	}
	hexPreview, err := store.Preview(stored.ID, "ctx_a", 0, 16, "hex")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hexPreview["hex"].(string), "74 72 61") {
		t.Fatalf("hex preview malformed: %v", hexPreview)
	}
	textPreview, _ := store.Preview(stored.ID, "ctx_a", 6, 4, "text")
	if textPreview["text"] != "line" {
		t.Fatalf("text offset wrong: %v", textPreview)
	}
	base64Preview, _ := store.Preview(stored.ID, "ctx_a", 0, 5, "base64")
	if base64Preview["data_base64"] != "dHJhY2U=" {
		t.Fatalf("base64 wrong: %v", base64Preview)
	}
}

func TestSanitizeTextReplacesControlBytes(t *testing.T) {
	sanitized := sanitizeText([]byte{'a', 0x01, 'b', 0xFF, 'c'})
	if strings.ContainsAny(sanitized, "\x01") {
		t.Fatalf("control byte leaked: %q", sanitized)
	}
}

func TestExpireOlderThanRemovesOnlyExpired(t *testing.T) {
	store := newTestStore(t)
	fresh, err := store.Put("ctx_a", "memory-dump", "application/octet-stream", []byte("fresh"))
	if err != nil {
		t.Fatal(err)
	}
	stale, err := store.Put("ctx_a", "memory-dump", "application/octet-stream", []byte("stale"))
	if err != nil {
		t.Fatal(err)
	}
	// Backdate one artifact past the TTL; the other stays current.
	store.mu.Lock()
	backdated := store.artifacts[stale.ID]
	backdated.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	store.artifacts[stale.ID] = backdated
	store.mu.Unlock()

	removed, err := store.ExpireOlderThan(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("ExpireOlderThan removed %d, want 1", removed)
	}
	if _, _, err := store.Bytes(stale.ID, "ctx_a"); err == nil {
		t.Fatal("expired artifact must no longer resolve")
	}
	if _, err := os.Stat(store.path(stale.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired artifact file must be deleted, stat err = %v", err)
	}
	if _, _, err := store.Bytes(fresh.ID, "ctx_a"); err != nil {
		t.Fatalf("fresh artifact must survive: %v", err)
	}

	// A non-positive TTL disables expiry entirely.
	removed, err = store.ExpireOlderThan(0)
	if err != nil || removed != 0 {
		t.Fatalf("disabled expiry must be a no-op: removed=%d err=%v", removed, err)
	}
}

func TestHandlerFullAndRangeRequests(t *testing.T) {
	store := newTestStore(t)
	stored, _ := store.Put("ctx_c", "memory-dump", "application/octet-stream", []byte("0123456789"))

	server := httptest.NewServer(store.Handler())
	defer server.Close()

	full, err := server.Client().Get(server.URL + "/artifacts/" + stored.ID + "?context=ctx_c")
	if err != nil {
		t.Fatal(err)
	}
	defer full.Body.Close()
	body, _ := io.ReadAll(full.Body)
	if full.StatusCode != 200 || string(body) != "0123456789" {
		t.Fatalf("full fetch failed: %d %q", full.StatusCode, body)
	}
	if full.Header.Get("ETag") != `"sha256-`+stored.SHA256+`"` || full.Header.Get("Accept-Ranges") != "bytes" {
		t.Fatalf("headers missing: %v", full.Header)
	}

	request, _ := httpNewRequest("GET", server.URL+"/artifacts/"+stored.ID+"?context=ctx_c")
	request.Header.Set("Range", "bytes=2-5")
	partial, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer partial.Body.Close()
	partialBody, _ := io.ReadAll(partial.Body)
	if partial.StatusCode != 206 || string(partialBody) != "2345" {
		t.Fatalf("range failed: %d %q", partial.StatusCode, partialBody)
	}

	notFound, _ := server.Client().Get(server.URL + "/artifacts/art_unknown?context=ctx_c")
	if notFound.StatusCode != 404 {
		t.Fatalf("unknown artifact must 404: %d", notFound.StatusCode)
	}
}

func TestStartupSweepRemovesStaleFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "art_stalecontent000")
	if err := os.WriteFile(stale, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale artifact survived startup sweep")
	}
}

func TestPutWithoutProvenanceReportsUnknownState(t *testing.T) {
	store := newTestStore(t)
	stored, err := store.Put("ctx_a", "memory-dump", "application/octet-stream", []byte("legacy bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Provenance != nil {
		t.Fatalf("legacy artifact must carry nil provenance: %+v", stored.Provenance)
	}
	if stored.Provenance.Known() {
		t.Fatal("nil provenance must not count as known")
	}
	if _, ok := stored.Provenance.CapturedStart(); ok {
		t.Fatal("nil provenance must not claim a start address")
	}
}

func TestPutWithProvenanceStampsSchemaAndState(t *testing.T) {
	store := newTestStore(t)
	start := uint64(0xFF0000)
	length := uint64(16)
	generation := uint64(7)
	frame := uint64(42)
	provenance := &Provenance{
		Kind:                "memory-dump",
		AddressSpace:        "mem-ram",
		StartAddress:        &start,
		EffectiveAddress:    &start,
		StartAddressHex:     "0xFF0000",
		EffectiveAddressHex: "0xFF0000",
		ByteLength:          &length,
		RawByteOrdering:     "address-order",
		ByteOrder:           "big-endian",
		SpaceKind:           "memory",
		Device:              "68000 work RAM",
		TargetGeneration:    &generation,
		ROMSHA256:           "abc123",
		ROMPath:             "F:\\roms\\kid.bin",
		FrameToken:          &frame,
		CPURunState:         "running",
		Consistency:         "live",
		CapturedAt:          time.Now().UTC().Add(-time.Minute),
	}
	stored, err := store.PutWithProvenance("ctx_a", "memory-dump", "application/octet-stream", []byte("bytes"), provenance)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Provenance == nil {
		t.Fatal("provenance lost on store")
	}
	if stored.Provenance.Schema != ProvenanceSchema || stored.Provenance.State != ProvenanceStateComplete {
		t.Fatalf("envelope not stamped: %+v", stored.Provenance)
	}
	if !stored.Provenance.Known() {
		t.Fatal("complete envelope must be known")
	}
	if captured, ok := stored.Provenance.CapturedStart(); !ok || captured != 0xFF0000 {
		t.Fatalf("captured start wrong: %d %v", captured, ok)
	}
	if length, ok := stored.Provenance.CapturedLength(); !ok || length != 16 {
		t.Fatalf("captured length wrong: %d %v", length, ok)
	}
	if !stored.Provenance.CapturedAt.Equal(provenance.CapturedAt) {
		t.Fatalf("captured_at must be preserved: %v", stored.Provenance.CapturedAt)
	}
	// Metadata and Bytes return the same immutable envelope.
	meta, err := store.Metadata(stored.ID, "ctx_a")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Provenance == nil || meta.Provenance.ROMSHA256 != "abc123" {
		t.Fatalf("metadata provenance wrong: %+v", meta.Provenance)
	}
}

func TestPutWithNilProvenanceIsUnknown(t *testing.T) {
	store := newTestStore(t)
	stored, err := store.PutWithProvenance("ctx_a", "memory-dump", "application/octet-stream", []byte("bytes"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Provenance != nil {
		t.Fatalf("nil provenance must stay nil: %+v", stored.Provenance)
	}
}

func httpNewRequest(method, url string) (*http.Request, error) {
	return http.NewRequest(method, url, nil)
}
