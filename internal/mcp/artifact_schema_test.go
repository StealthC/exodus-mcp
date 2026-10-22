package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// ----------------------------------------------------------------------------------------------------------------------
// Artifact schema-version declaration (roadmap issue #18)
//
// Every JSON artifact kind declares the schema_version its payload embeds, and
// every JSON write goes through the declaration. These tests are the
// enforcement half of the table documented in docs/ARTIFACTS.md.
// ----------------------------------------------------------------------------------------------------------------------

// artifactSchemaVersionDeviations lists kinds whose version string intentionally
// does not follow "<kind>/<n>" because the value predates this declaration and
// is already pinned by consumers.
var artifactSchemaVersionDeviations = map[string]string{
	"system-snapshot-manifest": "system-snapshot/1",
	"system-render-manifest":   "render-manifest/1",
}

func TestEveryJSONArtifactKindDeclaresSchemaVersion(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	seen := map[string]string{}
	for kind, declared := range artifactSchemaVersions {
		if declared == "" {
			t.Errorf("kind %q declares an empty schema_version", kind)
			continue
		}
		if previous, duplicate := seen[declared]; duplicate {
			t.Errorf("kinds %q and %q declare the same schema_version %q; a consumer could not tell them apart", previous, kind, declared)
		}
		seen[declared] = kind

		expected, deviates := artifactSchemaVersionDeviations[kind]
		if deviates {
			if declared != expected {
				t.Errorf("kind %q declares %q, expected the documented %q", kind, declared, expected)
			}
		} else if !strings.HasPrefix(declared, kind+"/") {
			t.Errorf("kind %q declares %q; the value must start with %q", kind, declared, kind+"/")
		}
		if _, err := strconv.Atoi(declared[strings.LastIndex(declared, "/")+1:]); err != nil {
			t.Errorf("kind %q declares %q without a trailing revision number", kind, declared)
		}

		// The single write path stamps the declared value, so no producer needs
		// to restate it (and none can disagree with this table).
		document := map[string]any{"kind": kind}
		stored, err := putJSONArtifact(server, "ctx_schema", kind, document, nil)
		if err != nil {
			t.Fatalf("kind %q: putJSONArtifact: %v", kind, err)
		}
		if stored.SchemaVersion != declared {
			t.Errorf("kind %q stored schema_version %q, declared %q", kind, stored.SchemaVersion, declared)
		}
		if document["schema_version"] != declared {
			t.Errorf("kind %q payload carries %v, declared %q", kind, document["schema_version"], declared)
		}
	}
}

func TestJSONArtifactRejectsUnregisteredKind(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	if _, err := putJSONArtifact(server, "ctx_schema", "undeclared-kind", map[string]any{}, nil); err == nil {
		t.Fatal("a JSON artifact kind without a declared schema_version must be refused")
	}
}

// TestJSONArtifactWritesGoThroughTheSchemaDeclaration is the structural half:
// the mcp package must not write a JSON artifact directly, because a direct call
// could publish a document with no (or a wrong) schema_version. The only
// allow-listed caller is the declaration file itself; runAnnotationExport writes
// a typed document whose version field is the same declared constant.
func TestJSONArtifactWritesGoThroughTheSchemaDeclaration(t *testing.T) {
	allowed := map[string]bool{"putJSONArtifact": true, "runAnnotationExport": true}
	files, err := parser.ParseDir(token.NewFileSet(), ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	found := 0
	for _, pkg := range files {
		for name, file := range pkg.Files {
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || selector.Sel.Name != "PutWithProvenance" {
						return true
					}
					if !hasJSONLiteralArgument(call) {
						return true
					}
					found++
					if !allowed[function.Name.Name] {
						t.Errorf("%s: %s writes a JSON artifact directly; route it through putJSONArtifact so the declared schema_version is stamped",
							name, function.Name.Name)
					}
					return true
				})
			}
		}
	}
	if found == 0 {
		t.Fatal("the scan found no JSON PutWithProvenance call; the invariant is no longer being checked")
	}
}

// hasJSONLiteralArgument reports whether one call passes the JSON media type as
// a literal, which is how every document producer names it.
func hasJSONLiteralArgument(call *ast.CallExpr) bool {
	for _, argument := range call.Args {
		literal, ok := argument.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(literal.Value)
		if err == nil && (value == "application/json" || value == "application/json; charset=utf-8") {
			return true
		}
	}
	return false
}

// TestPaletteJSONArtifactCarriesSchemaVersion drives one derived JSON export end
// to end and reads the declaration back through artifact_list, which is the
// discovery path a client uses.
func TestPaletteJSONArtifactCarriesSchemaVersion(t *testing.T) {
	server := newTestServer(t, paletteBridge())
	content := structured(postToolCall(t, server, "vdp_palette_export", "{}"))
	if content["code"] != nil {
		t.Fatalf("vdp_palette_export failed: %v", content)
	}
	listed := structured(postToolCall(t, server, "artifact_list", `{"kind":"vdp-palette-json"}`))
	artifacts, _ := listed["artifacts"].([]any)
	if len(artifacts) != 1 {
		t.Fatalf("expected one vdp-palette-json artifact: %v", listed)
	}
	descriptor := artifacts[0].(map[string]any)
	if descriptor["schema_version"] != schemaVDPPaletteJSON {
		t.Fatalf("vdp-palette-json schema_version = %v, want %q", descriptor["schema_version"], schemaVDPPaletteJSON)
	}
}

// TestSystemSnapshotJSONArtifactsCarrySchemaVersion covers the four register,
// status, render, and manifest documents one snapshot writes.
func TestSystemSnapshotJSONArtifactsCarrySchemaVersion(t *testing.T) {
	server := newTestServer(t, systemSnapshotBridge())
	server.runState.observe(server, false, nil)
	content := structured(postToolCall(t, server, "system_snapshot_capture",
		`{"memory_ranges":[{"name":"ram0","space":"mem-ram","address":"0xFF0000","length":8}],"include_frame":false}`))
	if content["code"] != nil {
		t.Fatalf("system_snapshot_capture failed: %v", content)
	}
	for _, kind := range []string{
		"system-m68k-registers",
		"system-z80-registers",
		"system-vdp-status",
		"system-render-manifest",
		"system-snapshot-manifest",
	} {
		listed := structured(postToolCall(t, server, "artifact_list", `{"kind":"`+kind+`"}`))
		artifacts, _ := listed["artifacts"].([]any)
		if len(artifacts) != 1 {
			t.Fatalf("kind %q: expected one artifact, got %v", kind, listed)
		}
		descriptor := artifacts[0].(map[string]any)
		declared, present := artifactSchemaVersions[kind]
		if !present {
			t.Fatalf("kind %q is not declared", kind)
		}
		if descriptor["schema_version"] != declared {
			t.Fatalf("kind %q schema_version = %v, want %q", kind, descriptor["schema_version"], declared)
		}
	}
}

// TestArtifactIndexSurvivesStoreReopen covers the persistence the artifact
// index promises: a reopened store serves the bytes and the declared version of
// what an earlier session wrote.
func TestArtifactIndexSurvivesStoreReopen(t *testing.T) {
	dir := t.TempDir()
	first, err := artifact.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := first.PutWithProvenance("ctx_persist", "memory-search-results", "application/json", []byte(`{"schema_version":"memory-search-results/1","kind":"memory-search-results"}`), &artifact.Provenance{Kind: "memory-search-results"})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := artifact.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := reopened.Metadata(stored.ID, "ctx_persist")
	if err != nil {
		t.Fatalf("reopened store lost the artifact: %v", err)
	}
	if metadata.SchemaVersion != schemaMemorySearchResults {
		t.Fatalf("schema_version = %q after reopen, want %q", metadata.SchemaVersion, schemaMemorySearchResults)
	}
	data, _, err := reopened.Bytes(stored.ID, "ctx_persist")
	if err != nil || len(data) == 0 {
		t.Fatalf("reopened store cannot serve the bytes: %v", err)
	}
	if _, err := reopened.Metadata(stored.ID, "ctx_other"); err == nil {
		t.Fatal("the reopened index must keep the artifact context-scoped")
	}
}

// paletteBridge answers the CRAM read vdp_palette_export needs.
func paletteBridge() *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "vdp_mem_read" {
			return json.RawMessage(`{}`), nil
		}
		cram := make([]byte, 128)
		cram[2] = 0x02
		return json.RawMessage(`{"target":"cram","address_space":"315-5313 CRAM","address":0,"length":128,"buffer_size":128,"entry_size":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","data":"` + base64.StdEncoding.EncodeToString(cram) + `"}`), nil
	}
	return client
}
