package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
	"github.com/StealthC/exodus-mcp/internal/experiment"
)

// This file is the single declaration of the schema_version each JSON artifact
// kind embeds in its own payload (not the tool-response schema, and not the
// artifact-provenance envelope). A consumer of an artifact can therefore detect
// a shape change by comparing the version it was written against; a future
// revision is a new value, never a silent shape change.
//
// Every JSON document producer writes through putJSONArtifact, which stamps the
// declared value and refuses a kind that is not registered here. Raw byte,
// image, and text artifacts have no embedded header of our own and are out of
// scope; application/jsonl artifacts carry a per-line schema instead.

const (
	schemaMemorySearchResults = "memory-search-results/1"
	schemaMemoryDiffResults   = "memory-diff-results/1"
	schemaExperimentManifest  = experiment.ManifestSchema
	schemaStateDiffResults    = "state-diff-results/1"
	schemaCaptureManifest     = "capture-manifest/1"
	schemaVDPCaptureManifest  = "vdp-capture-manifest/1"
	schemaVDPRenderManifest   = "vdp-render-manifest/1"
	schemaVDPStatus           = "vdp-status/1"
	schemaVDPPaletteJSON      = "vdp-palette-json/1"
	schemaVDPTilesJSON        = "vdp-tiles-json/1"
	schemaVDPPlaneJSON        = "vdp-plane-json/1"
	schemaSystemM68KRegisters = "system-m68k-registers/1"
	schemaSystemZ80Registers  = "system-z80-registers/1"
	schemaSystemVDPStatus     = "system-vdp-status/1"
)

// artifactSchemaVersions maps every JSON artifact kind to the schema_version its
// payload declares. The values of the kinds delivered before this declaration
// keep their historical strings (system-snapshot/1, render-manifest/1, ...) so a
// consumer that already pins one sees no change.
var artifactSchemaVersions = map[string]string{
	"memory-search-results":    schemaMemorySearchResults,
	"memory-diff-results":      schemaMemoryDiffResults,
	"experiment-manifest":      schemaExperimentManifest,
	"state-diff-results":       schemaStateDiffResults,
	"capture-manifest":         schemaCaptureManifest,
	"vdp-capture-manifest":     schemaVDPCaptureManifest,
	"vdp-render-manifest":      schemaVDPRenderManifest,
	"vdp-status":               schemaVDPStatus,
	"vdp-palette-json":         schemaVDPPaletteJSON,
	"vdp-tiles-json":           schemaVDPTilesJSON,
	"vdp-plane-json":           schemaVDPPlaneJSON,
	"system-m68k-registers":    schemaSystemM68KRegisters,
	"system-z80-registers":     schemaSystemZ80Registers,
	"system-vdp-status":        schemaSystemVDPStatus,
	"system-snapshot-manifest": systemSnapshotSchema,
	"system-render-manifest":   "render-manifest/1",
	"cpu-coverage":             "cpu-coverage/2",
	"debug-event":              "debug-event/1",
	"replay-manifest":          replayManifestVer,
	"annotation-export":        analysis.AnnotationExportSchema,
	"sound-status":             "sound-status/1",
}

// artifactSchemaVersion returns the declared version of one JSON artifact kind.
func artifactSchemaVersion(kind string) (string, bool) {
	version, present := artifactSchemaVersions[kind]
	return version, present
}

// putJSONArtifact stamps the declared schema_version of one JSON document kind
// and writes it immutably. Stamping happens here, at the single write path, so
// a producer cannot publish a document whose payload claims a version other than
// the one this server declares.
func putJSONArtifact(server *Server, contextID, kind string, document map[string]any, provenance *artifact.Provenance) (artifact.Artifact, error) {
	version, present := artifactSchemaVersion(kind)
	if !present {
		return artifact.Artifact{}, fmt.Errorf("artifact kind %q has no declared schema_version", kind)
	}
	document["schema_version"] = version
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return artifact.Artifact{}, fmt.Errorf("encode %s artifact: %w", kind, err)
	}
	return server.store.PutWithProvenance(contextID, kind, "application/json", encoded, provenance)
}
