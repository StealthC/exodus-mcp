package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// annotationToolSpecs implements the P2 evidence-annotation surface:
// context-scoped, analyst-provided observations and hypotheses about
// addresses and ranges. Every annotation is stamped with the ROM identity
// and target generation observed at creation; a later ROM load or target
// mutation flags it stale instead of deleting it. Annotations are analyst
// interpretation, never emulator output, and are never promoted to symbols
// automatically.
func annotationToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "annotation_create",
			description: "Record an analyst-provided observation or hypothesis about an address or range in one analysis context. Annotations are analyst interpretation, never emulator output: the record is stamped with the ROM identity (SHA-256 and path) and target generation observed at creation, so a later ROM load or target mutation flags it stale rather than deleting it. Evidence links (artifacts, states, captures, trace events, symbols, breakpoints, watchpoints) document what supports the claim; annotations are never promoted to symbols automatically.",
			schema: objectSchema(map[string]any{
				"title":         stringProperty("Required annotation title (1-200 characters)."),
				"text":          stringProperty("Optional body text, up to 4096 characters."),
				"tags":          stringArrayProperty("Optional tags for filtering."),
				"category":      enumProperty("Optional category.", []string{"observation", "hypothesis", "note", "bug", "todo"}),
				"author":        stringProperty("Analyst or tool that created the annotation."),
				"source":        stringProperty("Origin of the claim, e.g. the report or trace it came from."),
				"confidence":    enumProperty("Optional confidence in the claim.", []string{"low", "medium", "high", "unknown"}),
				"kind":          annotationKindProperty(),
				"address_space": stringProperty("Address space the annotation addresses (e.g. m68k-bus, mem-ram, mem-rom)."),
				"address":       addressProperty(),
				"end_address":   addressProperty(),
				"length":        integerProperty("Byte length of the annotated range; derived as end_address-address+1 when both are given.", 1),
				"links":         annotationLinksProperty(),
				"context":       contextProperty(),
			}, []string{"title"}),
			run: runAnnotationCreate,
		},
		{
			name:        "annotation_delete",
			description: "Delete one analyst annotation from a context. Deleting is permanent; export the context first when the annotation should survive for historical analysis.",
			schema: objectSchema(map[string]any{
				"annotation_id": stringProperty("Annotation id returned by annotation_create."),
				"context":       contextProperty(),
			}, []string{"annotation_id"}),
			run: runAnnotationDelete,
		},
		{
			name:        "annotation_export",
			description: "Export every annotation of a context as a versioned annotation-export/1 document artifact (application/json). The document carries the schema version, export time, the loaded target's ROM identity, the current target generation, and every annotation with its own creation-time ROM stamps and evidence links, so the export is reproducible and retains complete provenance. The artifact is stored with generic capture provenance (kind annotation-export); historical annotations that no longer match the loaded target are preserved, not dropped.",
			schema: objectSchema(map[string]any{
				"context": contextProperty(),
			}, nil),
			run: runAnnotationExport,
		},
		{
			name:        "annotation_get",
			description: "Fetch one analyst annotation with its full provenance: creation stamps, address domain, evidence links, and the current stale flag (stale when the annotation's ROM SHA-256 or target generation no longer matches the loaded target, with the matching stale_reason).",
			schema: objectSchema(map[string]any{
				"annotation_id": stringProperty("Annotation id returned by annotation_create."),
				"context":       contextProperty(),
			}, []string{"annotation_id"}),
			run: runAnnotationGet,
		},
		{
			name:        "annotation_import",
			description: "Import annotations from an annotation-export/1 document, either as inline JSON data or by artifact_id of a stored annotation-export artifact (provide exactly one). Imported annotations keep their original ids, timestamps, and creation-time ROM stamps; only the owning context changes. With overwrite=true an existing id is replaced; otherwise it is reported in conflicts and skipped. The per-context cap (500 annotations) is enforced against net growth.",
			schema: objectSchema(map[string]any{
				"artifact_id": stringProperty("Id of a stored annotation-export artifact to read the document from."),
				"data":        stringProperty("Inline JSON export document (schema annotation-export/1) to import; pass either the document object or a JSON string containing it."),
				"overwrite":   booleanProperty("Replace annotations whose id already exists in this context (default false: they are reported as conflicts)."),
				"context":     contextProperty(),
			}, nil),
			run: runAnnotationImport,
		},
		{
			name:        "annotation_list",
			description: "List the analyst annotations of a context, newest first, with bounded pagination. Every annotation is flagged stale (with stale_reason) when its creation-time ROM SHA-256 or target generation no longer matches the loaded target; stale annotations are preserved for historical analysis and by default excluded but counted in stale_excluded so nothing is dropped silently. include_stale keeps them in the results flagged; stale_only lists only stale ones. Filter by substring query (case-insensitive over title, text, tags), tags, category, kind, and address space.",
			schema: objectSchema(map[string]any{
				"filter":        stringProperty("Case-insensitive substring matched against title, text, and tags."),
				"tags":          stringArrayProperty("Only annotations carrying every listed tag."),
				"category":      enumProperty("Only this category.", []string{"observation", "hypothesis", "note", "bug", "todo"}),
				"kind":          annotationKindProperty(),
				"address_space": stringProperty("Only annotations in this address space."),
				"stale_only":    booleanProperty("Only annotations whose ROM identity or target generation no longer matches the loaded target."),
				"include_stale": booleanProperty("Keep stale annotations in the results, flagged (default false: they are excluded but counted in stale_excluded)."),
				"offset":        integerProperty("Skip this many matching annotations (default 0).", 0),
				"limit":         integerProperty(fmt.Sprintf("Maximum annotations returned (default %d, cap %d).", analysis.DefaultAnnotationLimit, analysis.MaxAnnotationLimit), 0),
				"context":       contextProperty(),
			}, nil),
			run: runAnnotationList,
		},
		{
			name:        "annotation_update",
			description: "Edit one analyst annotation: title, text, tags, category, confidence, kind, address space, address/end address, and evidence links. Omitted fields keep their current value; pass a null address to clear the address domain. The annotation keeps its creation-time ROM stamps, so editing never rewrites provenance; the stale flag reflects the original stamps against the loaded target. Address updates recompute length as end_address-address+1.",
			schema: objectSchema(map[string]any{
				"annotation_id": stringProperty("Annotation id returned by annotation_create."),
				"title":         stringProperty("New title (1-200 characters)."),
				"text":          stringProperty("New body text, up to 4096 characters."),
				"tags":          stringArrayProperty("Replacement tags."),
				"category":      enumProperty("New category.", []string{"observation", "hypothesis", "note", "bug", "todo"}),
				"confidence":    enumProperty("New confidence.", []string{"low", "medium", "high", "unknown"}),
				"kind":          annotationKindProperty(),
				"address_space": stringProperty("New address space."),
				"address":       addressUpdateProperty(),
				"end_address":   addressUpdateProperty(),
				"links":         annotationLinksProperty(),
				"context":       contextProperty(),
			}, []string{"annotation_id"}),
			run: runAnnotationUpdate,
		},
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Shared schema helpers
// ----------------------------------------------------------------------------------------------------------------------

func annotationKindProperty() map[string]any {
	property := enumProperty("Annotation kind: observation records something directly observed; hypothesis records an analyst claim that must be supported by evidence links.", []string{"observation", "hypothesis"})
	property["default"] = "observation"
	return property
}

func stringArrayProperty(description string) map[string]any {
	return map[string]any{
		"type":        "array",
		"items":       stringProperty(""),
		"description": description,
	}
}

func uintArrayProperty(description string) map[string]any {
	return map[string]any{
		"type":        "array",
		"items":       map[string]any{"type": "integer", "minimum": 0},
		"description": description,
	}
}

func annotationLinksProperty() map[string]any {
	return map[string]any{
		"type":                 "object",
		"description":          "Evidence links supporting the claim: artifacts, states, captures, trace events, symbols, breakpoints, and watchpoints that document the observation or hypothesis.",
		"additionalProperties": false,
		"properties": map[string]any{
			"artifacts":    stringArrayProperty("Artifact ids (art_...) that support the claim, e.g. a memory-diff-results artifact."),
			"states":       stringArrayProperty("State ids (state_...) captured around the evidence."),
			"captures":     stringArrayProperty("Capture ids of composite captures."),
			"trace_events": uintArrayProperty("Trace event ids (cpu trace operation ids) that support the claim."),
			"symbols":      stringArrayProperty("Symbol names the claim refers to."),
			"breakpoints":  uintArrayProperty("Breakpoint ids (plugin resource ids) used to observe the claim."),
			"watchpoints":  uintArrayProperty("Watchpoint ids (plugin resource ids) used to observe the claim."),
		},
	}
}

// addressUpdateProperty documents that the update form additionally accepts
// null to clear the address domain. The oneOf shape stays the canonical
// two-branch address form (integer + flexible hex string) enforced by the
// schema contract tests; the null clear behavior is documented and handled
// by the handler.
func addressUpdateProperty() map[string]any {
	property := addressProperty()
	property["description"] = property["description"].(string) + " Pass null to clear the address domain."
	return property
}

// ----------------------------------------------------------------------------------------------------------------------
// Shared handler helpers
// ----------------------------------------------------------------------------------------------------------------------

// currentAnnotationTarget captures the loaded target identity used to stamp
// new annotations and to compute staleness flags.
func currentAnnotationTarget(server *Server) analysis.AnnotationTarget {
	romPath := server.currentROMPath()
	facts := server.romIdentity.romFileFacts(romPath)
	return analysis.AnnotationTarget{
		ROMPath:    romPath,
		ROMSHA256:  facts.SHA256,
		Generation: server.target.Generation(),
	}
}

// annotationView renders one annotation with its staleness flags computed
// against the loaded target.
func annotationView(server *Server, ann analysis.Annotation) map[string]any {
	current := currentAnnotationTarget(server)
	view := map[string]any{
		"id":                ann.ID,
		"context_id":        ann.ContextID,
		"title":             ann.Title,
		"kind":              ann.Kind,
		"created_at":        ann.CreatedAt,
		"updated_at":        ann.UpdatedAt,
		"target_generation": ann.TargetGeneration,
		"stale":             analysis.AnnotationIsStale(ann, current),
		"stale_reason":      analysis.AnnotationStaleReason(ann, current),
	}
	if ann.Text != "" {
		view["text"] = ann.Text
	}
	if ann.Category != "" {
		view["category"] = ann.Category
	}
	if ann.Author != "" {
		view["author"] = ann.Author
	}
	if ann.Source != "" {
		view["source"] = ann.Source
	}
	if ann.Confidence != "" {
		view["confidence"] = ann.Confidence
	}
	if ann.AddressSpace != "" {
		view["address_space"] = ann.AddressSpace
	}
	if ann.Address != nil {
		view["address"] = *ann.Address
		view["address_hex"] = canonicalHex(*ann.Address)
	}
	if ann.EndAddress != nil {
		view["end_address"] = *ann.EndAddress
		view["end_address_hex"] = canonicalHex(*ann.EndAddress)
	}
	if ann.Length != nil {
		view["length"] = *ann.Length
	}
	if ann.ROMPath != "" {
		view["rom_path"] = ann.ROMPath
	}
	if ann.ROMSHA256 != "" {
		view["rom_sha256"] = ann.ROMSHA256
	}
	if links := linksView(ann.Links); len(links) > 0 {
		view["links"] = links
	}
	return view
}

func linksView(links analysis.AnnotationLinks) map[string]any {
	out := map[string]any{}
	if len(links.Artifacts) > 0 {
		out["artifacts"] = links.Artifacts
	}
	if len(links.States) > 0 {
		out["states"] = links.States
	}
	if len(links.Captures) > 0 {
		out["captures"] = links.Captures
	}
	if len(links.TraceEvents) > 0 {
		out["trace_events"] = links.TraceEvents
	}
	if len(links.Symbols) > 0 {
		out["symbols"] = links.Symbols
	}
	if len(links.Breakpoints) > 0 {
		out["breakpoints"] = links.Breakpoints
	}
	if len(links.Watchpoints) > 0 {
		out["watchpoints"] = links.Watchpoints
	}
	return out
}

func linksFromArgs(args annotationLinksArgs) analysis.AnnotationLinks {
	return analysis.AnnotationLinks{
		Artifacts:   args.Artifacts,
		States:      args.States,
		Captures:    args.Captures,
		TraceEvents: args.TraceEvents,
		Symbols:     args.Symbols,
		Breakpoints: args.Breakpoints,
		Watchpoints: args.Watchpoints,
	}
}

// annotationStoreFailure maps store errors to stable tool failure codes.
func annotationStoreFailure(err error) *toolFailure {
	var validation *analysis.ValidationError
	if errors.As(err, &validation) {
		return &toolFailure{Code: "invalid_params", Message: validation.Error()}
	}
	switch {
	case errors.Is(err, analysis.ErrAnnotationNotFound):
		return &toolFailure{Code: "unknown_annotation", Message: err.Error()}
	case errors.Is(err, analysis.ErrAnnotationLimit):
		return &toolFailure{Code: "annotation_limit_exceeded", Message: fmt.Sprintf("at most %d annotations per context", analysis.MaxAnnotationsPerContext)}
	default:
		return &toolFailure{Code: "invalid_params", Message: err.Error()}
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// annotation_create
// ----------------------------------------------------------------------------------------------------------------------

type annotationLinksArgs struct {
	Artifacts   []string `json:"artifacts"`
	States      []string `json:"states"`
	Captures    []string `json:"captures"`
	TraceEvents []uint64 `json:"trace_events"`
	Symbols     []string `json:"symbols"`
	Breakpoints []uint64 `json:"breakpoints"`
	Watchpoints []uint64 `json:"watchpoints"`
}

type annotationCreateArgs struct {
	Title        string               `json:"title"`
	Text         string               `json:"text"`
	Tags         []string             `json:"tags"`
	Category     string               `json:"category"`
	Author       string               `json:"author"`
	Source       string               `json:"source"`
	Confidence   string               `json:"confidence"`
	Kind         string               `json:"kind"`
	AddressSpace string               `json:"address_space"`
	Address      any                  `json:"address"`
	EndAddress   any                  `json:"end_address"`
	Length       *uint64              `json:"length"`
	Links        *annotationLinksArgs `json:"links"`
	Context      string               `json:"context"`
}

func runAnnotationCreate(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[annotationCreateArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	kind := strings.TrimSpace(parsed.Kind)
	if kind == "" {
		kind = "observation"
	}
	ann := analysis.Annotation{
		Title:        parsed.Title,
		Text:         parsed.Text,
		Tags:         parsed.Tags,
		Category:     strings.TrimSpace(parsed.Category),
		Author:       strings.TrimSpace(parsed.Author),
		Source:       strings.TrimSpace(parsed.Source),
		Confidence:   strings.TrimSpace(parsed.Confidence),
		Kind:         kind,
		AddressSpace: strings.TrimSpace(parsed.AddressSpace),
	}
	if parsed.Address != nil {
		address, failure := parseAddress(parsed.Address)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		ann.Address = &address
	}
	if parsed.EndAddress != nil {
		if ann.Address == nil {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "end_address requires address"}, tc.modern)
		}
		endAddress, failure := parseAddress(parsed.EndAddress)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		if endAddress < *ann.Address {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "end_address must be >= address"}, tc.modern)
		}
		ann.EndAddress = &endAddress
		length := endAddress - *ann.Address + 1
		if parsed.Length != nil && *parsed.Length != length {
			return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("length must equal end_address-address+1 (%d)", length)}, tc.modern)
		}
		ann.Length = &length
	}
	if parsed.Length != nil && ann.Address == nil {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "length requires address"}, tc.modern)
	}
	if parsed.Links != nil {
		ann.Links = linksFromArgs(*parsed.Links)
	}
	current := currentAnnotationTarget(tc.server)
	ann.ROMPath = current.ROMPath
	ann.ROMSHA256 = current.ROMSHA256
	ann.TargetGeneration = current.Generation
	stored, err := context.Annotations.Create(context.ID, ann)
	if err != nil {
		return failureResult(annotationStoreFailure(err), tc.modern)
	}
	return okResult(map[string]any{
		"annotation": annotationView(tc.server, stored),
	}, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// annotation_get
// ----------------------------------------------------------------------------------------------------------------------

type annotationRefArgs struct {
	AnnotationID string `json:"annotation_id"`
	Context      string `json:"context"`
}

func runAnnotationGet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[annotationRefArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if strings.TrimSpace(parsed.AnnotationID) == "" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "annotation_id is required"}, tc.modern)
	}
	ann, err := context.Annotations.Get(context.ID, parsed.AnnotationID)
	if err != nil {
		return failureResult(annotationStoreFailure(err), tc.modern)
	}
	return okResult(map[string]any{
		"annotation": annotationView(tc.server, *ann),
	}, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// annotation_update
// ----------------------------------------------------------------------------------------------------------------------

type annotationUpdateArgs struct {
	AnnotationID string               `json:"annotation_id"`
	Title        *string              `json:"title"`
	Text         *string              `json:"text"`
	Tags         *[]string            `json:"tags"`
	Category     *string              `json:"category"`
	Confidence   *string              `json:"confidence"`
	Kind         *string              `json:"kind"`
	AddressSpace *string              `json:"address_space"`
	Address      json.RawMessage      `json:"address"`
	EndAddress   json.RawMessage      `json:"end_address"`
	Links        *annotationLinksArgs `json:"links"`
	Context      string               `json:"context"`
}

func runAnnotationUpdate(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[annotationUpdateArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if strings.TrimSpace(parsed.AnnotationID) == "" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "annotation_id is required"}, tc.modern)
	}
	updates := analysis.AnnotationUpdate{
		Title:        parsed.Title,
		Text:         parsed.Text,
		Tags:         parsed.Tags,
		Category:     parsed.Category,
		Confidence:   parsed.Confidence,
		Kind:         parsed.Kind,
		AddressSpace: parsed.AddressSpace,
		Links:        nil,
	}
	if parsed.Links != nil {
		links := linksFromArgs(*parsed.Links)
		updates.Links = &links
	}
	address, clearAddress, failure := parseAnnotationAddressArg(parsed.Address)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	updates.Address = address
	updates.ClearAddress = clearAddress
	endAddress, clearEnd, failure := parseAnnotationAddressArg(parsed.EndAddress)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	updates.EndAddress = endAddress
	updates.ClearEndAddress = clearEnd
	updated, err := context.Annotations.Update(context.ID, parsed.AnnotationID, updates)
	if err != nil {
		return failureResult(annotationStoreFailure(err), tc.modern)
	}
	return okResult(map[string]any{
		"annotation": annotationView(tc.server, *updated),
	}, tc.modern)
}

// parseAnnotationAddressArg parses the update-form address argument: absent
// (nil raw) keeps the current value, JSON null clears it, any other flexible
// address form parses to a new value.
func parseAnnotationAddressArg(raw json.RawMessage) (*uint64, bool, *toolFailure) {
	if raw == nil {
		return nil, false, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, true, nil
	}
	var value any
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return nil, false, &toolFailure{Code: "invalid_params", Message: "invalid address: " + err.Error()}
	}
	address, failure := parseAddress(value)
	if failure != nil {
		return nil, false, failure
	}
	return &address, false, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// annotation_delete
// ----------------------------------------------------------------------------------------------------------------------

func runAnnotationDelete(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[annotationRefArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if strings.TrimSpace(parsed.AnnotationID) == "" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "annotation_id is required"}, tc.modern)
	}
	if err := context.Annotations.Delete(context.ID, parsed.AnnotationID); err != nil {
		return failureResult(annotationStoreFailure(err), tc.modern)
	}
	return okResult(map[string]any{
		"deleted":       true,
		"annotation_id": parsed.AnnotationID,
	}, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// annotation_list
// ----------------------------------------------------------------------------------------------------------------------

type annotationListArgs struct {
	Filter       string   `json:"filter"`
	Tags         []string `json:"tags"`
	Category     string   `json:"category"`
	Kind         string   `json:"kind"`
	AddressSpace string   `json:"address_space"`
	StaleOnly    bool     `json:"stale_only"`
	IncludeStale bool     `json:"include_stale"`
	Offset       *uint64  `json:"offset"`
	Limit        *uint64  `json:"limit"`
	Context      string   `json:"context"`
}

func runAnnotationList(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[annotationListArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	filter := analysis.AnnotationFilter{
		Tags:         parsed.Tags,
		Category:     strings.TrimSpace(parsed.Category),
		Kind:         strings.TrimSpace(parsed.Kind),
		Query:        parsed.Filter,
		AddressSpace: strings.TrimSpace(parsed.AddressSpace),
		IncludeStale: parsed.IncludeStale,
		StaleOnly:    parsed.StaleOnly,
		Limit:        analysis.DefaultAnnotationLimit,
	}
	if parsed.Offset != nil {
		filter.Offset = int(*parsed.Offset)
	}
	if parsed.Limit != nil {
		if *parsed.Limit > analysis.MaxAnnotationLimit {
			return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("limit is capped at %d", analysis.MaxAnnotationLimit)}, tc.modern)
		}
		filter.Limit = int(*parsed.Limit)
	}
	result := context.Annotations.List(context.ID, filter, currentAnnotationTarget(tc.server))
	views := make([]map[string]any, 0, len(result.Annotations))
	for _, ann := range result.Annotations {
		views = append(views, annotationView(tc.server, ann))
	}
	return okResult(map[string]any{
		"annotations":    views,
		"count":          len(views),
		"total":          result.Total,
		"stale_excluded": result.StaleExcluded,
		"truncated":      result.Truncated,
		"pagination": map[string]any{
			"offset":      filter.Offset,
			"limit":       filter.Limit,
			"next_offset": filter.Offset + len(views),
		},
	}, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// annotation_export
// ----------------------------------------------------------------------------------------------------------------------

type annotationExportArgs struct {
	Context string `json:"context"`
}

func runAnnotationExport(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[annotationExportArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	current := currentAnnotationTarget(tc.server)
	document := analysis.AnnotationExportDocument{
		SchemaVersion:    analysis.AnnotationExportSchema,
		ExportedAt:       time.Now().UTC(),
		ROMIdentity:      tc.server.romIdentityView(0),
		TargetGeneration: current.Generation,
		Annotations:      context.Annotations.Export(context.ID),
	}
	docBytes, err := document.Marshal()
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	exportedAt := time.Now().UTC()
	stored, err := tc.server.store.PutWithProvenance(context.ID, "annotation-export", "application/json", docBytes, genericProvenance(tc.server, "annotation-export", exportedAt))
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	return okResult(map[string]any{
		"annotation_count":  len(document.Annotations),
		"schema_version":    analysis.AnnotationExportSchema,
		"exported_at":       document.ExportedAt,
		"rom_identity":      document.ROMIdentity,
		"target_generation": document.TargetGeneration,
		"artifact":          artifactDescriptor(tc.server, stored, context.ID),
	}, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// annotation_import
// ----------------------------------------------------------------------------------------------------------------------

type annotationImportArgs struct {
	ArtifactID string          `json:"artifact_id"`
	Data       json.RawMessage `json:"data"`
	Overwrite  bool            `json:"overwrite"`
	Context    string          `json:"context"`
}

func runAnnotationImport(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[annotationImportArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	hasData := false
	if parsed.Data != nil {
		trimmed := bytes.TrimSpace(parsed.Data)
		hasData = len(trimmed) > 0 && string(trimmed) != "null"
	}
	if parsed.ArtifactID == "" && !hasData {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "provide one of artifact_id or inline data"}, tc.modern)
	}
	if parsed.ArtifactID != "" && hasData {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "provide exactly one of artifact_id or inline data"}, tc.modern)
	}
	var data []byte
	if parsed.ArtifactID != "" {
		meta, err := tc.server.store.Metadata(parsed.ArtifactID, context.ID)
		if err != nil {
			return failureResult(&toolFailure{Code: "unknown_artifact", Message: err.Error()}, tc.modern)
		}
		if meta.Kind != "annotation-export" {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "artifact_id must reference an annotation-export artifact; got kind " + meta.Kind}, tc.modern)
		}
		data, _, err = tc.server.store.Bytes(parsed.ArtifactID, context.ID)
		if err != nil {
			return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
		}
	} else {
		// The inline data accepts either the document object directly or a
		// JSON string containing the document text.
		trimmed := bytes.TrimSpace(parsed.Data)
		if len(trimmed) > 0 && trimmed[0] == '"' {
			var encoded string
			if err := json.Unmarshal(trimmed, &encoded); err != nil {
				return failureResult(&toolFailure{Code: "invalid_params", Message: "data must be an annotation-export/1 JSON document or a string containing one"}, tc.modern)
			}
			data = []byte(encoded)
		} else {
			data = trimmed
		}
	}
	imported, conflicts, err := context.Annotations.Import(context.ID, data, parsed.Overwrite)
	if err != nil {
		if errors.Is(err, analysis.ErrAnnotationLimit) {
			return failureResult(&toolFailure{Code: "annotation_limit_exceeded", Message: fmt.Sprintf("import would exceed the %d-annotation per-context cap", analysis.MaxAnnotationsPerContext)}, tc.modern)
		}
		return failureResult(&toolFailure{Code: "invalid_params", Message: err.Error()}, tc.modern)
	}
	return okResult(map[string]any{
		"imported":  imported,
		"conflicts": conflicts,
		"overwrite": parsed.Overwrite,
	}, tc.modern)
}
