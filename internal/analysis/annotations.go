package analysis

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Annotation is one analyst-provided, context-scoped record about an address
// or range. Annotations are analyst interpretation and hypotheses, never
// emulator output: they are stamped with the ROM identity and target
// generation observed at creation time, and links document the evidence
// (artifacts, states, captures, trace events, symbols, breakpoints,
// watchpoints) that supports the claim. An annotation is never promoted to a
// symbol automatically. When the loaded ROM identity or target generation no
// longer matches the stamps, the annotation is flagged stale by list/export
// views but preserved for historical analysis.
type Annotation struct {
	ID         string    `json:"id"`
	ContextID  string    `json:"context_id"`
	Title      string    `json:"title"`
	Text       string    `json:"text,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	Category   string    `json:"category,omitempty"`
	Author     string    `json:"author,omitempty"`
	Source     string    `json:"source,omitempty"`
	Confidence string    `json:"confidence,omitempty"`
	Kind       string    `json:"kind"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// Address domain of the claim, space-relative like every address the
	// server reports. A range is address..end_address inclusive; length is
	// end_address-address+1 when both ends are known.
	AddressSpace string  `json:"address_space,omitempty"`
	Address      *uint64 `json:"address,omitempty"`
	EndAddress   *uint64 `json:"end_address,omitempty"`
	Length       *uint64 `json:"length,omitempty"`

	// ROM identity and target generation observed when the annotation was
	// created or last updated. Staleness compares these against the loaded
	// target; the stamps are never rewritten by a later ROM load.
	ROMPath          string `json:"rom_path,omitempty"`
	ROMSHA256        string `json:"rom_sha256,omitempty"`
	TargetGeneration uint64 `json:"target_generation"`

	Links AnnotationLinks `json:"links,omitempty"`
}

// AnnotationLinks records the evidence supporting an annotation.
type AnnotationLinks struct {
	Artifacts   []string `json:"artifacts,omitempty"`
	States      []string `json:"states,omitempty"`
	Captures    []string `json:"captures,omitempty"`
	TraceEvents []uint64 `json:"trace_events,omitempty"`
	Symbols     []string `json:"symbols,omitempty"`
	Breakpoints []uint64 `json:"breakpoints,omitempty"`
	Watchpoints []uint64 `json:"watchpoints,omitempty"`
}

// Annotation limits and defaults. The per-context cap keeps list and import
// behavior bounded; list pagination defaults to 20 with a 100-item cap.
const (
	MaxAnnotationsPerContext = 500
	maxAnnotationTitleChars  = 200
	maxAnnotationTextChars   = 4096
	DefaultAnnotationLimit   = 20
	MaxAnnotationLimit       = 100
)

// Annotation category, confidence, and kind vocabularies.
var (
	annotationCategories  = []string{"observation", "hypothesis", "note", "bug", "todo"}
	annotationConfidences = []string{"low", "medium", "high", "unknown"}
	annotationKinds       = []string{"observation", "hypothesis"}
)

// Store errors mapped to stable MCP failure codes by the tool layer.
var (
	// ErrAnnotationNotFound is returned when an id does not resolve in the
	// caller's context.
	ErrAnnotationNotFound = errors.New("unknown annotation")
	// ErrAnnotationLimit is returned when a create/update/import would exceed
	// the per-context annotation cap.
	ErrAnnotationLimit = errors.New("annotation limit exceeded")
)

// ValidationError reports one invalid annotation field; the tool layer maps
// it to invalid_params.
type ValidationError struct {
	Field   string
	Message string
}

func (err *ValidationError) Error() string {
	return fmt.Sprintf("invalid annotation field %q: %s", err.Field, err.Message)
}

// AnnotationTarget is the loaded target identity used for staleness checks.
// ROMSHA256 is empty when no ROM is loaded or the file is unreadable; a
// comparison with an annotation stamp is then per the strict equality rule.
type AnnotationTarget struct {
	ROMPath    string
	ROMSHA256  string
	Generation uint64
}

// AnnotationFilter narrows one List call. Query is a case-insensitive
// substring matched against title, text, and tags. The staleness policy is:
// StaleOnly keeps only stale annotations; otherwise IncludeStale keeps stale
// annotations (flagged) alongside fresh ones; with neither flag stale
// annotations are excluded and reported through ListResult.StaleExcluded so
// historical records are never dropped silently.
type AnnotationFilter struct {
	Tags         []string
	Category     string
	Kind         string
	Query        string
	AddressSpace string
	IncludeStale bool
	StaleOnly    bool
	Offset       int
	Limit        int
}

// AnnotationUpdate carries the optional fields changed by Update. Nil
// pointers keep the current value; ClearAddress/ClearEndAddress express an
// explicit null that clears the domain field.
type AnnotationUpdate struct {
	Title           *string
	Text            *string
	Tags            *[]string
	Category        *string
	Confidence      *string
	Kind            *string
	AddressSpace    *string
	Address         *uint64
	ClearAddress    bool
	EndAddress      *uint64
	ClearEndAddress bool
	Links           *AnnotationLinks
}

// AnnotationListResult is one filtered page plus pagination facts.
// Total counts every annotation matching the non-pagination filters
// (staleness policy included); StaleExcluded counts matching annotations set
// aside by that policy so pagination never silently omits historical records.
type AnnotationListResult struct {
	Annotations   []Annotation
	Total         int
	StaleExcluded int
	Truncated     bool
}

// AnnotationStore tracks annotations per analysis context. It is safe for
// concurrent use.
type AnnotationStore struct {
	mu    sync.RWMutex
	byID  map[string]Annotation
	byCtx map[string][]string // context id -> annotation ids, newest first
}

// NewAnnotationStore creates an empty store.
func NewAnnotationStore() *AnnotationStore {
	return &AnnotationStore{
		byID:  make(map[string]Annotation),
		byCtx: make(map[string][]string),
	}
}

// NewAnnotationID returns a fresh annotation identifier.
func NewAnnotationID() string {
	buffer := make([]byte, 9)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("generate annotation id: %v", err))
	}
	return "annotation_" + base64.RawURLEncoding.EncodeToString(buffer)
}

// Create validates and registers one annotation. The caller stamps the ROM
// identity and target generation. The per-context cap is enforced.
func (store *AnnotationStore) Create(ctxID string, ann Annotation) (Annotation, error) {
	if err := validateAnnotation(&ann); err != nil {
		return Annotation{}, err
	}
	ann.ID = NewAnnotationID()
	ann.ContextID = ctxID
	now := time.Now().UTC()
	ann.CreatedAt = now
	ann.UpdatedAt = now
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.byCtx[ctxID]) >= MaxAnnotationsPerContext {
		return Annotation{}, ErrAnnotationLimit
	}
	store.insertLocked(ann)
	return ann, nil
}

// Get returns one annotation of a context.
func (store *AnnotationStore) Get(ctxID, id string) (*Annotation, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	ann, present := store.byID[id]
	if !present || ann.ContextID != ctxID {
		return nil, ErrAnnotationNotFound
	}
	copy := ann
	return &copy, nil
}

// Update merges the optional changes into one annotation, revalidates the
// result, and bumps UpdatedAt. ClearAddress clears address, end_address, and
// length together; ClearEndAddress clears end_address and the derived length.
func (store *AnnotationStore) Update(ctxID, id string, updates AnnotationUpdate) (*Annotation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	current, present := store.byID[id]
	if !present || current.ContextID != ctxID {
		return nil, ErrAnnotationNotFound
	}
	if updates.Title != nil {
		current.Title = *updates.Title
	}
	if updates.Text != nil {
		current.Text = *updates.Text
	}
	if updates.Tags != nil {
		current.Tags = *updates.Tags
	}
	if updates.Category != nil {
		current.Category = *updates.Category
	}
	if updates.Confidence != nil {
		current.Confidence = *updates.Confidence
	}
	if updates.Kind != nil {
		current.Kind = *updates.Kind
	}
	if updates.AddressSpace != nil {
		current.AddressSpace = *updates.AddressSpace
	}
	if updates.ClearAddress {
		current.Address = nil
		current.EndAddress = nil
		current.Length = nil
	} else {
		if updates.Address != nil {
			current.Address = updates.Address
		}
		if updates.ClearEndAddress {
			current.EndAddress = nil
			current.Length = nil
		} else if updates.EndAddress != nil {
			current.EndAddress = updates.EndAddress
		}
		if current.Address != nil && current.EndAddress != nil {
			if *current.EndAddress < *current.Address {
				return nil, &ValidationError{Field: "end_address", Message: "end_address must be >= address for a range annotation"}
			}
			length := *current.EndAddress - *current.Address + 1
			current.Length = &length
		}
	}
	if updates.Links != nil {
		current.Links = *updates.Links
	}
	if err := validateAnnotation(&current); err != nil {
		return nil, err
	}
	current.UpdatedAt = time.Now().UTC()
	store.byID[id] = current
	// Re-sort the context list so ordering stays newest-first by UpdatedAt.
	store.sortByCtxLocked(ctxID)
	copy := current
	return &copy, nil
}

// Delete removes one annotation of a context.
func (store *AnnotationStore) Delete(ctxID, id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	ann, present := store.byID[id]
	if !present || ann.ContextID != ctxID {
		return ErrAnnotationNotFound
	}
	delete(store.byID, id)
	ids := store.byCtx[ctxID]
	for index, candidate := range ids {
		if candidate == id {
			store.byCtx[ctxID] = append(ids[:index], ids[index+1:]...)
			break
		}
	}
	return nil
}

// List returns one filtered page of annotations plus pagination facts. The
// current target identity drives staleness filtering and flags.
func (store *AnnotationStore) List(ctxID string, filter AnnotationFilter, current AnnotationTarget) AnnotationListResult {
	if filter.Limit <= 0 {
		filter.Limit = DefaultAnnotationLimit
	}
	if filter.Limit > MaxAnnotationLimit {
		filter.Limit = MaxAnnotationLimit
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	matched := make([]Annotation, 0, len(store.byCtx[ctxID]))
	staleExcluded := 0
	for _, id := range store.byCtx[ctxID] {
		ann := store.byID[id]
		if !annotationMatchesFilter(ann, filter) {
			continue
		}
		stale := AnnotationIsStale(ann, current)
		if !staleMatchesPolicy(stale, filter) {
			// A matching annotation set aside by the staleness policy is
			// reported so pagination never silently omits it.
			staleExcluded++
			continue
		}
		matched = append(matched, ann)
	}
	total := len(matched)
	result := AnnotationListResult{Total: total, StaleExcluded: staleExcluded}
	if filter.Offset >= len(matched) {
		return result
	}
	matched = matched[filter.Offset:]
	if len(matched) > filter.Limit {
		matched = matched[:filter.Limit]
		result.Truncated = true
	}
	result.Annotations = matched
	return result
}

// Export returns every annotation of a context, newest first, as a stable
// snapshot for the versioned annotation-export document. The caller attaches
// schema, export time, and current ROM identity.
func (store *AnnotationStore) Export(ctxID string) []Annotation {
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := make([]Annotation, 0, len(store.byCtx[ctxID]))
	for _, id := range store.byCtx[ctxID] {
		if ann, present := store.byID[id]; present {
			out = append(out, ann)
		}
	}
	return out
}

// Import loads one exported annotation document (schema annotation-export/1)
// into a context. Imported annotations keep their original identifiers,
// timestamps, and ROM stamps; only the owning context is re-homed to ctxID.
// When overwrite is false an existing id is skipped and reported in
// conflicts. The import is all-or-nothing: any structurally invalid entry
// rejects the whole document. The per-context cap is enforced against the
// net growth so re-importing an existing set stays allowed.
func (store *AnnotationStore) Import(ctxID string, data []byte, overwrite bool) (imported int, conflicts []string, err error) {
	var document struct {
		SchemaVersion string       `json:"schema_version"`
		Annotations   []Annotation `json:"annotations"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return 0, nil, fmt.Errorf("parse annotation export: %w", err)
	}
	if document.SchemaVersion != "annotation-export/1" {
		return 0, nil, fmt.Errorf("unsupported annotation export schema %q (expected annotation-export/1)", document.SchemaVersion)
	}
	for index := range document.Annotations {
		ann := document.Annotations[index]
		if !strings.HasPrefix(ann.ID, "annotation_") {
			return 0, nil, fmt.Errorf("annotation %d: invalid id %q", index, ann.ID)
		}
		if err := validateAnnotation(&ann); err != nil {
			return 0, nil, fmt.Errorf("annotation %d: %w", index, err)
		}
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	existing := store.byCtx[ctxID]
	existingIDs := make(map[string]bool, len(existing))
	for _, id := range existing {
		existingIDs[id] = true
	}
	importedIDs := make(map[string]bool, len(document.Annotations))
	for _, ann := range document.Annotations {
		importedIDs[ann.ID] = true
	}
	overlaps := 0
	dropped := 0
	for id := range importedIDs {
		if existingIDs[id] {
			overlaps++
			if !overwrite {
				dropped++
			}
		}
	}
	if len(existing)+len(importedIDs)-overlaps > MaxAnnotationsPerContext {
		return 0, nil, ErrAnnotationLimit
	}
	conflicts = make([]string, 0, dropped)
	for _, ann := range document.Annotations {
		rewritten := ann
		rewritten.ContextID = ctxID
		if _, present := store.byID[rewritten.ID]; present {
			if !overwrite {
				conflicts = append(conflicts, rewritten.ID)
				continue
			}
			store.byID[rewritten.ID] = rewritten
			imported++
			continue
		}
		store.byID[rewritten.ID] = rewritten
		store.byCtx[ctxID] = append(store.byCtx[ctxID], rewritten.ID)
		imported++
	}
	store.sortByCtxLocked(ctxID)
	return imported, conflicts, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// Internals
// ----------------------------------------------------------------------------------------------------------------------

// insertLocked registers one annotation and keeps the context's newest-first
// list consistent. Callers must hold the store write lock.
func (store *AnnotationStore) insertLocked(ann Annotation) {
	store.byID[ann.ID] = ann
	store.byCtx[ann.ContextID] = append(store.byCtx[ann.ContextID], ann.ID)
}

// sortByCtxLocked re-sorts one context's ids by UpdatedAt, newest first.
func (store *AnnotationStore) sortByCtxLocked(ctxID string) {
	ids := store.byCtx[ctxID]
	sort.SliceStable(ids, func(i, j int) bool {
		return store.byID[ids[i]].UpdatedAt.After(store.byID[ids[j]].UpdatedAt)
	})
}

func validateAnnotation(ann *Annotation) error {
	ann.Title = strings.TrimSpace(ann.Title)
	if ann.Title == "" {
		return &ValidationError{Field: "title", Message: "title is required"}
	}
	if len(ann.Title) > maxAnnotationTitleChars {
		return &ValidationError{Field: "title", Message: fmt.Sprintf("title must be at most %d characters", maxAnnotationTitleChars)}
	}
	if len(ann.Text) > maxAnnotationTextChars {
		return &ValidationError{Field: "text", Message: fmt.Sprintf("text must be at most %d characters", maxAnnotationTextChars)}
	}
	if !contains(annotationKinds, ann.Kind) {
		return &ValidationError{Field: "kind", Message: fmt.Sprintf("kind must be one of %s", strings.Join(annotationKinds, ", "))}
	}
	if ann.Category != "" && !contains(annotationCategories, ann.Category) {
		return &ValidationError{Field: "category", Message: fmt.Sprintf("category must be one of %s", strings.Join(annotationCategories, ", "))}
	}
	if ann.Confidence != "" && !contains(annotationConfidences, ann.Confidence) {
		return &ValidationError{Field: "confidence", Message: fmt.Sprintf("confidence must be one of %s", strings.Join(annotationConfidences, ", "))}
	}
	if ann.Address != nil && ann.EndAddress != nil && *ann.EndAddress < *ann.Address {
		return &ValidationError{Field: "end_address", Message: "end_address must be >= address for a range annotation"}
	}
	if ann.EndAddress != nil && ann.Address == nil {
		return &ValidationError{Field: "end_address", Message: "end_address requires address"}
	}
	if ann.Length != nil && ann.Address == nil {
		return &ValidationError{Field: "length", Message: "length requires address"}
	}
	if ann.Address != nil && ann.EndAddress != nil && ann.Length != nil {
		if expected := *ann.EndAddress - *ann.Address + 1; *ann.Length != expected {
			return &ValidationError{Field: "length", Message: fmt.Sprintf("length must equal end_address-address+1 (%d)", expected)}
		}
	}
	return nil
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

// annotationMatchesFilter checks the non-staleness fields of one filter. A
// non-empty Tags filter requires every listed tag to be present.
func annotationMatchesFilter(ann Annotation, filter AnnotationFilter) bool {
	if len(filter.Tags) > 0 {
		for _, wanted := range filter.Tags {
			if !contains(ann.Tags, wanted) {
				return false
			}
		}
	}
	if filter.Category != "" && ann.Category != filter.Category {
		return false
	}
	if filter.Kind != "" && ann.Kind != filter.Kind {
		return false
	}
	if filter.AddressSpace != "" && ann.AddressSpace != filter.AddressSpace {
		return false
	}
	if query := strings.TrimSpace(strings.ToLower(filter.Query)); query != "" {
		haystacks := []string{strings.ToLower(ann.Title), strings.ToLower(ann.Text)}
		for _, tag := range ann.Tags {
			haystacks = append(haystacks, strings.ToLower(tag))
		}
		found := false
		for _, haystack := range haystacks {
			if strings.Contains(haystack, query) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// AnnotationIsStale reports whether one annotation no longer describes the
// loaded target: its ROM SHA-256 differs from the current identity or its
// target generation differs from the current generation.
func AnnotationIsStale(ann Annotation, current AnnotationTarget) bool {
	return ann.ROMSHA256 != current.ROMSHA256 || ann.TargetGeneration != current.Generation
}

func staleMatchesPolicy(stale bool, filter AnnotationFilter) bool {
	if filter.StaleOnly {
		return stale
	}
	if filter.IncludeStale {
		return true
	}
	return !stale
}

// AnnotationStaleReason names the axes on which an annotation diverged from
// the loaded target, joined with commas; empty when the annotation is fresh.
func AnnotationStaleReason(ann Annotation, current AnnotationTarget) string {
	reasons := make([]string, 0, 2)
	if ann.ROMSHA256 != current.ROMSHA256 {
		reasons = append(reasons, "rom_sha256_mismatch")
	}
	if ann.TargetGeneration != current.Generation {
		reasons = append(reasons, "target_generation_mismatch")
	}
	return strings.Join(reasons, ",")
}

// ----------------------------------------------------------------------------------------------------------------------
// Versioned export document
// ----------------------------------------------------------------------------------------------------------------------

// AnnotationExportSchema is the versioned JSON schema of exported annotation
// documents. Consumers compare it for equality; a future revision is a
// separate version, never a silent shape change.
const AnnotationExportSchema = "annotation-export/1"

// AnnotationExportDocument is the on-disk versioned export of one context's
// annotations. rom_identity describes the loaded target at export time; each
// annotation additionally carries its own creation-time ROM stamps.
type AnnotationExportDocument struct {
	SchemaVersion    string         `json:"schema_version"`
	ExportedAt       time.Time      `json:"exported_at"`
	ROMIdentity      map[string]any `json:"rom_identity"`
	TargetGeneration uint64         `json:"target_generation"`
	Annotations      []Annotation   `json:"annotations"`
}

// Marshal renders the versioned document as canonical JSON bytes.
func (document *AnnotationExportDocument) Marshal() ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("encode annotation export: %w", err)
	}
	return bytes.TrimSpace(buffer.Bytes()), nil
}
