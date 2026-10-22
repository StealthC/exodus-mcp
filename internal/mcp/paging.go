package mcp

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Paging for result sets (roadmap issue #11).
//
// Every list, search, and diff tool reports the same envelope:
//
//	{returned, total, truncated, has_more, next_cursor}
//
// so a consumer never has to guess whether a response is the whole answer, and
// every result set can be walked to exhaustion by passing next_cursor back as
// cursor instead of resending the request that produced it.
//
// A cursor is an opaque, versioned token that names a position in the
// underlying order, never an offset into a response array: array positions
// shift when entries are appended or evicted, which produced duplicate and
// skipped rows. Each family has its own prefix so a cursor issued by one tool
// is rejected by another instead of being misread, and each family anchors on
// the stable ordering key of its store (annotation created_at, audit
// operation_id, trace store_sequence, snapshot byte offset for searches and
// diffs; the last three are immutable once issued).

// cursorSeparator joins the fields of one decoded cursor. It cannot appear in
// an annotation id, a session id, or a hex number, so the split is unambiguous.
const cursorSeparator = "\x1f"

// cursor prefixes, one per cursor family.
const (
	searchCursorPrefix      = "ms1."
	diffCursorPrefix        = "md1."
	annotationCursorPrefix  = "an1."
	auditCursorPrefix       = "aud1."
	mutationCursorPrefix    = "mut1."
	traceEventsCursorPrefix = "te1."
)

// encodeCursor renders one versioned cursor from the given fields.
func encodeCursor(prefix string, fields ...string) string {
	return prefix + base64.RawURLEncoding.EncodeToString([]byte(strings.Join(fields, cursorSeparator)))
}

// decodeCursor parses one cursor of a family. A cursor from another family, a
// truncated token, or the wrong field count is rejected: silently ignoring it
// would restart the result set without saying so.
func decodeCursor(cursor, prefix string, fields int) ([]string, *toolFailure) {
	encoded, ok := strings.CutPrefix(cursor, prefix)
	if !ok {
		return nil, invalidCursorFailure(fmt.Sprintf("%q is not a cursor this tool issued", cursor))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, invalidCursorFailure(fmt.Sprintf("%q is not a cursor this server issued", cursor))
	}
	parts := strings.Split(string(decoded), cursorSeparator)
	if len(parts) != fields {
		return nil, invalidCursorFailure(fmt.Sprintf("%q is not a cursor this server issued", cursor))
	}
	return parts, nil
}

// invalidCursorFailure renders the structured rejection of a malformed or
// foreign cursor.
func invalidCursorFailure(message string) *toolFailure {
	return &toolFailure{
		Code:    "invalid_params",
		Message: "invalid cursor: " + message + "; omit cursor to start at the first page",
		Data:    map[string]any{"field": "cursor"},
	}
}

// pagingPage is the paging envelope computed for one response page.
type pagingPage struct {
	// Returned is the number of items in this response.
	Returned int
	// Total is the size of the whole result set the filters select, not just
	// the part this page reaches.
	Total int
	// Remaining is how many items the next cursor still reaches; it decides
	// HasMore. Negative means unknown and falls back to Total-Returned.
	Remaining int
	// NextCursor is the token that resumes after this page. It is empty
	// exactly when there is nothing left to read.
	NextCursor string
}

// hasMore reports whether another page exists.
func (page pagingPage) hasMore() bool {
	if page.NextCursor == "" {
		// A page whose cursor was not produced cannot be continued, so the
		// envelope must not claim more rows than a caller can retrieve.
		return false
	}
	remaining := page.Remaining
	if remaining < 0 {
		remaining = page.Total - page.Returned
	}
	return remaining > 0
}

// apply writes the envelope onto one response. truncated and has_more are the
// same fact stated once for humans and once for code: this page is not the
// whole result set.
func (page pagingPage) apply(result map[string]any) map[string]any {
	hasMore := page.hasMore()
	result["returned"] = page.Returned
	result["total"] = page.Total
	result["truncated"] = hasMore
	result["has_more"] = hasMore
	if hasMore {
		result["next_cursor"] = page.NextCursor
	} else {
		result["next_cursor"] = nil
	}
	return result
}

// pagingNote documents the envelope once, in the tool descriptions that return
// it, so a client learns the contract from the schema.
const pagingNote = "Reports the one paging envelope {returned, total, truncated, has_more, next_cursor} (next_cursor is null on the last page); total is the whole filtered result set and has_more/truncated say whether this page is only part of it."
