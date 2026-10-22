package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"strconv"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
)

func vdpToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "vdp_status",
			description: "Report Mega Drive VDP registers, decoded key fields, and image buffer geometry. Register state is read without pausing the system (system_paused_during_read is false).",
			schema:      objectSchema(map[string]any{}, nil),
			run:         runVdpStatus,
		},
		{
			name:        "vdp_memory_read",
			description: fmt.Sprintf("Read one VDP buffer (vram, cram, or vsram). output \"inline\" (default) returns at most %d bytes in the response with explicit byte-order metadata plus VDP-specific decoded views (big-endian words and CRAM 9-bit RGB entries); output \"artifact\" stores the range as a downloadable binary artifact and returns its descriptor, hash, size and URL, so a whole VRAM buffer never travels as Base64. Both paths report the standardized capture_consistency object (atomic when the timed-buffer read had to pause the system); optional capture_mode \"paused\" makes the sample temporally atomic. Inline length defaults to %d; an artifact length defaults to the whole buffer and is capped per buffer (vram 65536, cram 128, vsram 80 bytes).", inlineReadCapBytes, defaultVDPMemoryReadLen),
			schema: objectSchema(map[string]any{
				"output":         vdpOutputVocab.property("Delivery of the read: \"inline\" (default) returns the bytes in the response, \"artifact\" stores them as a downloadable binary artifact."),
				"target":         vdpBufferVocab.property("VDP memory buffer to read."),
				"address":        addressProperty(),
				"length":         integerProperty(fmt.Sprintf("Byte length between 1 and %d (default %d). Word views require an even address and length.", inlineReadCapBytes, defaultVDPMemoryReadLen), 1),
				"representation": vdpRepresentationVocab.property("Inline rendering."),
				"capture_mode":   captureModeProperty(),
				"context":        contextProperty(),
			}, []string{"target", "address"}),
			run: runVDPMemoryRead,
		},
		{
			name:        "vdp_sprite_table",
			description: "Decode the VDP sprite attribute table from VRAM: positions, size, tile mapping, palette, priority, link-chain order with cycle detection, and whether the read paused a running system (system_paused_during_read). Reports chain_visible_count (hardware-rendered link-chain length), table_entry_count (populated entries), and a warning when the chain renders fewer sprites than the table holds. Bounded paging over at most 80 entries. vdp_capture_id resolves a stored vdp_capture and decodes its captured VRAM and status components instead of reading the device: the response then reports data_source \"capture\", vdp_capture_reused true, the capture's frame token and capture_consistency. A capture without a usable VRAM component fails with capture_component_omitted; an unknown or foreign id fails with capture_not_found.",
			schema: objectSchema(map[string]any{
				"offset":         integerProperty("First sprite index to return (default 0, max 79).", 0),
				"count":          integerProperty(fmt.Sprintf("Entry count between 1 and %d (default %d). The link chain always covers the whole table.", vdpSpriteTableMaxEntries, defaultVDPSpritePage), 0),
				"vdp_capture_id": stringProperty("Optional capture_id from vdp_capture; when set, the table is decoded from the capture's stored VRAM and status components and no device read is performed."),
				"context":        contextProperty(),
			}, nil),
			run: runVDPSpriteTable,
		},
		{
			name:        "vdp_palette_export",
			description: "Export CRAM as four 16-color palette lines: a PNG swatch artifact, a JSON decode artifact, and a compact structural summary with capture consistency (system_paused_during_read).",
			schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
			run:         runVDPPaletteExport,
		},
		{
			name:        "vdp_tile_export",
			description: "Export one or more consecutive 8x8 4bpp VRAM patterns (tiles) as a scaled PNG artifact plus a JSON pixel-decode artifact, colored through a chosen CRAM palette line. Reports whether any read paused a running system (system_paused_during_read) and coherent_snapshot. vdp_capture_id resolves a stored vdp_capture and renders from its captured VRAM and CRAM components instead of reading the device, so repeated inspection is byte-identical and performs no read: the response then reports data_source \"capture\", vdp_capture_reused true, the capture's frame token, and source_capture_id. A capture without a covering VRAM or CRAM component fails with capture_component_omitted; an unknown or foreign id fails with capture_not_found.",
			schema: objectSchema(map[string]any{
				"crop":             renderCropSchemaProperty(),
				"tile":             integerProperty("First tile index counted from VRAM offset 0 (default 0). Each tile occupies 32 bytes.", 0),
				"count":            integerProperty(fmt.Sprintf("Consecutive tile count between 1 and %d (default 1).", maxVDPTileStripCount), 1),
				"palette":          integerProperty("CRAM palette line 0-3 used to color pixel indices 1-15 (default 0).", 0),
				"scale":            integerProperty("Nearest-neighbor upscale factor 1-32 (default 8).", 1),
				"transparent_zero": booleanProperty("Render pixel index 0 as transparent instead of its palette color (default true)."),
				"vdp_capture_id":   stringProperty("Optional capture_id from vdp_capture; when set, the tiles come from the capture's stored VRAM and CRAM components and no device read is performed."),
				"context":          contextProperty(),
			}, nil),
			run: aliasRun("vdp_tile_export", runVDPTileExport),
		},
		{
			name:        "vdp_plane_export",
			description: "Render a full scroll plane (A, B, or window) from VRAM as an unscrolled texture view: scaled PNG artifact plus JSON structural summary with distinct tiles, priority counts, and capture consistency (system_paused_during_read / coherent_snapshot). vdp_capture_id resolves a stored vdp_capture and renders from its captured VRAM, CRAM, and status components instead of reading the device: the response then reports data_source \"capture\" and vdp_capture_reused true. A capture whose VRAM component does not cover the whole buffer fails with capture_component_omitted; an unknown or foreign id fails with capture_not_found.",
			schema: objectSchema(map[string]any{
				"crop":             renderCropSchemaProperty(),
				"plane":            vdpPlaneVocab.property("Which name table to render."),
				"scale":            integerProperty("Nearest-neighbor upscale factor 1-4 (default 1).", 1),
				"transparent_zero": booleanProperty("Render pixel index 0 as transparent instead of its palette color (default true)."),
				"vdp_capture_id":   stringProperty("Optional capture_id from vdp_capture; when set, the plane comes from the capture's stored VRAM, CRAM, and status components and no device read is performed."),
				"context":          contextProperty(),
			}, nil),
			run: aliasRun("vdp_plane_export", runVDPPlaneExport),
		},
		{
			name:        "vdp_pixel_info",
			description: "Report per-pixel rendering attribution for one completed-frame coordinate: source layer, name-entry mapping, palette entry, shadow/highlight state, and sprite cell data. Enables full image buffer info lazily; if attribution is not ready yet the call fails with pixel_info_pending and must be retried after one rendered frame. This tool cannot reuse a vdp_capture: attribution exists only for the frame the VDP just completed and the bridge answers it one coordinate at a time, so a supplied vdp_capture_id fails with capture_component_omitted naming pixel_attribution instead of silently reading live.",
			schema: objectSchema(map[string]any{
				"x":              integerProperty("Pixel X within the completed frame buffer, including border and blanking regions.", 0),
				"y":              integerProperty("Pixel Y within the completed frame buffer.", 0),
				"vdp_capture_id": stringProperty("Rejected: per-pixel attribution cannot be stored in a capture. Supplying an id fails with capture_component_omitted; omit it to read the live frame buffer."),
				"context":        contextProperty(),
			}, []string{"x", "y"}),
			run: runVDPPixelInfo,
		},
		{
			name:        "frame_capture",
			description: "Capture the current rendered VDP frame as a PNG image artifact. The frame buffer is read without pausing the system, so system_paused_during_read is always false and capture_consistency.state is live (the frame token identifies the rendered frame). Optional capture_mode \"paused\" pauses once before the capture and restores the prior run state, making the frame match a temporally atomic instant.",
			schema:      objectSchema(map[string]any{"capture_mode": captureModeProperty(), "context": contextProperty()}, nil),
			run:         runFrameCapture,
		},
		{
			name:        "vdp_capture",
			description: "Atomic VDP capture: acquire the capture guard once, obtain VDP registers/status, frame buffer, CRAM, VSRAM, and the VRAM range the sprite and plane readers need, then restore prior run state. Returns a manifest plus linked artifacts sharing one capture_id and frame_token. The stored components are what vdp_sprite_table, vdp_tile_export, and vdp_plane_export consume when they are given this capture_id, so reuse is byte-identical and needs no device read (vdp_pixel_info cannot reuse a capture: per-pixel attribution exists only for the live frame). Callers can select components (include_frame, include_cram, include_vsram, include_vram, include_sprite_table); VRAM defaults to on because the other readers depend on it, and caps are documented. Omitted components are marked omitted in the manifest and in capture_get. All artifacts share one capture_id; when the composition is composite_non_atomic the pieces may come from different frames and must not be combined. The capture is artifact-first; resolve the id later with capture_get or artifact_list{capture_id}.",
			schema: objectSchema(map[string]any{
				"include_frame":        booleanProperty("Include the rendered frame PNG (default true)."),
				"include_cram":         booleanProperty("Include CRAM (default true)."),
				"include_vsram":        booleanProperty("Include VSRAM (default true)."),
				"include_vram":         booleanProperty("Include the VRAM range (default true: vdp_sprite_table, vdp_tile_export, and vdp_plane_export read it from the capture; false makes those reuse attempts fail with capture_component_omitted)."),
				"vram_address":         addressProperty(),
				"vram_length":          integerProperty("VRAM bytes to capture when include_vram is true (default 65536, cap 131072).", 1),
				"include_sprite_table": booleanProperty("Record that the sprite table is available through the VRAM component (default true)."),
				"capture_mode":         captureModeProperty(),
				"context":              contextProperty(),
			}, nil),
			run: runVDPCapture,
		},
	}
}

func runVdpStatus(tc toolContext, args json.RawMessage) map[string]any {
	if _, failure := decodeArgs[noArgs](args); failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(payload, tc.modern)
}

// defaultVDPMemoryReadLen keeps casual register-adjacent peeks small while
// still covering a full CRAM or a meaningful VSRAM window in one call.
const defaultVDPMemoryReadLen = 128

// vdpSpriteTableMaxEntries is the hardware maximum across H32 (64) and H40
// (80) modes; link fields may address up to 127 but entries beyond this bound
// are not part of any real sprite table.
const vdpSpriteTableMaxEntries = 80

// vdpOutputVocab is the closed delivery vocabulary of vdp_memory_read: inline
// bytes rendered in the response, or one downloadable binary artifact.
var vdpOutputVocab = newEnumVocab("output", "inline", "artifact")

type vdpMemoryReadArgs struct {
	Output         string `json:"output"`
	Target         string `json:"target"`
	Address        any    `json:"address"`
	AddressSpace   string `json:"address_space"`
	Length         uint64 `json:"length"`
	Representation string `json:"representation"`
	CaptureMode    string `json:"capture_mode"`
	Context        string `json:"context"`
}

// vdpMemoryReadValue reads one VDP buffer through the plugin's timed-buffer
// ReadLatest path and renders it inline, attaching the standardized
// capture_consistency object. The bridge returns raw bytes; all multi-byte
// decoding happens here so every view can carry explicit byte-order metadata.
func vdpMemoryReadValue(tc toolContext, target string, address uint64, length uint64, representation string, window *captureWindow) (map[string]any, *toolFailure) {
	wordView := representation == "array_u16" || representation == "cram_rgb333"
	if wordView && (address%2 != 0 || length%2 != 0) {
		return nil, &toolFailure{
			Code:    "unaligned_request",
			Message: fmt.Sprintf("%s reads whole 2-byte entries; address and length must both be even.", representation),
		}
	}
	if representation == "cram_rgb333" && target != "cram" {
		return nil, &toolFailure{Code: "invalid_params", Message: "cram_rgb333 is only valid with target cram"}
	}
	if !wordView {
		switch representation {
		case "hexdump", "array_u8", "raw_base64":
		default:
			return nil, &toolFailure{Code: "invalid_params", Message: "representation must be hexdump, array_u8, raw_base64, array_u16, or cram_rgb333"}
		}
	}

	payload, failure := tc.server.executeCommand(tc.ctx, "vdp_mem_read", map[string]string{
		"target":  target,
		"address": strconv.FormatUint(address, 10),
		"length":  strconv.FormatUint(length, 10),
	})
	if failure != nil {
		return nil, failure
	}
	rawDataBase64, _ := payload["data"].(string)
	byteOrder, _ := payload["byte_order"].(string)
	addressSpace, _ := payload["address_space"].(string)
	entrySize, _ := payload["entry_size"].(float64)
	bufferSize, _ := payload["buffer_size"].(float64)
	// The bridge reports whether the read had to stop a running system;
	// surfacing it lets callers judge snapshot coherence.
	pausedDuringRead, _ := payload["system_paused_during_read"].(bool)
	raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return nil, &toolFailure{Code: "bridge_error", Message: "decode base64 vdp memory payload: " + err.Error()}
	}

	value := map[string]any{
		"target":                    target,
		"address_space":             addressSpace,
		"address":                   address,
		"address_hex":               canonicalHex(address),
		"length":                    len(raw),
		"buffer_size":               uint64(bufferSize),
		"entry_size":                uint64(entrySize),
		"byte_order":                byteOrder,
		"representation":            representation,
		"representation_note":       representationNote(representation),
		"system_paused_during_read": pausedDuringRead,
		"capture_consistency":       tc.server.captureConsistencyViewWindow(window, window.consistencyFor(tc.server, payload)),
	}
	annotateAddressPair(value, addressSpace, address)
	switch representation {
	case "hexdump":
		value["hex"] = artifact.HexDump(raw, int64(address))
	case "array_u8":
		values := make([]int, 0, len(raw))
		for _, single := range raw {
			values = append(values, int(single))
		}
		value["values"] = values
	case "raw_base64":
		value["data_base64"] = base64.StdEncoding.EncodeToString(raw)
	case "array_u16":
		value["values"] = bigEndianWords(raw)
	default:
		value["entries"] = cramRGB333Entries(raw)
	}
	return value, nil
}

// runVDPMemoryRead renders one VDP buffer read, honoring the optional capture
// guard ("paused" makes the timed-buffer sample temporally atomic).
func runVDPMemoryRead(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpMemoryReadArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	output, failure := vdpOutputVocab.resolve(parsed.Output, "inline")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if output == "artifact" {
		// The artifact path owns its own length contract (default: the whole
		// buffer, per-buffer caps), so an inline representation has nothing to
		// render and is rejected rather than dropped.
		if parsed.Representation != "" {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "representation applies only to output \"inline\"; output \"artifact\" returns raw bytes as a downloadable artifact"}, tc.modern)
		}
		payload, failure := composeTool(tc, runVDPMemoryExport, map[string]any{
			"target":        parsed.Target,
			"address":       parsed.Address,
			"address_space": parsed.AddressSpace,
			"length":        parsed.Length,
			"capture_mode":  parsed.CaptureMode,
			"context":       parsed.Context,
		})
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		payload["output"] = output
		return okResult(payload, tc.modern)
	}
	if _, failure = resolveContext(tc.server, parsed.Context); failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := resolveAddress(parsed.Address, addressSpaceFromArgs(args), "mem-vdp-"+parsed.Target)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	length := parsed.Length
	if length == 0 {
		length = defaultVDPMemoryReadLen
	}
	if length < 1 || length > inlineReadCapBytes {
		return failureResult(&toolFailure{
			Code:    "length_exceeds_inline_cap",
			Message: fmt.Sprintf("vdp_memory_read length must be between 1 and %d bytes.", inlineReadCapBytes),
			Data:    map[string]any{"inline_cap_bytes": inlineReadCapBytes},
		}, tc.modern)
	}
	if failure := vdpBufferVocab.validate(parsed.Target); failure != nil {
		return failureResult(failure, tc.modern)
	}
	representation, failure := vdpRepresentationVocab.resolve(parsed.Representation, "hexdump")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	guard := captureGuard{Mode: parsed.CaptureMode}
	if failure = guard.resolve(); failure != nil {
		return failureResult(failure, tc.modern)
	}
	result := withCaptureGuard(tc, guard, func(window *captureWindow) (map[string]any, *toolFailure) {
		return vdpMemoryReadValue(tc, parsed.Target, address, length, representation, window)
	})
	return patchPayloadField(result, "output", output)
}

func representationNote(representation string) string {
	switch representation {
	case "array_u16":
		return "16-bit words assembled from big-endian byte pairs at consecutive even offsets."
	case "cram_rgb333":
		return "CRAM entries pack 9-bit RGB as -RRR-GGG-BBB- (channels at bits 1-3, 5-7, 9-11); each channel scales to 8-bit by (c*255+3)/7."
	default:
		return "Raw buffer bytes preserve address order."
	}
}

func bigEndianWords(raw []byte) []int {
	values := make([]int, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		values = append(values, int(raw[i])<<8|int(raw[i+1]))
	}
	return values
}

func cramRGB333Entries(raw []byte) []map[string]any {
	count := len(raw) / 2
	entries := make([]map[string]any, 0, count)
	for index := 0; index < count; index++ {
		word := int(raw[index*2])<<8 | int(raw[index*2+1])
		// Mega Drive CRAM words pack 9-bit RGB with a zero padding bit below
		// each channel: -RRR-GGG-BBB- occupies bits 1-3, 5-7, and 9-11.
		r9 := (word >> 1) & 0x0007
		g9 := (word >> 5) & 0x0007
		b9 := (word >> 9) & 0x0007
		r := (r9*255 + 3) / 7
		g := (g9*255 + 3) / 7
		b := (b9*255 + 3) / 7
		entries = append(entries, map[string]any{
			"index":     index,
			"word":      word,
			"r":         r,
			"g":         g,
			"b":         b,
			"nine_bit":  [3]int{r9, g9, b9},
			"color_hex": fmt.Sprintf("#%02X%02X%02X", r, g, b),
		})
	}
	return entries
}

type frameCaptureArgs struct {
	CaptureMode string `json:"capture_mode"`
	Context     string `json:"context"`
}

// frameCaptureValue fetches the live rendered frame and stores the PNG
// artifact, honoring the optional capture guard. The raw pixel payload never
// reaches model context; the response is a compact summary plus the artifact
// descriptor.
func frameCaptureValue(tc toolContext, context *analysis.Context, window *captureWindow) (map[string]any, *toolFailure) {
	_, value, failure := captureFrameArtifact(tc, context, window, "")
	return value, failure
}

// captureFrameArtifact stores the rendered frame and also returns the stored
// artifact so a composite capture can index it as one of its components.
// captureID, when set, links the frame artifact to the composite capture.
func captureFrameArtifact(tc toolContext, context *analysis.Context, window *captureWindow, captureID string) (artifact.Artifact, map[string]any, *toolFailure) {
	payload, failure := tc.server.executeCommand(tc.ctx, "frame_capture", nil)
	if failure != nil {
		return artifact.Artifact{}, nil, failure
	}

	rawDataBase64, _ := payload["data"].(string)
	rawRGB, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return artifact.Artifact{}, nil, &toolFailure{Code: "bridge_error", Message: "decode base64 frame payload: " + err.Error()}
	}
	widthValue, _ := payload["width"].(float64)
	heightValue, _ := payload["height"].(float64)
	width := int(widthValue)
	height := int(heightValue)
	if width <= 0 || height <= 0 || len(rawRGB) != width*height*3 {
		return artifact.Artifact{}, nil, &toolFailure{
			Code:    "bridge_error",
			Message: fmt.Sprintf("frame payload does not match declared dimensions (%dx%d, %d bytes).", width, height, len(rawRGB)),
		}
	}

	frame, err := rgb24ToNRGBA(rawRGB, width, height)
	if err != nil {
		return artifact.Artifact{}, nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	var pngBuffer bytes.Buffer
	if err := png.Encode(&pngBuffer, frame); err != nil {
		return artifact.Artifact{}, nil, &toolFailure{Code: "artifact_error", Message: "encode PNG: " + err.Error()}
	}
	frameToken, _ := payload["frame_token"].(float64)
	provenance := vdpProvenance(tc, "frame-capture", "vdp-buffers", "VDP frame buffer")
	token := uint64(frameToken)
	if token != 0 {
		provenance.FrameToken = &token
	}
	provenance.ByteOrder = "not-applicable"
	if captureID != "" {
		provenance.CaptureID = captureID
	}
	// One consistency object for the frame artifact and the response. Inside a
	// paused capture window the window owns it, so the artifact cannot claim a
	// live sample while the response reports an atomic one.
	consistencyObject := newCaptureConsistency(tc.server, consistencyLive, "The frame buffer is sampled as one rendered frame under the VDP's own lock; the frame token identifies it. The handler never pauses the system.")
	if window != nil && window.Consistency != nil {
		consistencyObject = window.Consistency
	}
	provenance.CaptureConsistency = consistencyObject
	stored, err := tc.server.store.PutWithProvenance(context.ID, "frame-capture", "image/png", pngBuffer.Bytes(), provenance)
	if err != nil {
		return artifact.Artifact{}, nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	window.track(stored)
	return stored, map[string]any{
		"summary": map[string]any{
			"kind":                      "frame-capture",
			"width":                     width,
			"height":                    height,
			"source_format":             "rgb24",
			"byte_order":                "not-applicable",
			"frame_token":               token,
			"system_paused_during_read": false,
			"capture_consistency":       tc.server.captureConsistencyViewWindow(window, consistencyObject),
			"png_size_bytes":            pngBuffer.Len(),
			"sha256":                    stored.SHA256,
		},
		"artifact": artifactDescriptor(tc.server, stored, context.ID),
	}, nil
}

// runFrameCapture renders one frame capture, honoring the optional capture
// guard ("paused" makes the frame match a temporally atomic instant).
func runFrameCapture(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[frameCaptureArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	guard := captureGuard{Mode: parsed.CaptureMode}
	if failure = guard.resolve(); failure != nil {
		return failureResult(failure, tc.modern)
	}
	return withCaptureGuard(tc, guard, func(window *captureWindow) (map[string]any, *toolFailure) {
		return frameCaptureValue(tc, context, window)
	})
}

type vdpCaptureArgs struct {
	IncludeFrame       *bool  `json:"include_frame"`
	IncludeCRAM        *bool  `json:"include_cram"`
	IncludeVSRAM       *bool  `json:"include_vsram"`
	IncludeVRAM        *bool  `json:"include_vram"`
	VRAMAddress        any    `json:"vram_address"`
	AddressSpace       string `json:"address_space"`
	VRAMLength         uint64 `json:"vram_length"`
	IncludeSpriteTable *bool  `json:"include_sprite_table"`
	CaptureMode        string `json:"capture_mode"`
	Context            string `json:"context"`
}

func runVDPCapture(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpCaptureArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	includeFrame := parsed.IncludeFrame == nil || *parsed.IncludeFrame
	includeCRAM := parsed.IncludeCRAM == nil || *parsed.IncludeCRAM
	includeVSRAM := parsed.IncludeVSRAM == nil || *parsed.IncludeVSRAM
	includeVRAM := parsed.IncludeVRAM == nil || *parsed.IncludeVRAM
	includeSprite := parsed.IncludeSpriteTable == nil || *parsed.IncludeSpriteTable
	vramAddr := uint64(0)
	if parsed.VRAMAddress != nil {
		vramAddr, failure = resolveAddress(parsed.VRAMAddress, addressSpaceFromArgs(args), "mem-vdp-vram")
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
	}
	vramLen := parsed.VRAMLength
	if vramLen == 0 {
		vramLen = 65536
	}
	if vramLen > 131072 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "vram_length capped at 131072"}, tc.modern)
	}
	guard := captureGuard{Mode: parsed.CaptureMode}
	if failure = guard.resolve(); failure != nil {
		return failureResult(failure, tc.modern)
	}
	return withCaptureGuard(tc, guard, func(window *captureWindow) (map[string]any, *toolFailure) {
		return vdpCaptureValue(tc, context, includeFrame, includeCRAM, includeVSRAM, includeVRAM, vramAddr, vramLen, includeSprite, window)
	})
}

func vdpCaptureValue(tc toolContext, context *analysis.Context, includeFrame, includeCRAM, includeVSRAM, includeVRAM bool, vramAddr, vramLen uint64, includeSprite bool, window *captureWindow) (map[string]any, *toolFailure) {
	captureID := newCaptureID()
	capturedAt := time.Now().UTC()
	// One consistency object for the whole composite: a paused capture window
	// owns it (the guard completes it after the restore), otherwise it is the
	// live sample this composite actually is.
	consistency := window.consistencyFor(tc.server, map[string]any{"system_paused_during_read": false})
	provenanceBase := genericProvenance(tc.server, "vdp-capture", capturedAt)
	provenanceBase.CaptureID = captureID
	provenanceBase.CaptureConsistency = consistency

	manifest := map[string]any{
		"kind":                "vdp-capture",
		"capture_id":          captureID,
		"captured_at":         capturedAt,
		"capture_consistency": tc.server.captureConsistencyView(consistency),
		"components":          map[string]any{},
		"artifacts":           []map[string]any{},
	}
	var artifacts []map[string]any
	var captureComponents []artifact.CaptureComponent
	var captureFrameToken *uint64
	// Helper to add artifact to manifest
	addArtifact := func(kind string, stored artifact.Artifact) {
		window.track(stored)
		desc := artifactDescriptor(tc.server, stored, context.ID)
		artifacts = append(artifacts, desc)
		manifest["components"].(map[string]any)[kind] = desc
		captureComponents = append(captureComponents, captureComponentFromProvenance(kind, stored))
	}
	// VDP status/registers
	statusPayload, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
	if failure != nil {
		return nil, failure
	}
	statusProvenance := vdpProvenanceWithCapture(tc, "vdp-status", "vdp-buffers", "VDP", captureID, consistency)
	storedStatus, _ := putJSONArtifact(tc.server, context.ID, "vdp-status", statusPayload, statusProvenance)
	addArtifact("vdp_status", storedStatus)
	manifest["vdp_status"] = statusPayload
	// The capture identifies one rendered frame whether or not the frame PNG was
	// requested; the token comes from the captured status.
	if imageBuffer, ok := statusPayload["image_buffer"].(map[string]any); ok {
		if token, ok := imageBuffer["last_rendered_frame_token"].(float64); ok && uint64(token) != 0 {
			rendered := uint64(token)
			captureFrameToken = &rendered
		}
	}

	// Frame buffer
	if includeFrame {
		frameStored, frameResult, failure := captureFrameArtifact(tc, context, window, captureID)
		if failure == nil {
			captureComponents = append(captureComponents, captureComponentFromProvenance("frame", frameStored))
			if summary, ok := frameResult["summary"].(map[string]any); ok {
				if token, ok := summary["frame_token"].(uint64); ok && token != 0 {
					captureFrameToken = &token
				}
			}
			if art, ok := frameResult["artifact"].(map[string]any); ok {
				artifacts = append(artifacts, art)
				manifest["components"].(map[string]any)["frame"] = art
			}
		}
	} else {
		manifest["components"].(map[string]any)["frame"] = map[string]any{"omitted": true, "reason": "include_frame=false"}
		captureComponents = append(captureComponents, omittedCaptureComponent("frame", true, false, "include_frame=false"))
	}

	// CRAM
	if includeCRAM {
		cramRaw, _, failure := fetchVDPBytes(tc, "cram", 0, 128)
		if failure == nil {
			cramProvenance := vdpProvenanceWithCapture(tc, "vdp-cram", "mem-vdp-cram", "VDP CRAM", captureID, consistency)
			cramLength := uint64(len(cramRaw))
			cramProvenance.ByteLength = &cramLength
			storedCRAM, _ := tc.server.store.PutWithProvenance(context.ID, "vdp-cram", "application/octet-stream", cramRaw, cramProvenance)
			addArtifact("cram", storedCRAM)
		}
	} else {
		manifest["components"].(map[string]any)["cram"] = map[string]any{"omitted": true}
		captureComponents = append(captureComponents, omittedCaptureComponent("cram", true, false, "include_cram=false"))
	}

	// VSRAM
	if includeVSRAM {
		vsramRaw, _, failure := fetchVDPBytes(tc, "vsram", 0, 80)
		if failure == nil {
			vsramProvenance := vdpProvenanceWithCapture(tc, "vdp-vsram", "mem-vdp-vsram", "VDP VSRAM", captureID, consistency)
			vsramLength := uint64(len(vsramRaw))
			vsramProvenance.ByteLength = &vsramLength
			storedVSRAM, _ := tc.server.store.PutWithProvenance(context.ID, "vdp-vsram", "application/octet-stream", vsramRaw, vsramProvenance)
			addArtifact("vsram", storedVSRAM)
		}
	} else {
		manifest["components"].(map[string]any)["vsram"] = map[string]any{"omitted": true}
		captureComponents = append(captureComponents, omittedCaptureComponent("vsram", true, false, "include_vsram=false"))
	}

	// VRAM range
	if includeVRAM {
		vramRaw, _, failure := fetchVDPBytesChunked(tc, "vram", vramAddr, vramLen)
		if failure == nil {
			vramProvenance := vdpProvenanceWithCapture(tc, "vdp-vram", "mem-vdp-vram", "VDP VRAM", captureID, consistency)
			vramProvenance.StartAddress = &vramAddr
			vramProvenance.StartAddressHex = canonicalHex(vramAddr)
			vramProvenance.EffectiveAddress = &vramAddr
			vramProvenance.EffectiveAddressHex = canonicalHex(vramAddr)
			length := uint64(len(vramRaw))
			vramProvenance.ByteLength = &length
			storedVRAM, _ := tc.server.store.PutWithProvenance(context.ID, "vdp-vram", "application/octet-stream", vramRaw, vramProvenance)
			addArtifact("vram", storedVRAM)
		}
	} else {
		manifest["components"].(map[string]any)["vram"] = map[string]any{"omitted": true, "reason": "include_vram=false (expensive, capped at 131072)"}
		captureComponents = append(captureComponents, omittedCaptureComponent("vram", true, false, "include_vram=false"))
	}

	// Sprite table
	switch {
	case !includeSprite:
		manifest["components"].(map[string]any)["sprite_table"] = map[string]any{"omitted": true}
		captureComponents = append(captureComponents, omittedCaptureComponent("sprite_table", true, false, "include_sprite_table=false"))
	case !includeVRAM:
		// The table lives in VRAM: without the VRAM component there is nothing to
		// decode from, so the manifest says that instead of claiming the table.
		reason := "the sprite table lives in the VRAM component and include_vram=false"
		manifest["components"].(map[string]any)["sprite_table"] = map[string]any{"unavailable": true, "reason": reason}
		captureComponents = append(captureComponents, omittedCaptureComponent("sprite_table", false, true, reason))
	default:
		// The stored VRAM component is what a later vdp_sprite_table reads, so
		// this component records where the data lives instead of claiming a
		// separate table read.
		manifest["components"].(map[string]any)["sprite_table"] = map[string]any{"included": true, "source": "vram", "note": "The sprite table is part of the captured VRAM component; decode it with vdp_sprite_table using this capture id."}
	}

	// Render manifest (simplified)
	renderManifest := map[string]any{
		"kind":             "vdp-render-manifest",
		"capture_id":       captureID,
		"display_geometry": map[string]any{"note": "Derived from vdp_status registers; see vdp_status artifact for details"},
		"palette_state":    map[string]any{"note": "CRAM artifact holds palette; decoded via vdp_palette_export"},
		"sprite_state":     map[string]any{"note": "Sprite table artifact holds link chain; see vdp_sprite_table"},
		"scroll_state":     map[string]any{"note": "VSRAM and hscroll data in vsram artifact"},
	}
	renderProvenance := vdpProvenanceWithCapture(tc, "vdp-render-manifest", "vdp-buffers", "VDP", captureID, consistency)
	storedRender, _ := putJSONArtifact(tc.server, context.ID, "vdp-render-manifest", renderManifest, renderProvenance)
	addArtifact("render_manifest", storedRender)

	// The manifest links every component artifact, so it must describe the
	// window as it ended, not as it stood while the components were read.
	// Publication therefore happens after the guard closed the window.
	window.publish = func() (map[string]any, *toolFailure) {
		view := tc.server.captureConsistencyViewWindow(window, consistency)
		manifest["artifacts"] = artifacts
		manifest["artifact_count"] = len(artifacts)
		manifest["capture_consistency"] = view
		restampCaptureProvenance(manifest, view, consistency.State)
		manifestProvenance := genericProvenance(tc.server, "vdp-capture-manifest", capturedAt)
		manifestProvenance.CaptureID = captureID
		manifestProvenance.CaptureConsistency = consistency
		storedManifest, err := putJSONArtifact(tc.server, context.ID, "vdp-capture-manifest", manifest, manifestProvenance)
		if err != nil {
			return nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
		}
		artifacts = append(artifacts, artifactDescriptor(tc.server, storedManifest, context.ID))
		// The manifest and every component artifact now exist: index the capture
		// so capture_get resolves it and the VDP readers can consume the stored
		// components instead of reading the device again.
		generation := tc.server.target.Generation()
		if failure := registerCapture(tc.server.store, artifact.Capture{
			CaptureID:        captureID,
			ContextID:        context.ID,
			ProducerTool:     "vdp_capture",
			ManifestArtifact: storedManifest.ID,
			Components:       captureComponents,
			FrameToken:       captureFrameToken,
			TargetGeneration: &generation,
			CreatedAt:        capturedAt,
		}); failure != nil {
			return nil, failure
		}
		return map[string]any{
			"summary": map[string]any{
				"kind":                "vdp-capture",
				"capture_id":          captureID,
				"capture_consistency": view,
				"components_included": map[string]bool{"frame": includeFrame, "cram": includeCRAM, "vsram": includeVSRAM, "vram": includeVRAM, "sprite_table": includeSprite},
				"artifact_count":      len(artifacts),
				"manifest_sha256":     storedManifest.SHA256,
			},
			"manifest":  artifactDescriptor(tc.server, storedManifest, context.ID),
			"artifacts": artifacts,
		}, nil
	}
	return nil, nil
}

func rgb24ToNRGBA(raw []byte, width, height int) (*image.NRGBA, error) {
	frame := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		rowStart := y * frame.Stride
		sourceRow := y * width * 3
		for x := 0; x < width; x++ {
			offset := rowStart + x*4
			sourceOffset := sourceRow + x*3
			frame.Pix[offset+0] = raw[sourceOffset+0]
			frame.Pix[offset+1] = raw[sourceOffset+1]
			frame.Pix[offset+2] = raw[sourceOffset+2]
			frame.Pix[offset+3] = 0xFF
		}
	}
	return frame, nil
}

const defaultVDPSpritePage = 16

type vdpSpriteTableArgs struct {
	Offset       uint64 `json:"offset"`
	Count        uint64 `json:"count"`
	VDPCaptureID string `json:"vdp_capture_id"`
	Context      string `json:"context"`
}

type spriteEntry struct {
	Index       int  `json:"index"`
	YRaw        int  `json:"y_raw"`
	ScreenY     int  `json:"screen_y"`
	WidthCells  int  `json:"width_cells"`
	HeightCells int  `json:"height_cells"`
	Link        int  `json:"link"`
	Tile        int  `json:"tile"`
	HFlip       bool `json:"hflip"`
	VFlip       bool `json:"vflip"`
	Palette     int  `json:"palette"`
	Priority    bool `json:"priority"`
	XRaw        int  `json:"x_raw"`
	ScreenX     int  `json:"screen_x"`
}

// fetchVDPBytes reads raw bytes through the plugin timed-buffer path and
// reports whether the read temporarily paused a running system (the plugin
// stops and restores when the buffer's worker threads would otherwise race).
func fetchVDPBytes(tc toolContext, target string, address uint64, length uint64) ([]byte, bool, *toolFailure) {
	payload, failure := tc.server.executeCommand(tc.ctx, "vdp_mem_read", map[string]string{
		"target":  target,
		"address": strconv.FormatUint(address, 10),
		"length":  strconv.FormatUint(length, 10),
	})
	if failure != nil {
		return nil, false, failure
	}
	rawDataBase64, _ := payload["data"].(string)
	raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return nil, false, &toolFailure{Code: "bridge_error", Message: "decode base64 vdp payload: " + err.Error()}
	}
	pausedDuringRead, _ := payload["system_paused_during_read"].(bool)
	return raw, pausedDuringRead, nil
}

// fetchVRAMSize resolves the active VRAM byte size from the status payload so
// sprite-table reads can clamp against extended VRAM configurations.
func fetchVRAMSize(status map[string]any) uint64 {
	const standard = uint64(65536)
	const extended = uint64(131072)
	size := standard
	if decoded, ok := status["decoded"].(map[string]any); ok {
		if extendedFlag, ok := decoded["extended_vram"].(bool); ok && extendedFlag {
			size = extended
		}
	}
	return size
}

func runVDPSpriteTable(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpSpriteTableArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	offset := parsed.Offset
	count := parsed.Count
	if count == 0 {
		count = defaultVDPSpritePage
	}
	if offset >= vdpSpriteTableMaxEntries || count > vdpSpriteTableMaxEntries || offset+count > vdpSpriteTableMaxEntries {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("sprite paging must satisfy offset+count <= %d.", vdpSpriteTableMaxEntries),
			Data:    map[string]any{"max_entries": vdpSpriteTableMaxEntries},
		}, tc.modern)
	}

	// A supplied capture replaces the VDP status read and the VRAM read with the
	// stored components; an unusable one fails instead of reading the device.
	source := captureReuseOf("", nil)
	var statusPayload map[string]any
	if parsed.VDPCaptureID != "" {
		captureData, failure := resolveVDPCapture(tc, context.ID, parsed.VDPCaptureID)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		capturedStatus, failure := captureData.statusView(tc, context.ID)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		source = captureReuseOf(parsed.VDPCaptureID, captureData)
		statusPayload = capturedStatus
	} else {
		liveStatus, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		statusPayload = liveStatus
	}
	baseValue, _ := statusPayload["decoded"].(map[string]any)["name_table_base_sprite"].(float64)
	base := uint64(baseValue)
	vramSize := fetchVRAMSize(statusPayload)

	// Fetch the whole table so the link chain is always globally accurate;
	// only the returned window honors the paging arguments.
	fetchCount := vdpSpriteTableMaxEntries
	if remaining := (vramSize - base) / 8; remaining < uint64(fetchCount) {
		fetchCount = int(remaining)
	}
	var raw []byte
	pausedDuringRead := false
	if source.unused {
		raw, pausedDuringRead, failure = fetchVDPBytes(tc, "vram", base, uint64(fetchCount)*8)
	} else {
		raw, failure = source.data.vramRange(tc, context.ID, base, uint64(fetchCount)*8)
	}
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	all := parseSpriteEntries(raw)

	windowEnd := int(offset + count)
	if windowEnd > len(all) {
		windowEnd = len(all)
	}
	window := all[offset:windowEnd]
	chain := walkLinkChain(all, vdpSpriteTableMaxEntries)
	chainVisible, _ := chain["length"].(int)
	tableEntryCount := populatedSpriteEntryCount(all)

	// The hardware renders exactly the link-chain entries; a table with more
	// populated entries than visible chain entries means the links were
	// mid-update or stale relative to the rendered frame.
	warning := ""
	if tableEntryCount > chainVisible {
		warning = fmt.Sprintf("link chain renders %d of %d entries; verify against the rendered frame (system may have been mid-update)", chainVisible, tableEntryCount)
	}

	consistency := buildCaptureConsistency(tc.server, map[string]any{"system_paused_during_read": pausedDuringRead}, false, true, nil, nil)
	value := map[string]any{
		"address_space":             "315-5313 VRAM",
		"sprite_table_base":         base,
		"sprite_table_base_hex":     canonicalHex(base),
		"byte_order":                "big-endian",
		"system_paused_during_read": pausedDuringRead,
		"capture_consistency":       tc.server.captureConsistencyView(consistency),
		"entries":                   window,
		"returned_entries":          len(window),
		"table_entries_valid":       len(all),
		"paging":                    map[string]any{"offset": offset, "count": len(window)},
		"chain":                     chain,
		"chain_visible_count":       chainVisible,
		"table_entry_count":         tableEntryCount,
		"warning":                   warning,
		"layout_note":               "8 bytes per entry; X/Y are 9-bit offsets minus 128; link occupies bits 8-14 of word 1; chain starts at sprite 0 and ends when a link returns 0. chain_visible_count is the hardware-rendered link-chain length; table_entry_count counts populated table entries (any nonzero field), so a mid-update table can hold more entries than the chain renders.",
	}
	source.annotate(tc, value, captureReuseNote("vdp_sprite_table", "VRAM", parsed.VDPCaptureID))
	return okResult(value, tc.modern)
}

// populatedSpriteEntryCount counts table entries with at least one nonzero
// decoded field. A fully zero entry (all four words zero) is an unused slot:
// Y=0, X=0, tile=0, link=0, size 1x1, palette 0 — indistinguishable from an
// intentionally empty entry on real hardware.
func populatedSpriteEntryCount(entries []spriteEntry) int {
	count := 0
	for _, entry := range entries {
		if entry.YRaw != 0 || entry.XRaw != 0 || entry.Tile != 0 || entry.Link != 0 ||
			entry.Palette != 0 || entry.Priority || entry.HFlip || entry.VFlip ||
			entry.WidthCells != 1 || entry.HeightCells != 1 {
			count++
		}
	}
	return count
}

func parseSpriteEntries(raw []byte) []spriteEntry {
	count := len(raw) / 8
	entries := make([]spriteEntry, 0, count)
	for index := 0; index < count; index++ {
		w0 := int(raw[index*8])<<8 | int(raw[index*8+1])
		w1 := int(raw[index*8+2])<<8 | int(raw[index*8+3])
		w2 := int(raw[index*8+4])<<8 | int(raw[index*8+5])
		w3 := int(raw[index*8+6])<<8 | int(raw[index*8+7])
		yRaw := w0 & 0x1FF
		xRaw := w3 & 0x1FF
		entries = append(entries, spriteEntry{
			Index:       index,
			YRaw:        yRaw,
			ScreenY:     yRaw - 128,
			WidthCells:  (w1 & 0x3) + 1,
			HeightCells: ((w1 >> 2) & 0x3) + 1,
			Link:        (w1 >> 8) & 0x7F,
			Tile:        w2 & 0x7FF,
			HFlip:       (w2>>11)&1 != 0,
			VFlip:       (w2>>12)&1 != 0,
			Palette:     (w2 >> 13) & 0x3,
			Priority:    (w2>>15)&1 != 0,
			XRaw:        xRaw,
			ScreenX:     xRaw - 128,
		})
	}
	return entries
}

// walkLinkChain follows the hardware display order starting at sprite 0. The
// chain ends when a link field returns to 0 after at least one hop or repeats.
func walkLinkChain(entries []spriteEntry, tableMax int) map[string]any {
	order := make([]int, 0, len(entries))
	visited := map[int]bool{}
	dangling := []int{}
	cycleDetected := false
	terminatedByZero := false
	incomplete := false
	current := 0
	steps := 0
	for steps <= len(entries) {
		if current >= len(entries) {
			incomplete = true
			break
		}
		if visited[current] {
			cycleDetected = true
			break
		}
		visited[current] = true
		order = append(order, current)
		link := entries[current].Link
		if link == 0 {
			terminatedByZero = true
			break
		}
		if int(link) >= tableMax {
			dangling = append(dangling, int(link))
			break
		}
		current = int(link)
		steps++
	}
	return map[string]any{
		"order":              order,
		"length":             len(order),
		"terminated_by_zero": terminatedByZero,
		"cycle_detected":     cycleDetected,
		"dangling_links":     dangling,
		"incomplete":         incomplete,
	}
}

type vdpPaletteExportArgs struct {
	Context string `json:"context"`
}

func runVDPPaletteExport(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpPaletteExportArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	raw, pausedDuringRead, failure := fetchVDPBytes(tc, "cram", 0, 128)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	decoded := cramRGB333Entries(raw)
	if len(decoded) != 64 {
		return failureResult(&toolFailure{
			Code:    "bridge_error",
			Message: fmt.Sprintf("CRAM payload decoded to %d entries instead of 64.", len(decoded)),
		}, tc.modern)
	}
	captureID := newCaptureID()
	consistency := buildCaptureConsistency(tc.server, map[string]any{"system_paused_during_read": pausedDuringRead}, false, true, nil, nil)

	paletteImg := renderPalettePNG(decoded)
	var pngBuffer bytes.Buffer
	if err := png.Encode(&pngBuffer, paletteImg); err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: "encode PNG: " + err.Error()}, tc.modern)
	}
	paletteProvenance := vdpProvenanceWithCapture(tc, "vdp-palette", "mem-vdp-cram", "VDP CRAM", captureID, consistency)
	cramLength := uint64(128)
	paletteProvenance.ByteLength = &cramLength
	pngStored, err := tc.server.store.PutWithProvenance(context.ID, "vdp-palette", "image/png", pngBuffer.Bytes(), paletteProvenance)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	jsonDocument := buildPaletteJSON(decoded)
	jsonProvenance := vdpProvenanceWithCapture(tc, "vdp-palette-json", "mem-vdp-cram", "VDP CRAM", captureID, consistency)
	jsonProvenance.ByteLength = &cramLength
	jsonStored, err := putJSONArtifact(tc.server, context.ID, "vdp-palette-json", jsonDocument, jsonProvenance)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	linesNonZero := make([]int, 4)
	for _, entry := range decoded {
		if entry["word"].(int) != 0 {
			linesNonZero[entry["index"].(int)/16]++
		}
	}
	return okResult(map[string]any{
		"summary": map[string]any{
			"kind":                      "vdp-palette",
			"line_count":                4,
			"colors_per_line":           16,
			"nonzero_per_line":          linesNonZero,
			"backdrop_color":            decoded[0]["color_hex"],
			"color_format":              "9-bit RGB expanded to 8-bit",
			"byte_order":                "big-endian",
			"capture_id":                captureID,
			"capture_consistency":       tc.server.captureConsistencyView(consistency),
			"system_paused_during_read": pausedDuringRead,
			"png_size_bytes":            pngBuffer.Len(),
			"png_sha256":                pngStored.SHA256,
			"json_size_bytes":           len(jsonDocument),
			"json_sha256":               jsonStored.SHA256,
		},
		"artifacts": []map[string]any{
			artifactDescriptor(tc.server, pngStored, context.ID),
			artifactDescriptor(tc.server, jsonStored, context.ID),
		},
	}, tc.modern)
}

func renderPalettePNG(entries []map[string]any) image.Image {
	const swatch = 24
	const border = 1
	width := 16*(swatch+border) + border
	height := 4*(swatch+border) + border
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	grid := color.RGBA{R: 0x20, G: 0x20, B: 0x20, A: 0xFF}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, grid)
		}
	}
	for _, entry := range entries {
		index := entry["index"].(int)
		line := index / 16
		column := index % 16
		r := uint8(entry["r"].(int))
		g := uint8(entry["g"].(int))
		b := uint8(entry["b"].(int))
		fill := color.RGBA{R: r, G: g, B: b, A: 0xFF}
		x0 := border + column*(swatch+border)
		y0 := border + line*(swatch+border)
		for y := 0; y < swatch; y++ {
			for x := 0; x < swatch; x++ {
				img.Set(x0+x, y0+y, fill)
			}
		}
	}
	return img
}

func buildPaletteJSON(entries []map[string]any) map[string]any {
	type colorEntry struct {
		Index     int    `json:"index"`
		Word      int    `json:"word"`
		RGB333    [3]int `json:"rgb333_r_g_b"`
		RGB888Hex string `json:"rgb888_hex"`
	}
	lines := make([][16]colorEntry, 0, 4)
	for line := 0; line < 4; line++ {
		var row [16]colorEntry
		for column := 0; column < 16; column++ {
			source := entries[line*16+column]
			nineBit := source["nine_bit"].([3]int)
			row[column] = colorEntry{
				Index:     source["index"].(int),
				Word:      source["word"].(int),
				RGB333:    nineBit,
				RGB888Hex: source["color_hex"].(string),
			}
		}
		lines = append(lines, row)
	}
	// schema_version is stamped by putJSONArtifact; the document carries only
	// its own payload fields.
	return map[string]any{
		"kind":         "vdp-palette",
		"color_format": "9-bit RGB expanded to 8-bit",
		"byte_order":   "big-endian",
		"lines":        lines,
	}
}

const (
	mdTileSizeBytes      = 32
	mdTileEdgePixels     = 8
	defaultVDPTileScale  = 8
	defaultVDPPlaneScale = 1
)

const (
	maxVDPTileStripCount = 64
	maxVDPTileUpscale    = 32
	maxVDPPlaneUpscale   = 4
)

type vdpTileExportArgs struct {
	Crop            *renderCropArgs `json:"crop"`
	Tile            uint64          `json:"tile"`
	Count           uint64          `json:"count"`
	Palette         uint64          `json:"palette"`
	Scale           uint64          `json:"scale"`
	TransparentZero *bool           `json:"transparent_zero"`
	VDPCaptureID    string          `json:"vdp_capture_id"`
	Context         string          `json:"context"`
}

type vdpPlaneExportArgs struct {
	Crop            *renderCropArgs `json:"crop"`
	Plane           string          `json:"plane"`
	Scale           uint64          `json:"scale"`
	TransparentZero *bool           `json:"transparent_zero"`
	VDPCaptureID    string          `json:"vdp_capture_id"`
	Context         string          `json:"context"`
}

// fetchVDPBytesChunked reads length bytes through repeated timed-buffer reads,
// because a single inline read is capped at inlineReadCapBytes. The returned
// flag reports whether every underlying read found the system already paused;
// when true the composite buffer is a coherent snapshot.
func fetchVDPBytesChunked(tc toolContext, target string, address uint64, length uint64) ([]byte, bool, *toolFailure) {
	raw := make([]byte, 0, length)
	allPaused := true
	for offset := uint64(0); offset < length; {
		chunk := length - offset
		if chunk > inlineReadCapBytes {
			chunk = inlineReadCapBytes
		}
		payload, failure := tc.server.executeCommand(tc.ctx, "vdp_mem_read", map[string]string{
			"target":  target,
			"address": strconv.FormatUint(address+offset, 10),
			"length":  strconv.FormatUint(chunk, 10),
		})
		if failure != nil {
			return nil, false, failure
		}
		rawDataBase64, _ := payload["data"].(string)
		decodedChunk, err := base64.StdEncoding.DecodeString(rawDataBase64)
		if err != nil {
			return nil, false, &toolFailure{Code: "bridge_error", Message: "decode base64 vdp payload: " + err.Error()}
		}
		raw = append(raw, decodedChunk...)
		// The bridge flag reports that the read had to stop a RUNNING
		// system; any such chunk means emulation resumed between reads,
		// so the composite buffer spans multiple emulated moments.
		if hadToPause, ok := payload["system_paused_during_read"].(bool); ok && hadToPause {
			allPaused = false
		}
		offset += chunk
	}
	return raw, allPaused, nil
}

// statusRegisters flattens the vdp_status register dump into an index/value map.
func statusRegisters(status map[string]any) map[int]int {
	registers := map[int]int{}
	rawList, ok := status["registers"].([]any)
	if !ok {
		return registers
	}
	for _, item := range rawList {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		index, hasIndex := entry["register"].(float64)
		value, hasValue := entry["value"].(float64)
		if hasIndex && hasValue {
			registers[int(index)] = int(value)
		}
	}
	return registers
}

// planeCellSpan decodes one nibble of VDP register 16 into plane cells:
// 00 selects 32 cells, 01 selects 64, anything else selects 128.
func planeCellSpan(layout int) int {
	switch layout & 3 {
	case 0:
		return 32
	case 1:
		return 64
	default:
		return 128
	}
}

// cramPaletteColors converts the decoded CRAM entries into packed RGB triples.
func cramPaletteColors(entries []map[string]any) [][3]uint8 {
	colors := make([][3]uint8, len(entries))
	for index, entry := range entries {
		colors[index] = [3]uint8{uint8(entry["r"].(int)), uint8(entry["g"].(int)), uint8(entry["b"].(int))}
	}
	return colors
}

// decodeMDTile expands one 4bpp Mega Drive pattern into 8x8 palette indices.
// Every row holds four bytes packing two pixels each with the high nibble on
// the left.
func decodeMDTile(pattern []byte) [mdTileEdgePixels][mdTileEdgePixels]int {
	var tile [mdTileEdgePixels][mdTileEdgePixels]int
	for row := 0; row < mdTileEdgePixels; row++ {
		base := row * 4
		for column := 0; column < mdTileEdgePixels; column++ {
			packed := pattern[base+column/2]
			if column%2 == 0 {
				tile[row][column] = int(packed >> 4)
			} else {
				tile[row][column] = int(packed & 0x0F)
			}
		}
	}
	return tile
}

// drawMDTile blits one decoded tile with optional flips. Transparent pixels
// are skipped so the destination stays at alpha zero.
func drawMDTile(img *image.NRGBA, tile *[mdTileEdgePixels][mdTileEdgePixels]int, colors [][3]uint8, paletteLine int, transparentZero bool, originX, originY, scale int, hflip, vflip bool) {
	for row := 0; row < mdTileEdgePixels; row++ {
		sourceRow := row
		if vflip {
			sourceRow = mdTileEdgePixels - 1 - row
		}
		for column := 0; column < mdTileEdgePixels; column++ {
			sourceColumn := column
			if hflip {
				sourceColumn = mdTileEdgePixels - 1 - column
			}
			index := tile[sourceRow][sourceColumn]
			if transparentZero && index == 0 {
				continue
			}
			rgb := colors[paletteLine*16+index]
			fill := color.NRGBA{R: rgb[0], G: rgb[1], B: rgb[2], A: 0xFF}
			for offsetY := 0; offsetY < scale; offsetY++ {
				for offsetX := 0; offsetX < scale; offsetX++ {
					img.Set(originX+column*scale+offsetX, originY+row*scale+offsetY, fill)
				}
			}
		}
	}
}

func storeArtifactAndDescriptor(tc toolContext, contextID, kind, mimeType string, payload []byte, captureID string, consistency *artifact.CaptureConsistency) (artifact.Artifact, map[string]any, error) {
	provenance := vdpProvenanceWithCapture(tc, kind, vdpSpaceForKind(kind), vdpDeviceForKind(kind), captureID, consistency)
	stored, err := tc.server.store.PutWithProvenance(contextID, kind, mimeType, payload, provenance)
	if err != nil {
		return artifact.Artifact{}, nil, err
	}
	return stored, artifactDescriptor(tc.server, stored, contextID), nil
}

// storeJSONArtifactAndDescriptor is the JSON counterpart of
// storeArtifactAndDescriptor: the document's schema_version is stamped by the
// single declaration, so a derived JSON export cannot drift from its kind.
func storeJSONArtifactAndDescriptor(tc toolContext, contextID, kind string, document map[string]any, captureID string, consistency *artifact.CaptureConsistency) (artifact.Artifact, map[string]any, error) {
	provenance := vdpProvenanceWithCapture(tc, kind, vdpSpaceForKind(kind), vdpDeviceForKind(kind), captureID, consistency)
	stored, err := putJSONArtifact(tc.server, contextID, kind, document, provenance)
	if err != nil {
		return artifact.Artifact{}, nil, err
	}
	return stored, artifactDescriptor(tc.server, stored, contextID), nil
}

// vdpProvenance builds the capture envelope for a VDP-derived artifact: the
// device buffer domain (VRAM/CRAM/VSRAM are not linearly CPU-mapped, so the
// space carries a note), target identity, and capture time. Addresses are
// device-relative and the caller sets byte length when it knows the captured
// range exactly (the export summaries always state their ranges inline).
func vdpProvenance(tc toolContext, kind, spaceID, device string) *artifact.Provenance {
	return vdpProvenanceWithCapture(tc, kind, spaceID, device, "", nil)
}

// vdpProvenanceWithCapture is vdpProvenance with an explicit capture id and
// capture-consistency object, used by exports whose artifacts belong to one
// composite capture.
func vdpProvenanceWithCapture(tc toolContext, kind, spaceID, device string, captureID string, consistency *artifact.CaptureConsistency) *artifact.Provenance {
	provenance := genericProvenance(tc.server, kind, time.Now().UTC())
	start := uint64(0)
	provenance.AddressSpace = spaceID
	provenance.Device = device
	provenance.StartAddress = &start
	provenance.EffectiveAddress = &start
	provenance.StartAddressHex = canonicalHex(0)
	provenance.EffectiveAddressHex = canonicalHex(0)
	provenance.SpaceKind = "timed-buffer"
	provenance.ByteOrder = "device-specific"
	if captureID != "" {
		provenance.CaptureID = captureID
	}
	if consistency != nil {
		provenance.CaptureConsistency = consistency
	}
	// The deprecated flat label is derived from the object, never hardcoded:
	// a VDP export read inside a paused window must not claim to be live.
	provenance.Consistency = provenance.CaptureConsistency.State
	return provenance
}

// vdpSpaceForKind maps an export artifact kind to the VDP buffer space it was
// read from, for provenance. Unknown kinds fall back to the generic VDP space.
func vdpSpaceForKind(kind string) string {
	switch kind {
	case "vdp-palette", "vdp-palette-json":
		return "mem-vdp-cram"
	case "vdp-plane-a", "vdp-plane-b", "vdp-plane-window", "vdp-plane-json":
		return "mem-vdp-vram"
	case "vdp-tile-strip", "vdp-tile-json", "vdp-tiles", "vdp-tiles-json":
		return "mem-vdp-vram"
	default:
		return "vdp-buffers"
	}
}

// vdpDeviceForKind names the owning device for VDP export kinds.
func vdpDeviceForKind(kind string) string {
	switch kind {
	case "vdp-palette", "vdp-palette-json":
		return "VDP CRAM"
	case "vdp-plane-a", "vdp-plane-b", "vdp-plane-window", "vdp-plane-json":
		return "VDP VRAM"
	case "vdp-tile-strip", "vdp-tile-json", "vdp-tiles", "vdp-tiles-json":
		return "VDP VRAM"
	default:
		return "VDP"
	}
}

type exportedTile struct {
	Index   int                                     `json:"index"`
	Address int                                     `json:"vram_address"`
	Rows    [mdTileEdgePixels][mdTileEdgePixels]int `json:"pixel_indices"`
}

// renderCropArgs is the optional rectangular window of a rendered export. The
// coordinates are source pixels before scaling (a tile is 8x8 source pixels), so
// a crop is independent of the requested upscale.
type renderCropArgs struct {
	X      uint64 `json:"x"`
	Y      uint64 `json:"y"`
	Width  uint64 `json:"width"`
	Height uint64 `json:"height"`
}

// cropRenderedImage applies one crop window to a rendered export image and
// returns the cropped image plus the structured crop view. A nil crop returns the
// image unchanged and no view, so a caller that never asks for a crop sees
// exactly the pre-merge payload.
func cropRenderedImage(img *image.NRGBA, crop *renderCropArgs, scale int) (*image.NRGBA, map[string]any, *toolFailure) {
	if crop == nil {
		return img, nil, nil
	}
	sourceWidth := img.Bounds().Dx() / scale
	sourceHeight := img.Bounds().Dy() / scale
	if crop.Width == 0 || crop.Height == 0 {
		return nil, nil, &toolFailure{Code: "invalid_params", Message: "crop.width and crop.height must be at least 1 source pixel"}
	}
	if crop.X+crop.Width > uint64(sourceWidth) || crop.Y+crop.Height > uint64(sourceHeight) {
		return nil, nil, &toolFailure{
			Code: "out_of_range",
			Message: fmt.Sprintf("crop x=%d,y=%d %dx%d exceeds the rendered %dx%d source pixels",
				crop.X, crop.Y, crop.Width, crop.Height, sourceWidth, sourceHeight),
			Data: map[string]any{"source_width": sourceWidth, "source_height": sourceHeight},
		}
	}
	rect := image.Rect(int(crop.X)*scale, int(crop.Y)*scale, int(crop.X+crop.Width)*scale, int(crop.Y+crop.Height)*scale)
	cropped := image.NewNRGBA(image.Rect(0, 0, rect.Dx(), rect.Dy()))
	draw.Draw(cropped, cropped.Bounds(), img, rect.Min, draw.Src)
	view := map[string]any{
		"x":             crop.X,
		"y":             crop.Y,
		"width":         crop.Width,
		"height":        crop.Height,
		"unit":          "source pixels before scaling",
		"scale":         scale,
		"source_width":  sourceWidth,
		"source_height": sourceHeight,
	}
	return cropped, view, nil
}

func runVDPTileExport(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpTileExportArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	count := parsed.Count
	if count == 0 {
		count = 1
	}
	scale := int(parsed.Scale)
	if scale == 0 {
		scale = defaultVDPTileScale
	}
	transparentZero := parsed.TransparentZero == nil || *parsed.TransparentZero

	if parsed.Palette > 3 || count > maxVDPTileStripCount || scale < 1 || scale > maxVDPTileUpscale {
		return failureResult(&toolFailure{
			Code: "invalid_params",
			Message: fmt.Sprintf("vdp_tile_export requires palette 0-3, count 1-%d, and scale 1-%d.",
				maxVDPTileStripCount, maxVDPTileUpscale),
			Data: map[string]any{"max_tiles": maxVDPTileStripCount, "max_scale": maxVDPTileUpscale},
		}, tc.modern)
	}

	// A supplied capture replaces the status, VRAM, and CRAM reads with the stored
	// components; a capture that cannot serve them fails explicitly.
	source := captureReuseOf("", nil)
	var statusPayload map[string]any
	if parsed.VDPCaptureID != "" {
		captureData, failure := resolveVDPCapture(tc, context.ID, parsed.VDPCaptureID)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		capturedStatus, failure := captureData.statusView(tc, context.ID)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		source = captureReuseOf(parsed.VDPCaptureID, captureData)
		statusPayload = capturedStatus
	} else {
		liveStatus, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		statusPayload = liveStatus
	}
	vramSize := fetchVRAMSize(statusPayload)
	firstByte := parsed.Tile * mdTileSizeBytes
	totalBytes := count * mdTileSizeBytes
	if firstByte+totalBytes > vramSize {
		return failureResult(&toolFailure{
			Code: "out_of_range",
			Message: fmt.Sprintf("Tiles %d-%d exceed the VRAM capacity of %d bytes (%d tiles).",
				parsed.Tile, parsed.Tile+count-1, vramSize, vramSize/mdTileSizeBytes),
			Data: map[string]any{"vram_size": vramSize},
		}, tc.modern)
	}

	var vram, cramRaw []byte
	var consistency *artifact.CaptureConsistency
	coherent := false
	if source.unused {
		vram, coherent, failure = fetchVDPBytesChunked(tc, "vram", firstByte, totalBytes)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		cramRaw, _, failure = fetchVDPBytesChunked(tc, "cram", 0, 128)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		consistency = compositeCaptureConsistency(tc.server, coherent)
	} else {
		vram, failure = source.data.vramRange(tc, context.ID, firstByte, totalBytes)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		cramRaw, failure = source.data.componentBytes(tc, context.ID, "cram")
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		coherent = source.data.coherentCapture()
		consistency = source.data.consistency
	}
	if uint64(len(vram)) < totalBytes {
		// A bridge answer shorter than the requested strip cannot be rendered;
		// report the shortfall instead of slicing past the buffer.
		return failureResult(&toolFailure{
			Code:    "out_of_range",
			Message: fmt.Sprintf("VRAM read returned %d of %d bytes for tiles %d-%d", len(vram), totalBytes, parsed.Tile, parsed.Tile+count-1),
			Data:    map[string]any{"requested_bytes": totalBytes, "returned_bytes": len(vram)},
		}, tc.modern)
	}
	colors := cramPaletteColors(cramRGB333Entries(cramRaw))
	// A derived export of a stored capture stays in that capture's lineage, so
	// artifact_list(capture_id) finds it next to the captured components.
	captureID := newCaptureID()
	if !source.unused {
		captureID = source.id
	}

	width := int(count) * mdTileEdgePixels * scale
	height := mdTileEdgePixels * scale
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	tiles := make([]exportedTile, 0, int(count))
	nonzeroPerTile := make([]int, 0, int(count))
	for index := 0; index < int(count); index++ {
		tile := decodeMDTile(vram[index*mdTileSizeBytes : (index+1)*mdTileSizeBytes])
		drawMDTile(img, &tile, colors, int(parsed.Palette), transparentZero, index*mdTileEdgePixels*scale, 0, scale, false, false)
		nonzero := 0
		for _, rowValues := range tile {
			for _, value := range rowValues {
				if value != 0 {
					nonzero++
				}
			}
		}
		nonzeroPerTile = append(nonzeroPerTile, nonzero)
		tiles = append(tiles, exportedTile{
			Index:   int(parsed.Tile) + index,
			Address: int(firstByte) + index*mdTileSizeBytes,
			Rows:    tile,
		})
	}

	croppedImg, cropView, failure := cropRenderedImage(img, parsed.Crop, scale)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	img = croppedImg

	var pngBuffer bytes.Buffer
	if err := png.Encode(&pngBuffer, img); err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: "encode PNG: " + err.Error()}, tc.modern)
	}
	jsonDocument := map[string]any{
		"kind":         "vdp-tiles",
		"pixel_order":  "high-nibble-left",
		"byte_order":   "big-endian",
		"palette_line": int(parsed.Palette),
		"tiles":        tiles,
	}

	pngStored, pngDescriptor, err := storeArtifactAndDescriptor(tc, context.ID, "vdp-tiles", "image/png", pngBuffer.Bytes(), captureID, consistency)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	jsonStored, jsonDescriptor, err := storeJSONArtifactAndDescriptor(tc, context.ID, "vdp-tiles-json", jsonDocument, captureID, consistency)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	summary := map[string]any{
		"kind":                      "vdp-tiles",
		"address_space":             "315-5313 VRAM",
		"tile_count":                count,
		"tile_size_bytes":           mdTileSizeBytes,
		"bpp":                       4,
		"vram_address_start":        firstByte,
		"vram_address_start_hex":    canonicalHex(firstByte),
		"vram_address_end":          firstByte + totalBytes - 1,
		"vram_address_end_hex":      canonicalHex(firstByte + totalBytes - 1),
		"palette_line":              parsed.Palette,
		"nonzero_pixels_per_tile":   nonzeroPerTile,
		"coherent_snapshot":         coherent,
		"system_paused_during_read": !coherent,
		"capture_id":                captureID,
		"capture_consistency":       tc.server.captureConsistencyView(consistency),
		"byte_order":                "big-endian",
		"layout_note":               "Each tile is 8x8 4bpp: four bytes per row, two pixels per byte, high nibble left. Pixel 0 is transparent unless transparent_zero is false. system_paused_during_read is true when any chunked read had to pause a running system; coherent_snapshot is true only when every chunk found it already paused. Both artifacts share one capture_id; when the composition is composite_non_atomic the VRAM and CRAM pieces may come from different frames and must not be combined into a coherent instant.",
		"png_size_bytes":            pngBuffer.Len(),
		"png_sha256":                pngStored.SHA256,
		"json_size_bytes":           len(jsonDocument),
		"json_sha256":               jsonStored.SHA256,
	}
	if cropView != nil {
		summary["crop"] = cropView
		summary["png_width"] = img.Bounds().Dx()
		summary["png_height"] = img.Bounds().Dy()
	}
	if !source.unused {
		summary["system_paused_during_read"] = false
		summary["source_capture_id"] = source.id
	}
	source.annotate(tc, summary, captureReuseNote("vdp_tile_export", "VRAM and CRAM", parsed.VDPCaptureID))
	return okResult(map[string]any{
		"summary":   summary,
		"artifacts": []map[string]any{pngDescriptor, jsonDescriptor},
	}, tc.modern)
}

func runVDPPlaneExport(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpPlaneExportArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	scale := int(parsed.Scale)
	if scale == 0 {
		scale = defaultVDPPlaneScale
	}
	transparentZero := parsed.TransparentZero == nil || *parsed.TransparentZero

	if failure := vdpPlaneVocab.validate(parsed.Plane); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if scale < 1 || scale > maxVDPPlaneUpscale {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("vdp_plane_export scale must be between 1 and %d.", maxVDPPlaneUpscale),
		}, tc.modern)
	}

	// A supplied capture replaces the status, VRAM, and CRAM reads with the stored
	// components; a capture that cannot serve them fails explicitly.
	source := captureReuseOf("", nil)
	var statusPayload map[string]any
	if parsed.VDPCaptureID != "" {
		captureData, failure := resolveVDPCapture(tc, context.ID, parsed.VDPCaptureID)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		capturedStatus, failure := captureData.statusView(tc, context.ID)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		source = captureReuseOf(parsed.VDPCaptureID, captureData)
		statusPayload = capturedStatus
	} else {
		liveStatus, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		statusPayload = liveStatus
	}
	decoded, _ := statusPayload["decoded"].(map[string]any)
	baseValue, _ := decoded["name_table_base_"+parsed.Plane].(float64)
	nameTableBase := uint64(baseValue)
	registers := statusRegisters(statusPayload)
	widthCells := planeCellSpan(registers[16])
	heightCells := planeCellSpan(registers[16] >> 4)
	interlaceActive := registers[12]&0x2 != 0

	vramSize := fetchVRAMSize(statusPayload)
	var vramAll, cramRaw []byte
	var consistency *artifact.CaptureConsistency
	coherent := false
	if source.unused {
		vramAll, coherent, failure = fetchVDPBytesChunked(tc, "vram", 0, vramSize)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		cramRaw, _, failure = fetchVDPBytesChunked(tc, "cram", 0, 128)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		consistency = compositeCaptureConsistency(tc.server, coherent)
	} else {
		vramAll, failure = source.data.vramRange(tc, context.ID, 0, vramSize)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		cramRaw, failure = source.data.componentBytes(tc, context.ID, "cram")
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		coherent = source.data.coherentCapture()
		consistency = source.data.consistency
	}
	colors := cramPaletteColors(cramRGB333Entries(cramRaw))
	// A derived export of a stored capture stays in that capture's lineage, so
	// artifact_list(capture_id) finds it next to the captured components.
	captureID := newCaptureID()
	if !source.unused {
		captureID = source.id
	}

	if nameTableBase > uint64(len(vramAll)) {
		return failureResult(&toolFailure{
			Code:    "out_of_range",
			Message: fmt.Sprintf("the %s name table starts at %s, past the %d bytes of VRAM the bridge returned", parsed.Plane, canonicalHex(nameTableBase), len(vramAll)),
			Data:    map[string]any{"name_table_base": nameTableBase, "vram_bytes": len(vramAll)},
		}, tc.modern)
	}
	nameTableBytes := widthCells * heightCells * 2
	truncated := false
	if nameTableBase+uint64(nameTableBytes) > uint64(len(vramAll)) {
		nameTableBytes = len(vramAll) - int(nameTableBase)
		truncated = true
	}
	nameTable := vramAll[nameTableBase : nameTableBase+uint64(nameTableBytes)]

	width := widthCells * mdTileEdgePixels * scale
	height := heightCells * mdTileEdgePixels * scale
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	histogram := map[int]int{}
	priorityEntries := 0
	invalidEntries := 0
	for cellRow := 0; cellRow < heightCells; cellRow++ {
		for cellColumn := 0; cellColumn < widthCells; cellColumn++ {
			entryOffset := (cellRow*widthCells + cellColumn) * 2
			if entryOffset+1 >= len(nameTable) {
				break
			}
			word := int(nameTable[entryOffset])<<8 | int(nameTable[entryOffset+1])
			tileIndex := word & 0x07FF
			hflip := word&0x0800 != 0
			vflip := word&0x1000 != 0
			paletteLine := (word >> 13) & 0x3
			if word&0x8000 != 0 {
				priorityEntries++
			}
			histogram[tileIndex]++
			if (tileIndex+1)*mdTileSizeBytes > len(vramAll) {
				invalidEntries++
				continue
			}
			tile := decodeMDTile(vramAll[tileIndex*mdTileSizeBytes : (tileIndex+1)*mdTileSizeBytes])
			drawMDTile(img, &tile, colors, paletteLine, transparentZero,
				cellColumn*mdTileEdgePixels*scale, cellRow*mdTileEdgePixels*scale, scale, hflip, vflip)
		}
	}

	croppedImg, cropView, failure := cropRenderedImage(img, parsed.Crop, scale)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	img = croppedImg
	if cropView != nil {
		width = img.Bounds().Dx()
		height = img.Bounds().Dy()
	}

	var pngBuffer bytes.Buffer
	if err := png.Encode(&pngBuffer, img); err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: "encode PNG: " + err.Error()}, tc.modern)
	}
	jsonDocument := map[string]any{
		"kind":              "vdp-plane",
		"plane":             parsed.Plane,
		"byte_order":        "big-endian",
		"name_entry_format": "bits 0-10 tile, 11 hflip, 12 vflip, 13-14 palette, 15 priority",
		"name_table_base":   int(nameTableBase),
		"size_cells":        [2]int{widthCells, heightCells},
		"distinct_tiles":    histogram,
		"priority_entries":  priorityEntries,
		"invalid_entries":   invalidEntries,
		"truncated":         truncated,
	}

	pngStored, pngDescriptor, err := storeArtifactAndDescriptor(tc, context.ID, "vdp-plane", "image/png", pngBuffer.Bytes(), captureID, consistency)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	jsonStored, jsonDescriptor, err := storeJSONArtifactAndDescriptor(tc, context.ID, "vdp-plane-json", jsonDocument, captureID, consistency)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	notes := []string{
		"This is an unscrolled texture view of the name table; hardware scrolling, window boundaries, and sprite layering are not applied.",
		"Priority bit counts are reported but not rendered; the image shows every cell regardless of priority.",
	}
	if interlaceActive {
		notes = append(notes, "Interlace mode is active; cells render here at single height.")
	}

	summary := map[string]any{
		"kind":                      "vdp-plane",
		"address_space":             "315-5313 VRAM",
		"plane":                     parsed.Plane,
		"name_table_base":           nameTableBase,
		"name_table_base_hex":       canonicalHex(nameTableBase),
		"size_cells":                []int{widthCells, heightCells},
		"png_size_bytes":            pngBuffer.Len(),
		"png_width":                 width,
		"png_height":                height,
		"png_sha256":                pngStored.SHA256,
		"json_size_bytes":           len(jsonDocument),
		"json_sha256":               jsonStored.SHA256,
		"distinct_tiles":            len(histogram),
		"priority_entries":          priorityEntries,
		"invalid_entries":           invalidEntries,
		"truncated":                 truncated,
		"interlace_active":          interlaceActive,
		"coherent_snapshot":         coherent,
		"system_paused_during_read": !coherent,
		"capture_id":                captureID,
		"capture_consistency":       tc.server.captureConsistencyView(consistency),
		"byte_order":                "big-endian",
		"notes":                     notes,
	}
	if cropView != nil {
		summary["crop"] = cropView
	}
	if !source.unused {
		summary["system_paused_during_read"] = false
		summary["source_capture_id"] = source.id
	}
	source.annotate(tc, summary, captureReuseNote("vdp_plane_export", "VRAM and CRAM", parsed.VDPCaptureID))
	return okResult(map[string]any{
		"summary":   summary,
		"artifacts": []map[string]any{pngDescriptor, jsonDescriptor},
	}, tc.modern)
}

type vdpPixelInfoArgs struct {
	X            uint64 `json:"x"`
	Y            uint64 `json:"y"`
	VDPCaptureID string `json:"vdp_capture_id"`
	Context      string `json:"context"`
}

// runVDPPixelInfo reads one pixel's rendering attribution from the VDP
// completed image buffer. The plugin enables full image buffer info lazily;
// until one frame has been rendered with it active the bridge answers
// attribution_ready=false and this tool surfaces the retry contract.
func runVDPPixelInfo(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpPixelInfoArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.VDPCaptureID != "" {
		// Per-pixel attribution exists only for the frame the VDP has just
		// completed: it is produced while rendering and the bridge answers it one
		// coordinate at a time, so no vdp_capture component can hold it. Say so
		// instead of pretending to reuse the capture.
		captureData, failure := resolveVDPCapture(tc, context.ID, parsed.VDPCaptureID)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		return failureResult(captureData.omittedFailure("pixel_attribution",
			"vdp_pixel_info reads the per-pixel attribution of the completed frame buffer, which the native bridge exposes only for the current frame and one coordinate at a time; vdp_capture cannot persist it. Call vdp_pixel_info without vdp_capture_id to read the live frame buffer."), tc.modern)
	}

	payload, failure := tc.server.executeCommand(tc.ctx, "vdp_pixel_info", map[string]string{
		"x": strconv.FormatUint(parsed.X, 10),
		"y": strconv.FormatUint(parsed.Y, 10),
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if ready, _ := payload["attribution_ready"].(bool); !ready {
		frameToken, _ := payload["frame_token"].(float64)
		return failureResult(&toolFailure{
			Code:    "pixel_info_pending",
			Message: "Pixel attribution is not ready: full image buffer info was just enabled and no frame has rendered with it active yet. Resume execution until at least one frame completes, then retry.",
			Data: map[string]any{
				"frame_token": uint64(frameToken),
				"retry_hint":  "run the emulator for one frame, then call vdp_pixel_info again with the same coordinates",
			},
		}, tc.modern)
	}
	payload["address_space"] = "315-5313 completed image buffer"
	payload["coordinate_space"] = "completed frame buffer coordinates, including border and blanking regions"
	// Pixel attribution reads the completed render buffer under the VDP's own
	// lock; the handler never pauses the system for it.
	payload["system_paused_during_read"] = false
	payload["capture_consistency"] = tc.server.captureConsistencyView(newCaptureConsistency(tc.server, consistencyLive, "The completed render buffer is read under the VDP's own lock; the read never pauses the system and the buffer may advance between reads."))
	captureReuseOf("", nil).annotate(tc, payload, "")
	return okResult(payload, tc.modern)
}
