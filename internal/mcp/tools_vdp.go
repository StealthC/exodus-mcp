package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strconv"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

func vdpToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "vdp_status",
			description: "Report Mega Drive VDP registers, decoded key fields, and image buffer geometry.",
			schema:      objectSchema(map[string]any{}, nil),
			run:         runVdpStatus,
		},
		{
			name:        "vdp_memory_read",
			description: fmt.Sprintf("Read raw VRAM, CRAM, or VSRAM bytes inline (cap %d) with explicit byte-order metadata, plus VDP-specific decoded views: big-endian words and CRAM 9-bit RGB entries.", inlineReadCapBytes),
			schema: objectSchema(map[string]any{
				"target":         enumProperty("VDP memory buffer to read.", []string{"vram", "cram", "vsram"}),
				"address":        addressProperty(),
				"length":         integerProperty(fmt.Sprintf("Byte length between 1 and %d (default %d). Word views require an even address and length.", inlineReadCapBytes, defaultVDPMemoryReadLen), 1),
				"representation": enumProperty("Inline rendering.", []string{"hexdump", "array_u8", "raw_base64", "array_u16", "cram_rgb333"}),
				"context":        contextProperty(),
			}, []string{"target", "address"}),
			run: runVDPMemoryRead,
		},
		{
			name:        "vdp_sprite_table",
			description: "Decode the VDP sprite attribute table from VRAM: positions, size, tile mapping, palette, priority, and link-chain order with cycle detection. Bounded paging over at most 80 entries.",
			schema: objectSchema(map[string]any{
				"offset":  integerProperty("First sprite index to return (default 0, max 79).", 0),
				"count":   integerProperty(fmt.Sprintf("Entry count between 1 and %d (default %d). The link chain always covers the whole table.", vdpSpriteTableMaxEntries, defaultVDPSpritePage), 0),
				"context": contextProperty(),
			}, nil),
			run: runVDPSpriteTable,
		},
		{
			name:        "vdp_palette_export",
			description: "Export CRAM as four 16-color palette lines: a PNG swatch artifact, a JSON decode artifact, and a compact structural summary.",
			schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
			run:         runVDPPaletteExport,
		},
		{
			name:        "vdp_tile_export",
			description: "Export one or more consecutive 8x8 4bpp VRAM patterns (tiles) as a scaled PNG artifact plus a JSON pixel-decode artifact, colored through a chosen CRAM palette line.",
			schema: objectSchema(map[string]any{
				"tile":             integerProperty("First tile index counted from VRAM offset 0 (default 0). Each tile occupies 32 bytes.", 0),
				"count":            integerProperty(fmt.Sprintf("Consecutive tile count between 1 and %d (default 1).", maxVDPTileStripCount), 1),
				"palette":          integerProperty("CRAM palette line 0-3 used to color pixel indices 1-15 (default 0).", 0),
				"scale":            integerProperty("Nearest-neighbor upscale factor 1-32 (default 8).", 1),
				"transparent_zero": booleanProperty("Render pixel index 0 as transparent instead of its palette color (default true)."),
				"context":          contextProperty(),
			}, nil),
			run: runVDPTileExport,
		},
		{
			name:        "vdp_plane_export",
			description: "Render a full scroll plane (A, B, or window) from VRAM as an unscrolled texture view: scaled PNG artifact plus JSON structural summary with distinct tiles and priority counts.",
			schema: objectSchema(map[string]any{
				"plane":            enumProperty("Which name table to render.", []string{"a", "b", "window"}),
				"scale":            integerProperty("Nearest-neighbor upscale factor 1-4 (default 1).", 1),
				"transparent_zero": booleanProperty("Render pixel index 0 as transparent instead of its palette color (default true)."),
				"context":          contextProperty(),
			}, nil),
			run: runVDPPlaneExport,
		},
		{
			name:        "frame_capture",
			description: "Capture the current rendered VDP frame as a PNG image artifact.",
			schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
			run:         runFrameCapture,
		},
	}
}

func runVdpStatus(tc toolContext, _ json.RawMessage) map[string]any {
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

type vdpMemoryReadArgs struct {
	Target         string `json:"target"`
	Address        any    `json:"address"`
	Length         uint64 `json:"length"`
	Representation string `json:"representation"`
	Context        string `json:"context"`
}

// runVDPMemoryRead reads one VDP buffer through the plugin's timed-buffer
// ReadLatest path and renders it inline. The bridge returns raw bytes; all
// multi-byte decoding happens here so every view can carry explicit byte-order
// metadata.
func runVDPMemoryRead(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpMemoryReadArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if _, failure = resolveContext(tc.server, parsed.Context); failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := parseAddress(parsed.Address)
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
	switch parsed.Target {
	case "vram", "cram", "vsram":
	default:
		return errorResult("invalid_params", "target must be vram, cram, or vsram", tc.modern)
	}
	representation := parsed.Representation
	if representation == "" {
		representation = "hexdump"
	}
	wordView := representation == "array_u16" || representation == "cram_rgb333"
	if wordView && (address%2 != 0 || length%2 != 0) {
		return failureResult(&toolFailure{
			Code:    "unaligned_request",
			Message: fmt.Sprintf("%s reads whole 2-byte entries; address and length must both be even.", representation),
		}, tc.modern)
	}
	if representation == "cram_rgb333" && parsed.Target != "cram" {
		return errorResult("invalid_params", "cram_rgb333 is only valid with target cram", tc.modern)
	}
	if !wordView {
		switch representation {
		case "hexdump", "array_u8", "raw_base64":
		default:
			return errorResult("invalid_params", "representation must be hexdump, array_u8, raw_base64, array_u16, or cram_rgb333", tc.modern)
		}
	}

	payload, failure := tc.server.executeCommand(tc.ctx, "vdp_mem_read", map[string]string{
		"target":  parsed.Target,
		"address": strconv.FormatUint(address, 10),
		"length":  strconv.FormatUint(length, 10),
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
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
		return failureResult(&toolFailure{Code: "bridge_error", Message: "decode base64 vdp memory payload: " + err.Error()}, tc.modern)
	}

	value := map[string]any{
		"target":                    parsed.Target,
		"address_space":             addressSpace,
		"address":                   address,
		"length":                    len(raw),
		"buffer_size":               uint64(bufferSize),
		"entry_size":                uint64(entrySize),
		"byte_order":                byteOrder,
		"consistency":               payload["consistency"],
		"representation":            representation,
		"representation_note":       representationNote(representation),
		"system_paused_during_read": pausedDuringRead,
	}
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
	return okResult(value, tc.modern)
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
	Context string `json:"context"`
}

// runFrameCapture fetches the live rendered frame from the plugin as tightly
// packed RGB24 bytes and stores a PNG artifact. The raw pixel payload never
// reaches model context; the response is a compact summary plus the artifact
// descriptor.
func runFrameCapture(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[frameCaptureArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "frame_capture", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	rawDataBase64, _ := payload["data"].(string)
	rawRGB, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return failureResult(&toolFailure{Code: "bridge_error", Message: "decode base64 frame payload: " + err.Error()}, tc.modern)
	}
	widthValue, _ := payload["width"].(float64)
	heightValue, _ := payload["height"].(float64)
	width := int(widthValue)
	height := int(heightValue)
	if width <= 0 || height <= 0 || len(rawRGB) != width*height*3 {
		return failureResult(&toolFailure{
			Code:    "bridge_error",
			Message: fmt.Sprintf("frame payload does not match declared dimensions (%dx%d, %d bytes).", width, height, len(rawRGB)),
		}, tc.modern)
	}

	frame, err := rgb24ToNRGBA(rawRGB, width, height)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	var pngBuffer bytes.Buffer
	if err := png.Encode(&pngBuffer, frame); err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: "encode PNG: " + err.Error()}, tc.modern)
	}
	stored, err := tc.server.store.Put(context.ID, "frame-capture", "image/png", pngBuffer.Bytes())
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	frameToken, _ := payload["frame_token"].(float64)
	return okResult(map[string]any{
		"summary": map[string]any{
			"kind":           "frame-capture",
			"width":          width,
			"height":         height,
			"source_format":  "rgb24",
			"byte_order":     "not-applicable",
			"consistency":    "live",
			"frame_token":    uint64(frameToken),
			"png_size_bytes": pngBuffer.Len(),
			"sha256":         stored.SHA256,
		},
		"artifact": artifactDescriptor(tc.server, stored, context.ID),
	}, tc.modern)
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
	Offset  uint64 `json:"offset"`
	Count   uint64 `json:"count"`
	Context string `json:"context"`
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

// fetchVDPBytes reads raw bytes through the plugin timed-buffer path.
func fetchVDPBytes(tc toolContext, target string, address uint64, length uint64) ([]byte, *toolFailure) {
	payload, failure := tc.server.executeCommand(tc.ctx, "vdp_mem_read", map[string]string{
		"target":  target,
		"address": strconv.FormatUint(address, 10),
		"length":  strconv.FormatUint(length, 10),
	})
	if failure != nil {
		return nil, failure
	}
	rawDataBase64, _ := payload["data"].(string)
	raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return nil, &toolFailure{Code: "bridge_error", Message: "decode base64 vdp payload: " + err.Error()}
	}
	return raw, nil
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
	if _, failure = resolveContext(tc.server, parsed.Context); failure != nil {
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

	statusPayload, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
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
	raw, failure := fetchVDPBytes(tc, "vram", base, uint64(fetchCount)*8)
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

	value := map[string]any{
		"address_space":       "315-5313 VRAM",
		"sprite_table_base":   base,
		"byte_order":          "big-endian",
		"consistency":         "live",
		"entries":             window,
		"returned_entries":    len(window),
		"table_entries_valid": len(all),
		"paging":              map[string]any{"offset": offset, "count": len(window)},
		"chain":               chain,
		"layout_note":         "8 bytes per entry; X/Y are 9-bit offsets minus 128; link occupies bits 8-14 of word 1; chain starts at sprite 0 and ends when a link returns 0.",
	}
	return okResult(value, tc.modern)
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
	raw, failure := fetchVDPBytes(tc, "cram", 0, 128)
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

	paletteImg := renderPalettePNG(decoded)
	var pngBuffer bytes.Buffer
	if err := png.Encode(&pngBuffer, paletteImg); err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: "encode PNG: " + err.Error()}, tc.modern)
	}
	pngStored, err := tc.server.store.Put(context.ID, "vdp-palette", "image/png", pngBuffer.Bytes())
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	jsonDocument := buildPaletteJSON(decoded)
	jsonStored, err := tc.server.store.Put(context.ID, "vdp-palette-json", "application/json", jsonDocument)
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
			"kind":             "vdp-palette",
			"line_count":       4,
			"colors_per_line":  16,
			"nonzero_per_line": linesNonZero,
			"backdrop_color":   decoded[0]["color_hex"],
			"color_format":     "9-bit RGB expanded to 8-bit",
			"byte_order":       "big-endian",
			"consistency":      "live",
			"png_size_bytes":   pngBuffer.Len(),
			"png_sha256":       pngStored.SHA256,
			"json_size_bytes":  len(jsonDocument),
			"json_sha256":      jsonStored.SHA256,
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

func buildPaletteJSON(entries []map[string]any) []byte {
	type colorEntry struct {
		Index     int    `json:"index"`
		Word      int    `json:"word"`
		RGB333    [3]int `json:"rgb333_r_g_b"`
		RGB888Hex string `json:"rgb888_hex"`
	}
	document := struct {
		Kind        string           `json:"kind"`
		ColorFormat string           `json:"color_format"`
		ByteOrder   string           `json:"byte_order"`
		Lines       [][16]colorEntry `json:"lines"`
	}{}
	document.Kind = "vdp-palette"
	document.ColorFormat = "9-bit RGB expanded to 8-bit"
	document.ByteOrder = "big-endian"
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
		document.Lines = append(document.Lines, row)
	}
	data, _ := json.MarshalIndent(document, "", "  ")
	return data
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
	Tile            uint64 `json:"tile"`
	Count           uint64 `json:"count"`
	Palette         uint64 `json:"palette"`
	Scale           uint64 `json:"scale"`
	TransparentZero *bool  `json:"transparent_zero"`
	Context         string `json:"context"`
}

type vdpPlaneExportArgs struct {
	Plane           string `json:"plane"`
	Scale           uint64 `json:"scale"`
	TransparentZero *bool  `json:"transparent_zero"`
	Context         string `json:"context"`
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

func storeArtifactAndDescriptor(tc toolContext, contextID, kind, mimeType string, payload []byte) (artifact.Artifact, map[string]any, error) {
	stored, err := tc.server.store.Put(contextID, kind, mimeType, payload)
	if err != nil {
		return artifact.Artifact{}, nil, err
	}
	return stored, artifactDescriptor(tc.server, stored, contextID), nil
}

type exportedTile struct {
	Index   int                                     `json:"index"`
	Address int                                     `json:"vram_address"`
	Rows    [mdTileEdgePixels][mdTileEdgePixels]int `json:"pixel_indices"`
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

	statusPayload, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
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

	vram, coherent, failure := fetchVDPBytesChunked(tc, "vram", firstByte, totalBytes)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	cramRaw, _, failure := fetchVDPBytesChunked(tc, "cram", 0, 128)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	colors := cramPaletteColors(cramRGB333Entries(cramRaw))

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

	var pngBuffer bytes.Buffer
	if err := png.Encode(&pngBuffer, img); err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: "encode PNG: " + err.Error()}, tc.modern)
	}
	jsonDocument, err := json.MarshalIndent(struct {
		Kind       string         `json:"kind"`
		PixelOrder string         `json:"pixel_order"`
		ByteOrder  string         `json:"byte_order"`
		Palette    int            `json:"palette_line"`
		Tiles      []exportedTile `json:"tiles"`
	}{
		Kind:       "vdp-tiles",
		PixelOrder: "high-nibble-left",
		ByteOrder:  "big-endian",
		Palette:    int(parsed.Palette),
		Tiles:      tiles,
	}, "", "  ")
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	pngStored, pngDescriptor, err := storeArtifactAndDescriptor(tc, context.ID, "vdp-tiles", "image/png", pngBuffer.Bytes())
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	jsonStored, jsonDescriptor, err := storeArtifactAndDescriptor(tc, context.ID, "vdp-tiles-json", "application/json", jsonDocument)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	return okResult(map[string]any{
		"summary": map[string]any{
			"kind":                    "vdp-tiles",
			"tile_count":              count,
			"tile_size_bytes":         mdTileSizeBytes,
			"bpp":                     4,
			"vram_address_start":      firstByte,
			"vram_address_end":        firstByte + totalBytes - 1,
			"palette_line":            parsed.Palette,
			"nonzero_pixels_per_tile": nonzeroPerTile,
			"coherent_snapshot":       coherent,
			"consistency":             "live",
			"byte_order":              "big-endian",
			"layout_note":             "Each tile is 8x8 4bpp: four bytes per row, two pixels per byte, high nibble left. Pixel 0 is transparent unless transparent_zero is false.",
			"png_size_bytes":          pngBuffer.Len(),
			"png_sha256":              pngStored.SHA256,
			"json_size_bytes":         len(jsonDocument),
			"json_sha256":             jsonStored.SHA256,
		},
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

	if parsed.Plane != "a" && parsed.Plane != "b" && parsed.Plane != "window" {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: "vdp_plane_export plane must be one of: a, b, window.",
		}, tc.modern)
	}
	if scale < 1 || scale > maxVDPPlaneUpscale {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("vdp_plane_export scale must be between 1 and %d.", maxVDPPlaneUpscale),
		}, tc.modern)
	}

	statusPayload, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	decoded, _ := statusPayload["decoded"].(map[string]any)
	baseValue, _ := decoded["name_table_base_"+parsed.Plane].(float64)
	nameTableBase := uint64(baseValue)
	registers := statusRegisters(statusPayload)
	widthCells := planeCellSpan(registers[16])
	heightCells := planeCellSpan(registers[16] >> 4)
	interlaceActive := registers[12]&0x2 != 0

	vramAll, coherent, failure := fetchVDPBytesChunked(tc, "vram", 0, fetchVRAMSize(statusPayload))
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	cramRaw, _, failure := fetchVDPBytesChunked(tc, "cram", 0, 128)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	colors := cramPaletteColors(cramRGB333Entries(cramRaw))

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

	var pngBuffer bytes.Buffer
	if err := png.Encode(&pngBuffer, img); err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: "encode PNG: " + err.Error()}, tc.modern)
	}
	jsonDocument, err := json.MarshalIndent(struct {
		Kind            string      `json:"kind"`
		Plane           string      `json:"plane"`
		ByteOrder       string      `json:"byte_order"`
		NameEntryFormat string      `json:"name_entry_format"`
		NameTableBase   int         `json:"name_table_base"`
		SizeCells       [2]int      `json:"size_cells"`
		DistinctTiles   map[int]int `json:"distinct_tiles"`
		PriorityEntries int         `json:"priority_entries"`
		InvalidEntries  int         `json:"invalid_entries"`
		Truncated       bool        `json:"truncated"`
	}{
		Kind:            "vdp-plane",
		Plane:           parsed.Plane,
		ByteOrder:       "big-endian",
		NameEntryFormat: "bits 0-10 tile, 11 hflip, 12 vflip, 13-14 palette, 15 priority",
		NameTableBase:   int(nameTableBase),
		SizeCells:       [2]int{widthCells, heightCells},
		DistinctTiles:   histogram,
		PriorityEntries: priorityEntries,
		InvalidEntries:  invalidEntries,
		Truncated:       truncated,
	}, "", "  ")
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	pngStored, pngDescriptor, err := storeArtifactAndDescriptor(tc, context.ID, "vdp-plane", "image/png", pngBuffer.Bytes())
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	jsonStored, jsonDescriptor, err := storeArtifactAndDescriptor(tc, context.ID, "vdp-plane-json", "application/json", jsonDocument)
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

	return okResult(map[string]any{
		"summary": map[string]any{
			"kind":              "vdp-plane",
			"plane":             parsed.Plane,
			"name_table_base":   nameTableBase,
			"size_cells":        []int{widthCells, heightCells},
			"png_size_bytes":    pngBuffer.Len(),
			"png_width":         width,
			"png_height":        height,
			"png_sha256":        pngStored.SHA256,
			"json_size_bytes":   len(jsonDocument),
			"json_sha256":       jsonStored.SHA256,
			"distinct_tiles":    len(histogram),
			"priority_entries":  priorityEntries,
			"invalid_entries":   invalidEntries,
			"truncated":         truncated,
			"interlace_active":  interlaceActive,
			"coherent_snapshot": coherent,
			"consistency":       "live",
			"byte_order":        "big-endian",
			"notes":             notes,
		},
		"artifacts": []map[string]any{pngDescriptor, jsonDescriptor},
	}, tc.modern)
}
