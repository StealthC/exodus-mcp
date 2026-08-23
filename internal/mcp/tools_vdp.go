package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
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
	raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return failureResult(&toolFailure{Code: "bridge_error", Message: "decode base64 vdp memory payload: " + err.Error()}, tc.modern)
	}

	value := map[string]any{
		"target":              parsed.Target,
		"address_space":       addressSpace,
		"address":             address,
		"length":              len(raw),
		"buffer_size":         uint64(bufferSize),
		"entry_size":          uint64(entrySize),
		"byte_order":          byteOrder,
		"consistency":         payload["consistency"],
		"representation":      representation,
		"representation_note": representationNote(representation),
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
		return "CRAM entries are 9-bit RGB (3 bits per channel, R in bits 0-2); channels scale to 8-bit by (c*255+3)/7."
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
		r9 := word & 0x07
		g9 := (word >> 3) & 0x07
		b9 := (word >> 6) & 0x07
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
