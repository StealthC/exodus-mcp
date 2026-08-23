package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
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
