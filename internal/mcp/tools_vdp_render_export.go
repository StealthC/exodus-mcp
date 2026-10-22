package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
)

// vdp_render_export is the single VDP image-export tool (roadmap issue #17). One
// concept: "render a piece of the VDP as an image artifact". mode selects what is
// rendered (a strip of 8x8 tiles, or a scroll plane), and every mode keeps the
// handler it had: the merged tool only adds the mode/crop dispatch.
//
// crop is the merged tool's addition: an optional rectangular window in source
// pixels before upscaling, so one call can export a region instead of a whole
// plane.

const (
	renderModeTiles = "tiles"
	renderModePlane = "plane"
)

// renderModeVocab is the closed render-mode vocabulary.
var renderModeVocab = newEnumVocab("mode", renderModeTiles, renderModePlane)

type vdpRenderExportArgs struct {
	Mode            string          `json:"mode"`
	Crop            *renderCropArgs `json:"crop"`
	Tile            uint64          `json:"tile"`
	Count           uint64          `json:"count"`
	Palette         uint64          `json:"palette"`
	Scale           uint64          `json:"scale"`
	TransparentZero *bool           `json:"transparent_zero"`
	VDPCaptureID    string          `json:"vdp_capture_id"`
	Plane           string          `json:"plane"`
	Context         string          `json:"context"`
}

func vdpRenderExportSpec() toolSpec {
	return toolSpec{
		name:        "vdp_render_export",
		description: fmt.Sprintf("Render part of the VDP as image artifacts. mode \"tiles\" exports one or more consecutive 8x8 4bpp VRAM patterns as a scaled PNG plus a JSON pixel decode, colored through a CRAM palette line (tile, count 1-%d, palette 0-3, scale 1-%d); mode \"plane\" renders a whole scroll plane (A, B, or window) as an unscrolled texture view plus its structural JSON summary (scale 1-%d). Both modes accept an optional crop window in source pixels before scaling, and both resolve vdp_capture_id to render from a stored capture instead of reading the device (data_source \"capture\", no device read, byte-identical output). Reports system_paused_during_read and coherent_snapshot, and links both artifacts to one capture_id.", maxVDPTileStripCount, maxVDPTileUpscale, maxVDPPlaneUpscale),
		schema: objectSchema(map[string]any{
			"mode":             renderModeVocab.property("What to render: tiles (a consecutive tile strip) or plane (a whole scroll plane)."),
			"crop":             renderCropSchemaProperty(),
			"tile":             integerProperty("mode tiles: first tile index counted from VRAM offset 0 (default 0). Each tile occupies 32 bytes.", 0),
			"count":            integerProperty(fmt.Sprintf("mode tiles: consecutive tile count between 1 and %d (default 1).", maxVDPTileStripCount), 1),
			"palette":          integerProperty("mode tiles: CRAM palette line 0-3 used to color pixel indices 1-15 (default 0).", 0),
			"scale":            integerProperty("Nearest-neighbor upscale factor (tiles 1-32 default 8; plane 1-4 default 1).", 1),
			"transparent_zero": booleanProperty("Render pixel index 0 as transparent instead of its palette color (default true)."),
			"plane":            vdpPlaneVocab.property("mode plane: which name table to render."),
			"vdp_capture_id":   stringProperty("Optional capture_id from capture/vdp_capture; when set, the render uses the capture's stored VRAM, CRAM and status components and performs no device read."),
			"context":          contextProperty(),
		}, []string{"mode"}),
		run: runVDPRenderExport,
	}
}

// renderCropSchemaProperty publishes the crop window of a rendered export.
func renderCropSchemaProperty() map[string]any {
	return map[string]any{
		"type":                 "object",
		"description":          "Optional rectangular window of the rendered image, in source pixels before scaling (one tile is 8x8 source pixels). The returned image and its png_width/png_height describe the cropped region.",
		"additionalProperties": false,
		"properties": map[string]any{
			"x":      integerProperty("Left edge in source pixels.", 0),
			"y":      integerProperty("Top edge in source pixels.", 0),
			"width":  integerProperty("Crop width in source pixels.", 1),
			"height": integerProperty("Crop height in source pixels.", 1),
		},
		"required": []string{"width", "height"},
	}
}

func runVDPRenderExport(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpRenderExportArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.Mode == "" {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: "mode is required: tiles or plane",
			Data:    map[string]any{"field": "mode", "allowed": renderModeVocab.valuesEcho()},
		}, tc.modern)
	}
	mode, failure := renderModeVocab.resolve(parsed.Mode, renderModeTiles)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	raw, failure := decodeArgumentMap(args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := validateRenderModeArguments(raw, mode); failure != nil {
		return failureResult(failure, tc.modern)
	}

	if mode == renderModePlane {
		if parsed.Plane == "" {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "plane is required with mode plane", Data: map[string]any{"field": "plane"}}, tc.modern)
		}
		payload, failure := composeTool(tc, runVDPPlaneExport, map[string]any{
			"plane":            parsed.Plane,
			"scale":            parsed.Scale,
			"transparent_zero": parsed.TransparentZero,
			"vdp_capture_id":   parsed.VDPCaptureID,
			"context":          parsed.Context,
			"crop":             parsed.Crop,
		})
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		payload["mode"] = mode
		return okResult(payload, tc.modern)
	}

	payload, failure := composeTool(tc, runVDPTileExport, map[string]any{
		"tile":             parsed.Tile,
		"count":            parsed.Count,
		"palette":          parsed.Palette,
		"scale":            parsed.Scale,
		"transparent_zero": parsed.TransparentZero,
		"vdp_capture_id":   parsed.VDPCaptureID,
		"context":          parsed.Context,
		"crop":             parsed.Crop,
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload["mode"] = mode
	return okResult(payload, tc.modern)
}

// renderModeAcceptedFields lists the arguments one mode consumes.
func renderModeAcceptedFields(mode string) []string {
	common := []string{"mode", "crop", "scale", "transparent_zero", "vdp_capture_id", "context"}
	if mode == renderModePlane {
		return append(common, "plane")
	}
	return append(common, "tile", "count", "palette")
}

// validateRenderModeArguments rejects an argument outside the selected mode's
// contract, so a caller never believes a field it sent had an effect.
func validateRenderModeArguments(raw map[string]json.RawMessage, mode string) *toolFailure {
	accepted := renderModeAcceptedFields(mode)
	allowed := make(map[string]bool, len(accepted))
	for _, name := range accepted {
		allowed[name] = true
	}
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if allowed[key] {
			continue
		}
		return &toolFailure{
			Code:    "unsupported_parameter",
			Message: fmt.Sprintf("%q is not consumed by vdp_render_export{mode:%q}", key, mode),
			Data: map[string]any{
				"field":           key,
				"path":            "$." + key,
				"accepted_fields": accepted,
				"mode":            mode,
			},
		}
	}
	return nil
}
