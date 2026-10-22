package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// capture is the single capture tool (roadmap issue #17). One concept: "freeze a
// set of components and keep them resolvable". components names what to capture,
// mode says whether the sample must be one paused instant or may be live, and the
// response always carries one capture_id, one manifest, and the artifacts.
//
// The merged tool routes to the producer that can capture the requested
// components, and never reimplements them: the response's summary, artifacts and
// manifest are the producer's own, so provenance, consistency (#1/#4/#8), schema
// versions (#18), and capture indexing (#2/#3/#10) are unchanged. The routing
// table is closed and published in the error, so an unsupported combination is
// rejected with the supported alternatives instead of being approximated.

const (
	captureComponentMemory    = "memory"
	captureComponentRegisters = "registers"
	captureComponentVDP       = "vdp"
	captureComponentFrame     = "frame"
	captureComponentCRAM      = "cram"
	captureComponentVSRAM     = "vsram"
	captureComponentVRAM      = "vram"
	captureComponentSprites   = "sprites"

	captureProducerMemory = "memory"
	captureProducerSystem = "system"
	captureProducerVDP    = "vdp"
)

// captureComponentVocab is the closed component vocabulary.
var captureComponentVocab = newEnumVocab("components",
	captureComponentMemory,
	captureComponentRegisters,
	captureComponentVDP,
	captureComponentFrame,
	captureComponentCRAM,
	captureComponentVSRAM,
	captureComponentVRAM,
	captureComponentSprites,
)

// captureModeVocab is declared in consistency.go for the capture guard, whose
// values are live/paused. The merged tool's mode answers a different question
// (atomic vs live sampling), so it owns its own vocabulary over the same
// capture_consistency states.
var captureSelectionModeVocab = newEnumVocab("mode", consistencyAtomic, consistencyLive)

type captureArgs struct {
	Components []string           `json:"components"`
	Mode       string             `json:"mode"`
	Space      string             `json:"space"`
	Ranges     []captureRangeArgs `json:"ranges"`
	// VRAM options apply to the vdp producer.
	VRAMAddress              any     `json:"vram_address"`
	AddressSpace             string  `json:"address_space"`
	VRAMLength               uint64  `json:"vram_length"`
	Context                  string  `json:"context"`
	ExpectedTargetGeneration *uint64 `json:"expected_target_generation"`
	ControlID                string  `json:"control_id"`
}

func captureSpec() toolSpec {
	return toolSpec{
		name:        "capture",
		description: "Capture target state into one resolvable capture: components selects what to freeze (memory, registers, vdp, frame, cram, vsram, vram, sprites) and mode selects the sampling guarantee (atomic pauses once, samples, and restores the prior run state; live never pauses). The tool routes to the producer that owns the requested component set: components [\"memory\"] with ranges uses the paused memory snapshot; a set that includes memory plus CPU/VDP/frame components captures a system snapshot with exactly the listed A/V components; a set without memory (VDP status, frame, CRAM, VSRAM, VRAM, sprites) uses the VDP capture, where requesting sprites implies the VRAM component they live in. mode live is available only for the VDP producer, because a memory or system composite cannot be live without describing different instants. The response reports producer, mode, capture_id, the producer's manifest descriptor, its artifacts, and the producer summary and payload under detail, so provenance, consistency, byte order and schema versions are the ones the producer publishes. Every artifact is also resolvable later with capture_get or artifact_list{capture_id}. An unsupported component combination is rejected with the supported ones.",
		schema: objectSchema(map[string]any{
			"components": map[string]any{
				"type":        "array",
				"description": "Components to capture. memory needs ranges; memory plus CPU/VDP/frame components selects the system producer; a set without memory selects the VDP producer; sprites implies vram.",
				"items":       map[string]any{"type": "string", "enum": captureComponentVocab.values},
				"minItems":    1,
			},
			"mode":  captureModeVocab.property("Sampling guarantee: atomic (default) pauses once, samples every component in that instant, and restores the prior run state; live never pauses and is available only for the VDP producer."),
			"space": stringProperty("Default memory space id for ranges (required with the memory component unless every range names one)."),
			"ranges": map[string]any{
				"type":        "array",
				"description": fmt.Sprintf("Named memory ranges for the memory component (1-%d, total bytes capped at %d).", captureMaxRanges, dumpCapBytes),
				"items": map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"name":          stringProperty(fmt.Sprintf("Unique range label (max %d characters, letters/digits/_/-).", captureMaxRangeNameLen)),
						"address":       addressProperty(),
						"address_space": stringProperty("Optional domain of this range address; omitted means the capture space."),
						"length":        integerProperty("Byte length between 1 and the dump cap.", 1),
					},
					"required": []string{"name", "address", "length"},
				},
				"minItems": 1,
				"maxItems": captureMaxRanges,
			},
			"vram_address":               addressProperty(),
			"vram_length":                integerProperty("VDP producer: VRAM bytes to capture (default 65536, cap 131072).", 1),
			"context":                    contextProperty(),
			"expected_target_generation": integerProperty("Optional target generation the caller last observed; accepted by the memory and system producers and rejected by the VDP producer, which does not mutate the target.", 1),
			"control_id":                 stringProperty("Optional control id from target_control_acquire; accepted by the memory and system producers and rejected by the VDP producer."),
		}, []string{"components"}),
		run: runCapture,
	}
}

func runCapture(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[captureArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	components, failure := resolveCaptureComponents(parsed.Components)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	mode, failure := captureSelectionModeVocab.resolve(parsed.Mode, consistencyAtomic)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	producer, included, failure := planCapture(components, parsed, mode)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := validateCaptureArguments(producer, parsed); failure != nil {
		return failureResult(failure, tc.modern)
	}

	var payload map[string]any
	switch producer {
	case captureProducerMemory:
		if mode != consistencyAtomic {
			return failureResult(captureLiveUnsupported(producer), tc.modern)
		}
		arguments := map[string]any{
			"space":   parsed.Space,
			"ranges":  captureRangeArguments(parsed.Ranges, false),
			"context": parsed.Context,
		}
		putGuardArguments(arguments, parsed.ControlID, parsed.ExpectedTargetGeneration)
		payload, failure = composeTool(tc, runMemorySnapshotCapture, arguments)
	case captureProducerSystem:
		if mode != consistencyAtomic {
			return failureResult(captureLiveUnsupported(producer), tc.modern)
		}
		arguments := map[string]any{
			"space":                  parsed.Space,
			"memory_ranges":          captureRangeArguments(parsed.Ranges, true),
			"include_m68k_registers": included[captureComponentRegisters],
			"include_z80_registers":  included[captureComponentRegisters],
			"include_vdp_status":     included[captureComponentVDP],
			"include_frame":          included[captureComponentFrame],
			"include_cram":           included[captureComponentCRAM],
			"include_vsram":          included[captureComponentVSRAM],
			"include_vram":           included[captureComponentVRAM],
			"include_sprite_table":   included[captureComponentSprites],
			"vram_length":            parsed.VRAMLength,
			"context":                parsed.Context,
		}
		if parsed.VRAMAddress != nil {
			arguments["vram_address"] = parsed.VRAMAddress
		}
		if parsed.AddressSpace != "" {
			arguments["address_space"] = parsed.AddressSpace
		}
		putGuardArguments(arguments, parsed.ControlID, parsed.ExpectedTargetGeneration)
		payload, failure = composeTool(tc, runSystemSnapshot, arguments)
	default:
		// The VDP producer has no guard arguments: it captures control-lock-free
		// state. The capture mode is its own capture_mode vocabulary.
		captureMode := captureModeLive
		if mode == consistencyAtomic {
			captureMode = captureModePaused
		}
		arguments := map[string]any{
			"include_frame":        included[captureComponentFrame],
			"include_cram":         included[captureComponentCRAM],
			"include_vsram":        included[captureComponentVSRAM],
			"include_vram":         included[captureComponentVRAM] || included[captureComponentSprites],
			"include_sprite_table": included[captureComponentSprites],
			"capture_mode":         captureMode,
			"context":              parsed.Context,
		}
		if parsed.VRAMAddress != nil {
			arguments["vram_address"] = parsed.VRAMAddress
		}
		if parsed.AddressSpace != "" {
			arguments["address_space"] = parsed.AddressSpace
		}
		if parsed.VRAMLength != 0 {
			arguments["vram_length"] = parsed.VRAMLength
		}
		payload, failure = composeTool(tc, runVDPCapture, arguments)
	}
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	summary, _ := payload["summary"].(map[string]any)
	result := map[string]any{
		"producer":   producer,
		"mode":       mode,
		"components": components,
		"capture_id": captureIDFromProducerPayload(payload),
		"summary":    summary,
		"detail":     payload,
	}
	if manifest, present := payload["manifest"]; present {
		result["manifest"] = manifest
	}
	if artifacts, present := payload["artifacts"]; present {
		result["artifacts"] = artifacts
	}
	if consistency, present := summary["capture_consistency"]; present {
		result["capture_consistency"] = consistency
	}
	return okResult(result, tc.modern)
}

// resolveCaptureComponents validates and de-duplicates the component set.
func resolveCaptureComponents(requested []string) ([]string, *toolFailure) {
	if len(requested) == 0 {
		return nil, &toolFailure{
			Code:    "invalid_params",
			Message: "components must name at least one component to capture",
			Data:    map[string]any{"field": "components", "allowed": captureComponentVocab.valuesEcho()},
		}
	}
	seen := map[string]bool{}
	components := make([]string, 0, len(requested))
	for _, component := range requested {
		if failure := captureComponentVocab.validate(component); failure != nil {
			return nil, failure
		}
		if seen[component] {
			return nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("components lists %q twice", component),
				Data:    map[string]any{"field": "components", "value": component},
			}
		}
		seen[component] = true
		components = append(components, component)
	}
	return components, nil
}

// planCapture selects the producer for one component set and resolves the
// producer's include flags.
func planCapture(components []string, parsed *captureArgs, mode string) (string, map[string]bool, *toolFailure) {
	included := make(map[string]bool, len(components))
	for _, component := range components {
		included[component] = true
	}
	onlyVDP := true
	for _, component := range components {
		switch component {
		case captureComponentVDP, captureComponentFrame, captureComponentCRAM, captureComponentVSRAM, captureComponentVRAM, captureComponentSprites:
		default:
			onlyVDP = false
		}
	}
	memory := included[captureComponentMemory]
	switch {
	case memory && len(components) > 1:
		// memory plus any other component is the system snapshot: it is the only
		// producer that can hold memory and CPU/VDP pieces in one paused window.
		return captureProducerSystem, included, nil
	case memory:
		// memory alone: the paused memory snapshot is the cheapest producer that
		// owns the component.
		return captureProducerMemory, included, nil
	case onlyVDP:
		return captureProducerVDP, included, nil
	default:
		return "", nil, &toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("components %s cannot be captured in one call; supported sets are [\"memory\"] with ranges, memory plus any of registers/vdp/frame/cram/vsram/vram/sprites, and any set drawn from vdp/frame/cram/vsram/vram/sprites", strings.Join(components, ",")),
			Data: map[string]any{
				"field":      "components",
				"components": components,
				"supported": []string{
					"[memory] + ranges",
					"[memory, registers|vdp|frame|cram|vsram|vram|sprites] + ranges",
					"[vdp|frame|cram|vsram|vram|sprites]",
				},
			},
		}
	}
}

// captureLiveUnsupported explains why a composite producer has no live mode.
func captureLiveUnsupported(producer string) *toolFailure {
	return &toolFailure{
		Code:    "invalid_params",
		Message: fmt.Sprintf("mode live is not available for the %s producer: a composite read without a paused window describes different instants, which is exactly what capture_consistency would have to report as composite_non_atomic; request mode atomic, or capture only VDP components for a live sample", producer),
		Data:    map[string]any{"field": "mode", "producer": producer, "allowed": []string{consistencyAtomic}},
	}
}

// validateCaptureArguments rejects producer-specific arguments the selected
// producer does not consume.
func validateCaptureArguments(producer string, parsed *captureArgs) *toolFailure {
	reject := func(field, reason string) *toolFailure {
		return &toolFailure{
			Code:    "unsupported_parameter",
			Message: fmt.Sprintf("%s is not consumed by the %s producer: %s", field, producer, reason),
			Data:    map[string]any{"field": field, "path": "$." + field, "producer": producer},
		}
	}
	if producer == captureProducerVDP {
		if parsed.ControlID != "" {
			return reject("control_id", "the VDP producer does not mutate the target")
		}
		if parsed.ExpectedTargetGeneration != nil {
			return reject("expected_target_generation", "the VDP producer does not mutate the target")
		}
		if parsed.Space != "" {
			return reject("space", "only the memory and system producers read memory ranges")
		}
		if len(parsed.Ranges) > 0 {
			return reject("ranges", "only the memory and system producers read memory ranges")
		}
		return nil
	}
	if parsed.VRAMLength != 0 {
		return reject("vram_length", "it sizes the VDP VRAM component, which this producer does not capture")
	}
	if parsed.VRAMAddress != nil {
		return reject("vram_address", "it is the start of the VDP VRAM component, which this producer does not capture")
	}
	if parsed.AddressSpace != "" {
		return reject("address_space", "it is the domain of vram_address, which this producer does not capture")
	}
	if len(parsed.Ranges) == 0 {
		return &toolFailure{
			Code:    "invalid_params",
			Message: "ranges is required with the memory component",
			Data:    map[string]any{"field": "ranges"},
		}
	}
	if parsed.Space == "" {
		return &toolFailure{
			Code:    "invalid_params",
			Message: "space is required with the memory component: every range is read from one address space",
			Data:    map[string]any{"field": "space"},
		}
	}
	return nil
}

// captureRangeArguments renders the merged range list for one producer. The
// system producer takes a per-range space, the memory producer takes the
// top-level space.
func captureRangeArguments(ranges []captureRangeArgs, withSpace bool) []map[string]any {
	arguments := make([]map[string]any, 0, len(ranges))
	for _, entry := range ranges {
		rangeArguments := map[string]any{
			"name":          entry.Name,
			"address":       entry.Address,
			"length":        entry.Length,
			"space":         entry.Space,
			"address_space": entry.AddressSpace,
		}
		if entry.AddressSpace == "" {
			delete(rangeArguments, "address_space")
		}
		if !withSpace {
			delete(rangeArguments, "space")
		}
		arguments = append(arguments, rangeArguments)
	}
	return arguments
}

// putGuardArguments copies the optional mutation guards into a composed call.
func putGuardArguments(arguments map[string]any, controlID string, expected *uint64) {
	if controlID != "" {
		arguments["control_id"] = controlID
	}
	if expected != nil {
		arguments["expected_target_generation"] = *expected
	}
}

// captureIDFromProducerPayload reads the capture id a producer published in its
// summary.
func captureIDFromProducerPayload(payload map[string]any) any {
	if summary, ok := payload["summary"].(map[string]any); ok {
		if id, present := summary["capture_id"]; present {
			return id
		}
	}
	return nil
}
