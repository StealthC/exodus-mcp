package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"strconv"
	"time"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

const systemSnapshotSchema = "system-snapshot/1"

type systemSnapshotArgs struct {
	Space string `json:"space"`
	// AddressSpace is the published optional domain of the supplied address
	// (injected by objectSchema because the tool has vram_address). The decoder
	// must accept it: rejecting a property the schema advertises made the field
	// unusable for every client that followed the published contract.
	AddressSpace             string             `json:"address_space"`
	MemoryRanges             []captureRangeArgs `json:"memory_ranges"`
	IncludeM68K              *bool              `json:"include_m68k_registers"`
	IncludeZ80               *bool              `json:"include_z80_registers"`
	IncludeVDPStatus         *bool              `json:"include_vdp_status"`
	IncludeFrame             *bool              `json:"include_frame"`
	IncludeCRAM              *bool              `json:"include_cram"`
	IncludeVSRAM             *bool              `json:"include_vsram"`
	IncludeVRAM              *bool              `json:"include_vram"`
	VRAMAddress              any                `json:"vram_address"`
	VRAMLength               uint64             `json:"vram_length"`
	IncludeSpriteTable       *bool              `json:"include_sprite_table"`
	Context                  string             `json:"context"`
	ControlID                string             `json:"control_id"`
	ExpectedTargetGeneration *uint64            `json:"expected_target_generation"`
}

func systemSnapshotToolSpec() toolSpec {
	boolProp := func(text string) map[string]any { return booleanProperty(text) }
	return toolSpec{name: "system_snapshot_capture", description: "Capture a temporally atomic, artifact-first snapshot of memory, CPU registers, VDP state, and the rendered frame. The server pauses once when needed, performs all selected reads in that window, and restores the prior run state. The versioned system-snapshot/1 manifest links every component with one capture_id and records consistency, generation, ROM identity, byte order, address domains, and omitted/unavailable components. This tool has no live mode. Each memory range declares its own space or falls back to the top-level space; address_space is the optional domain of vram_address only, and every memory component records the real space id, device, and space-relative plus bus start address in its provenance.", schema: objectSchema(map[string]any{
		"space":                  stringProperty("Default memory space id for ranges that omit space."),
		"memory_ranges":          map[string]any{"type": "array", "description": fmt.Sprintf("Named memory ranges (1-%d; total capped at %d bytes).", captureMaxRanges, dumpCapBytes), "items": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"name": stringProperty("Range name."), "address": addressProperty(), "address_space": stringProperty("Address domain; omitted means space."), "length": integerProperty("Range length.", 1), "space": stringProperty("Memory space id; defaults to the address domain.")}, "required": []string{"name", "address", "length"}}, "minItems": 1, "maxItems": captureMaxRanges},
		"include_m68k_registers": boolProp("Include M68K registers (default true)."), "include_z80_registers": boolProp("Include Z80 registers (default true)."), "include_vdp_status": boolProp("Include VDP status (default true)."), "include_frame": boolProp("Include rendered PNG frame (default true)."), "include_cram": boolProp("Include CRAM bytes (default true)."), "include_vsram": boolProp("Include VSRAM bytes (default true)."), "include_vram": boolProp("Include VRAM range (default false)."), "vram_address": addressProperty(), "vram_length": integerProperty("VRAM length, capped at 131072 bytes.", 1), "include_sprite_table": boolProp("Include sprite-table data when available (default true)."),
		"context": contextProperty(), "expected_target_generation": integerProperty("Expected target generation.", 1), "control_id": stringProperty("Existing target control lock."),
	}, []string{"memory_ranges"}), run: runSystemSnapshot}
}

func systemBool(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func runSystemSnapshot(tc toolContext, args json.RawMessage) map[string]any {
	p, failure := decodeArgs[systemSnapshotArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	ctx, failure := resolveContext(tc.server, p.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if p.ExpectedTargetGeneration != nil {
		if f := targetGenerationPrecondition(tc.server, *p.ExpectedTargetGeneration); f != nil {
			return failureResult(f, tc.modern)
		}
	}
	// A named range carries its own space; default only from the explicit
	// top-level space. Promoting address_space into space silently ignored the
	// caller's address domain and skipped translation.
	ranges := make([]captureRange, 0, len(p.MemoryRanges))
	seen := map[string]bool{}
	var total uint64
	if len(p.MemoryRanges) < 1 || len(p.MemoryRanges) > captureMaxRanges {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "memory_ranges must hold between 1 and 16 entries"}, tc.modern)
	}
	for i, r := range p.MemoryRanges {
		space := r.Space
		if space == "" {
			space = p.Space
		}
		if space == "" {
			return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("memory_ranges[%d].space is required", i)}, tc.modern)
		}
		if seen[r.Name] {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "memory range names must be unique"}, tc.modern)
		}
		seen[r.Name] = true
		addr, f := resolveAddress(r.Address, r.AddressSpace, space)
		if f != nil {
			return failureResult(f, tc.modern)
		}
		if r.Length < 1 || r.Length > dumpCapBytes || total+r.Length > dumpCapBytes {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "memory_ranges exceed the per-range or total byte cap"}, tc.modern)
		}
		total += r.Length
		ranges = append(ranges, captureRange{Name: r.Name, Space: space, Address: addr, Length: r.Length})
	}
	vramLen := p.VRAMLength
	if vramLen == 0 {
		vramLen = 65536
	}
	if vramLen > 131072 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "vram_length capped at 131072"}, tc.modern)
	}
	vramAddr := uint64(0)
	if p.VRAMAddress != nil {
		vramAddr, failure = resolveAddress(p.VRAMAddress, p.AddressSpace, "mem-vdp-vram")
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
	}

	controlID := p.ControlID
	internal := false
	if controlID == "" {
		lock, err := tc.server.controls.Acquire("system_snapshot_capture", ctx.ID, 120*time.Second, tc.server.target.Generation())
		if err != nil {
			return failureResult(&toolFailure{Code: "target_control_held", Message: err.Error()}, tc.modern)
		}
		controlID = lock.ID
		internal = true
		defer func() {
			if err := tc.server.controls.Release(controlID, "capture_completed"); err != nil {
				// The capture result is already committed; lock expiry also
				// guarantees eventual release if this bookkeeping path fails.
			}
		}()
	} else if !tc.server.controls.Valid(controlID) {
		return failureResult(&toolFailure{Code: "target_control_held", Message: "control_id does not own the active target control lock"}, tc.modern)
	}
	initial, initialKnown := observedRunState(tc)
	initialToken := currentFrameToken(tc)
	genBefore := tc.server.target.Generation()
	// The pause is the only mutation that may carry the caller's expected
	// generation; the restore that closes the window carries the control id
	// alone, because the pause already advanced the generation.
	openGuard := newWindowOpenGuard(controlID, p.ExpectedTargetGeneration)
	closeGuard := windowCloseGuard(controlID)
	resume := func() (map[string]any, *toolFailure) {
		payload, _, _, f := tc.server.executeMutation(tc.ctx, mutationCall{tool: "system_snapshot_capture", operation: "cpu_control", params: map[string]string{"action": "run"}, guard: closeGuard, contextID: ctx.ID})
		if f != nil {
			return nil, f
		}
		tc.server.runState.setByMCP(true)
		return payload, nil
	}
	window := &captureWindow{
		Mode:            captureModePaused,
		InitialRunState: initial,
		InitialKnown:    initialKnown,
		InitialToken:    initialToken,
	}
	running, known := tc.server.runState.currentState()
	wasRunning := !known || running
	window.PausedByTool = wasRunning
	if wasRunning {
		pausedPayload, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{tool: "system_snapshot_capture", operation: "cpu_control", params: map[string]string{"action": "pause"}, guard: openGuard, contextID: ctx.ID})
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		tc.server.runState.setByMCP(false)
		if state, ok := payloadRunState(pausedPayload); ok {
			window.PauseVerified = state == runStatePaused
		}
	}
	captureID := newCaptureID()
	at := time.Now().UTC()
	consistency := &artifact.CaptureConsistency{State: consistencyAtomic, ExecutionPausedByTool: wasRunning, InitialRunState: initial, InitialFrameToken: initialToken}
	window.Consistency = consistency
	components := map[string]any{}
	artifacts := []map[string]any{}
	captureComponents := []artifact.CaptureComponent{}
	var captureFrameToken *uint64
	// markSkipped records a component the producer did not capture, in the
	// manifest and in the capture index, so capture_get lists it instead of
	// hiding it.
	markSkipped := func(name string, unavailable bool, reason string) {
		entry := map[string]any{"omitted": true}
		if unavailable {
			entry = map[string]any{"unavailable": true}
		}
		if reason != "" {
			entry["reason"] = reason
		}
		components[name] = entry
		captureComponents = append(captureComponents, omittedCaptureComponent(name, !unavailable, unavailable, reason))
	}
	fail := func(f *toolFailure) map[string]any {
		window.closeWindow(tc, resume)
		if f.Data == nil {
			f.Data = map[string]any{}
		}
		f.Data["run_state_restore"] = window.restoreView()
		if window.RestoreFailure != nil {
			f.Data[runStateRestoreFailed] = true
		}
		return failureResult(f, tc.modern)
	}
	addJSON := func(name, kind string, value any) *toolFailure {
		b, e := json.MarshalIndent(value, "", "  ")
		if e != nil {
			return &toolFailure{Code: "artifact_error", Message: e.Error()}
		}
		prov := genericProvenance(tc.server, kind, at)
		prov.CaptureID = captureID
		prov.CaptureConsistency = consistency
		a, e := tc.server.store.PutWithProvenance(ctx.ID, kind, "application/json", b, prov)
		if e != nil {
			return &toolFailure{Code: "artifact_error", Message: e.Error()}
		}
		window.track(a)
		d := artifactDescriptor(tc.server, a, ctx.ID)
		components[name] = d
		artifacts = append(artifacts, d)
		captureComponents = append(captureComponents, captureComponentFromProvenance(name, a))
		return nil
	}
	addRaw := func(name, kind, space string, addr uint64, raw []byte, payload map[string]any) *toolFailure {
		prov := captureProvenance(tc.server, kind, space, addr, uint64(len(raw)), payload, at, captureID, consistency)
		a, e := tc.server.store.PutWithProvenance(ctx.ID, kind, "application/octet-stream", raw, prov)
		if e != nil {
			return &toolFailure{Code: "artifact_error", Message: e.Error()}
		}
		window.track(a)
		d := artifactDescriptor(tc.server, a, ctx.ID)
		components[name] = d
		artifacts = append(artifacts, d)
		captureComponents = append(captureComponents, captureComponentFromProvenance(name, a))
		return nil
	}
	for _, r := range ranges {
		payload, f := tc.server.executeCommand(tc.ctx, "mem_read", map[string]string{"space": r.Space, "address": strconv.FormatUint(r.Address, 10), "length": strconv.FormatUint(r.Length, 10)})
		if f != nil {
			return fail(f)
		}
		raw, e := base64.StdEncoding.DecodeString(fmt.Sprint(payload["data"]))
		if e != nil {
			return fail(&toolFailure{Code: "bridge_error", Message: e.Error()})
		}
		// The range name is a label, never an address domain: provenance carries
		// the real space id, its device, and both the space-relative and bus form
		// of the start address through the shared memory-range envelope builder.
		if f = addRaw("memory:"+r.Name, "system-memory", r.Space, r.Address, raw, payload); f != nil {
			return fail(f)
		}
	}
	readJSON := func(name, cmd string, params map[string]string, kind string) *toolFailure {
		v, f := tc.server.executeCommand(tc.ctx, cmd, params)
		if f != nil {
			return f
		}
		return addJSON(name, kind, v)
	}
	if systemBool(p.IncludeM68K, true) {
		if f := readJSON("m68k_registers", "regs_get", map[string]string{"cpu": "m68k"}, "system-m68k-registers"); f != nil {
			return fail(f)
		}
	} else {
		markSkipped("m68k_registers", false, "include_m68k_registers=false")
	}
	if systemBool(p.IncludeZ80, true) {
		if f := readJSON("z80_registers", "regs_get", map[string]string{"cpu": "z80"}, "system-z80-registers"); f != nil {
			return fail(f)
		}
	} else {
		markSkipped("z80_registers", false, "include_z80_registers=false")
	}
	if systemBool(p.IncludeVDPStatus, true) {
		if f := readJSON("vdp_status", "vdp_status", nil, "system-vdp-status"); f != nil {
			return fail(f)
		}
	} else {
		markSkipped("vdp_status", false, "include_vdp_status=false")
	}
	for _, spec := range []struct {
		name, target string
		on           *bool
		addr, length uint64
	}{{"cram", "cram", p.IncludeCRAM, 0, 128}, {"vsram", "vsram", p.IncludeVSRAM, 0, 80}, {"vram", "vram", p.IncludeVRAM, vramAddr, vramLen}} {
		if systemBool(spec.on, spec.name != "vram") {
			raw, _, f := fetchVDPBytesChunked(tc, spec.target, spec.addr, spec.length)
			if f != nil {
				return fail(f)
			}
			if f = addRaw(spec.name, "system-vdp-"+spec.name, "mem-vdp-"+spec.name, spec.addr, raw, map[string]any{"byte_order": "big-endian", "address_space": "mem-vdp-" + spec.name, "effective_address": float64(spec.addr)}); f != nil {
				return fail(f)
			}
		} else {
			markSkipped(spec.name, false, "not requested")
		}
	}
	if systemBool(p.IncludeSpriteTable, true) {
		// The native bridge does not expose a raw sprite-table operation. Do not
		// substitute a status read and label it as sprite data.
		markSkipped("sprite_table", true, "the native bridge does not expose sprite-table capture; use vdp_sprite_table after this manifest")
	} else {
		markSkipped("sprite_table", false, "include_sprite_table=false")
	}
	if systemBool(p.IncludeFrame, true) {
		payload, f := tc.server.executeCommand(tc.ctx, "frame_capture", nil)
		if f != nil {
			return fail(f)
		}
		raw, e := base64.StdEncoding.DecodeString(fmt.Sprint(payload["data"]))
		if e != nil {
			return fail(&toolFailure{Code: "bridge_error", Message: e.Error()})
		}
		w, _ := payload["width"].(float64)
		h, _ := payload["height"].(float64)
		img, e := rgb24ToNRGBA(raw, int(w), int(h))
		if e != nil {
			return fail(&toolFailure{Code: "bridge_error", Message: e.Error()})
		}
		var b bytes.Buffer
		if e = png.Encode(&b, img); e != nil {
			return fail(&toolFailure{Code: "artifact_error", Message: e.Error()})
		}
		prov := genericProvenance(tc.server, "system-frame", at)
		prov.CaptureID = captureID
		prov.CaptureConsistency = consistency
		tok, _ := payload["frame_token"].(float64)
		t := uint64(tok)
		prov.FrameToken = &t
		a, e := tc.server.store.PutWithProvenance(ctx.ID, "system-frame", "image/png", b.Bytes(), prov)
		if e != nil {
			return fail(&toolFailure{Code: "artifact_error", Message: e.Error()})
		}
		window.track(a)
		d := artifactDescriptor(tc.server, a, ctx.ID)
		components["frame"] = d
		artifacts = append(artifacts, d)
		captureComponents = append(captureComponents, captureComponentFromProvenance("frame", a))
		if t != 0 {
			captureFrameToken = &t
		}
	} else {
		markSkipped("frame", false, "include_frame=false")
	}
	// Keep the renderer-facing relationship explicit and bounded. This is a
	// derived artifact, not a second read window.
	if f := addJSON("render_manifest", "system-render-manifest", map[string]any{"schema_version": "render-manifest/1", "capture_id": captureID, "frame": components["frame"], "vdp_status": components["vdp_status"], "palette": components["cram"], "scroll": components["vsram"], "sprites": components["sprite_table"]}); f != nil {
		return fail(f)
	}
	// Close the window once: restore the prior run state, complete the single
	// capture-consistency object, and report the restore outcome.
	window.closeWindow(tc, resume)
	restore := window.restoreView()
	genAfter := tc.server.target.Generation()
	manifest := map[string]any{"schema_version": systemSnapshotSchema, "kind": "system-snapshot", "capture_id": captureID, "captured_at": at, "capture_consistency": consistency, "run_state_restore": restore, "target_generation_before": genBefore, "target_generation_after": genAfter, "rom_identity": tc.server.romIdentityView(0), "byte_order": map[string]any{"m68k": "big-endian", "z80": "little-endian", "raw": "address-order"}, "components": components, "artifacts": artifacts}
	// The manifest embeds the component descriptors, which were built while the
	// window was open: re-stamp them before writing the durable manifest so it
	// cannot carry a provisional window state.
	view := captureConsistencyToMap(consistency)
	restampCaptureProvenance(manifest, view, consistency.State)
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	prov := genericProvenance(tc.server, "system-snapshot-manifest", at)
	prov.CaptureID = captureID
	prov.CaptureConsistency = consistency
	stored, e := tc.server.store.PutWithProvenance(ctx.ID, "system-snapshot-manifest", "application/json", b, prov)
	if e != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: e.Error()}, tc.modern)
	}
	md := artifactDescriptor(tc.server, stored, ctx.ID)
	artifacts = append(artifacts, md)
	summary := map[string]any{"kind": "system-snapshot", "schema_version": systemSnapshotSchema, "capture_id": captureID, "capture_consistency": view, "run_state_restore": restore, "initial_run_state": window.InitialRunState, "final_run_state": window.FinalRunState, "resumed": window.Resumed, "pause_resume_cycle": map[bool]int{true: 1, false: 0}[wasRunning], "target_generation_before": genBefore, "target_generation_after": genAfter, "artifact_count": len(artifacts), "internal_lock_acquired": internal}
	if window.ResumeSkippedReason != "" {
		summary["resume_skipped_reason"] = window.ResumeSkippedReason
	}
	result := map[string]any{"summary": summary, "manifest": md, "components": components, "artifacts": artifacts, "run_state_restore": restore}
	if window.RestoreFailure != nil {
		result[runStateRestoreFailed] = true
	}
	// Every component artifact was written while the window was open:
	// complete its stored provenance, then re-stamp the response views.
	tc.server.store.FinalizeCaptureConsistency(window.ids(), consistency)
	restampCaptureProvenance(result, view, consistency.State)
	// Every component and the manifest now exist: index the capture so
	// capture_get resolves it without this response.
	generation := genBefore
	if failure := registerCapture(tc.server.store, artifact.Capture{
		CaptureID:        captureID,
		ContextID:        ctx.ID,
		ProducerTool:     "system_snapshot_capture",
		ManifestArtifact: stored.ID,
		SchemaVersion:    systemSnapshotSchema,
		Components:       captureComponents,
		FrameToken:       captureFrameToken,
		TargetGeneration: &generation,
		CreatedAt:        at,
	}); failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(stampGenerations(result, genBefore, genAfter), tc.modern)
}
