package mcp

import (
	"fmt"
	"sort"
)

// This file is the single declaration of every code an error response can
// carry. It exists because the server accumulated three sources of codes: its
// own handlers, the pinned native plugin (whose failure codes are passed
// through), and experiment scripts. Clients need one closed set (they branch
// on it) and one coarse class per code (they can group without knowing every
// member).
//
// The taxonomy is declared data, not prose: errorCodeRegistry is the only
// place a code is introduced, failureResult stamps the declared class on every
// failure (and refuses to publish an undeclared code), and the conformance test
// drives the registry so a new literal cannot appear without an entry here.
//
// Two other `code` fields exist and are deliberately NOT error codes:
//
//   - run_state_restore.* codes (run_state_restored, run_state_restore_failed,
//     ...) are outcome labels of one capture window, declared in
//     consistency.go and documented with the run-state vocabulary;
//   - artifact_describe_deprecated is a success-payload warning marker.
//
// Turn them into error codes only if they ever become the reason a call failed.

// Error classes group codes by what the caller can do about them.
const (
	// errorClassInvalidRequest: the request itself was wrong (shape, value,
	// bound, or a field that contradicts another).
	errorClassInvalidRequest = "invalid_request"
	// errorClassNotFound: the request named a resource that does not exist.
	errorClassNotFound = "not_found"
	// errorClassUnsupported: the capability is not offered here (plugin,
	// operation, tool, or a read-only space).
	errorClassUnsupported = "unsupported"
	// errorClassConflict: the request is well formed but the current state
	// contradicts it (held lock, stale generation, mismatched provenance).
	errorClassConflict = "conflict"
	// errorClassTarget: the emulator or the native action failed, was
	// preempted, or cannot answer.
	errorClassTarget = "target"
	// errorClassArtifact: artifact storage, indexing, or retrieval failed, or
	// the referenced artifact is unusable.
	errorClassArtifact = "artifact"
	// errorClassWorkspace: analysis-context, snapshot, annotation, symbol, or
	// trace-session bookkeeping failed.
	errorClassWorkspace = "workspace"
	// errorClassBridge: the authenticated local bridge is unreachable or its
	// answer cannot be decoded.
	errorClassBridge = "bridge"
	// errorClassExperiment: a scripted experiment failed.
	errorClassExperiment = "experiment"
	// errorClassInternal: the server could not classify or complete its own
	// work; this is a defect, not a caller mistake.
	errorClassInternal = "internal"
)

// errorClassVocab is the closed vocabulary of error_class values.
var errorClassVocab = newEnumVocab("error_class",
	errorClassInvalidRequest,
	errorClassNotFound,
	errorClassUnsupported,
	errorClassConflict,
	errorClassTarget,
	errorClassArtifact,
	errorClassWorkspace,
	errorClassBridge,
	errorClassExperiment,
	errorClassInternal,
)

// Code origins. A "native" code is produced by the pinned plugin and passed
// through unchanged; registering it here is what makes it part of the contract.
const (
	errorOriginServer     = "server"
	errorOriginNative     = "native"
	errorOriginExperiment = "experiment"
)

// errorCode is one declared failure code.
type errorCode struct {
	Code        string
	Class       string
	Origin      string
	Description string
}

// errorCodeNativeError is the declared fallback for a native failure code that
// this server does not know (a newer plugin). The original value is preserved
// in the native_code field so no diagnostic is lost.
const errorCodeNativeError = "native_error"

// errorCodeInternal is the declared fallback for a failure a handler produced
// with a code that is not in this registry.
const errorCodeInternalFallback = "internal_error"

// errorCodeRegistry is every code an error response may carry, sorted by code.
var errorCodeRegistry = []errorCode{
	{Code: "annotation_limit_exceeded", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "The per-context annotation cap (500) would be exceeded."},
	{Code: "artifact_error", Class: errorClassArtifact, Origin: errorOriginServer, Description: "Artifact encoding, write, or index persistence failed."},
	{Code: "audio_incomplete", Class: errorClassTarget, Origin: errorOriginServer, Description: "The native audio capture returned fewer frames than requested."},
	{Code: "audio_unavailable", Class: errorClassTarget, Origin: errorOriginNative, Description: "The pinned plugin cannot capture PCM audio; audio_capture is unavailable."},
	{Code: "breakpoint_error", Class: errorClassTarget, Origin: errorOriginNative, Description: "The plugin failed to create or remove a breakpoint."},
	{Code: "breakpoint_not_found", Class: errorClassNotFound, Origin: errorOriginNative, Description: "The requested breakpoint id does not exist in the plugin."},
	{Code: "bridge_error", Class: errorClassBridge, Origin: errorOriginServer, Description: "The bridge call failed or its answer could not be decoded; the command may have executed (ambiguous)."},
	{Code: "bridge_unavailable", Class: errorClassBridge, Origin: errorOriginServer, Description: "The authenticated native bridge is unreachable; no command was sent."},
	{Code: "byte_order_mismatch", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "A decode request names a byte order that contradicts the space's declared order."},
	{Code: "byte_order_required", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "A multi-byte decode was requested without the byte order the space does not declare."},
	{Code: "byte_order_unknown", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "The space's byte order is unknown, so a multi-byte decode cannot be performed."},
	{Code: "cannot_close_default", Class: errorClassConflict, Origin: errorOriginServer, Description: "The implicit default analysis context cannot be closed."},
	{Code: "capture_component_omitted", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The requested component was omitted by the producer of that capture."},
	{Code: "capture_not_found", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The capture id does not resolve in this analysis context."},
	{Code: "context_mismatch", Class: errorClassConflict, Origin: errorOriginServer, Description: "A referenced resource belongs to another analysis context."},
	{Code: "control_invalid", Class: errorClassConflict, Origin: errorOriginServer, Description: "The control id is structurally invalid or cannot own the requested action."},
	{Code: "control_not_found", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The control id does not match an active control lock."},
	{Code: "controller_not_found", Class: errorClassNotFound, Origin: errorOriginNative, Description: "No controller device is connected to the requested player port."},
	{Code: "cpu_not_found", Class: errorClassNotFound, Origin: errorOriginNative, Description: "The loaded target has no processor of the requested type."},
	{Code: "experiment_error", Class: errorClassExperiment, Origin: errorOriginServer, Description: "The experiment runner failed before or while executing the script."},
	{Code: "experiment_failed", Class: errorClassExperiment, Origin: errorOriginServer, Description: "The experiment ran and finished in a failed status."},
	{Code: "experiments_disabled", Class: errorClassUnsupported, Origin: errorOriginServer, Description: "No experiment runner is configured, so experiment_run is disabled."},
	{Code: "fixture_invalid", Class: errorClassInvalidRequest, Origin: errorOriginExperiment, Description: "A declarative experiment fixture is malformed or has an unsupported version."},
	{Code: "frame_capture_failed", Class: errorClassTarget, Origin: errorOriginNative, Description: "The plugin could not capture the rendered frame."},
	{Code: "frame_timeout", Class: errorClassTarget, Origin: errorOriginNative, Description: "The VDP did not render a new frame inside the wait window."},
	{Code: "freeze_limit", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "The per-server frozen-cell cap would be exceeded."},
	{Code: "incompatible_provenance", Class: errorClassConflict, Origin: errorOriginServer, Description: "Two artifacts of one comparison have incompatible address or target provenance."},
	{Code: "initial_state_load_failed", Class: errorClassTarget, Origin: errorOriginServer, Description: "experiment_run could not load its initial_state_id before starting."},
	{Code: "internal_error", Class: errorClassInternal, Origin: errorOriginServer, Description: "The server could not complete its own work (unclassified failure)."},
	{Code: "invalid_params", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "An argument is missing, malformed, or outside its documented bound."},
	{Code: "length_exceeds_buffer", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "The requested length exceeds the captured buffer."},
	{Code: "length_exceeds_inline_cap", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "The requested inline length exceeds the inline cap; use the artifact-first tool."},
	{Code: "length_out_of_range", Class: errorClassInvalidRequest, Origin: errorOriginNative, Description: "The requested length is outside the space's addressable range."},
	{Code: "native_error", Class: errorClassTarget, Origin: errorOriginServer, Description: "The plugin answered with a failure code this server does not declare; native_code carries the original value."},
	{Code: "no_cartridge", Class: errorClassConflict, Origin: errorOriginServer, Description: "The operation needs a loaded cartridge and none is loaded."},
	{Code: "no_rom_loaded", Class: errorClassConflict, Origin: errorOriginServer, Description: "The operation needs cartridge identity and no ROM is loaded or readable."},
	{Code: "no_trace_session", Class: errorClassConflict, Origin: errorOriginServer, Description: "No active or retained trace session exists for the requested operation."},
	{Code: "out_of_range", Class: errorClassInvalidRequest, Origin: errorOriginNative, Description: "The address or range is outside the space's addressable range."},
	{Code: "pixel_info_pending", Class: errorClassConflict, Origin: errorOriginServer, Description: "The requested pixel information is not available yet."},
	{Code: "pixel_info_unavailable", Class: errorClassTarget, Origin: errorOriginNative, Description: "The plugin cannot produce pixel information for the request."},
	{Code: "provenance_conflict", Class: errorClassConflict, Origin: errorOriginServer, Description: "A caller-restated range or identity contradicts the artifact's captured provenance."},
	{Code: "python_exited", Class: errorClassExperiment, Origin: errorOriginExperiment, Description: "The Python experiment process exited before completing its protocol."},
	{Code: "python_start_failed", Class: errorClassExperiment, Origin: errorOriginExperiment, Description: "The Python experiment process could not be started."},
	{Code: "read_fault", Class: errorClassTarget, Origin: errorOriginNative, Description: "The processor or debugger reported a read fault."},
	{Code: "recovery_error", Class: errorClassTarget, Origin: errorOriginServer, Description: "Trace-session recovery could not restore the retained session."},
	{Code: "rom_load_failed", Class: errorClassTarget, Origin: errorOriginNative, Description: "The plugin could not load the cartridge."},
	{Code: "run_until_cancelled", Class: errorClassTarget, Origin: errorOriginServer, Description: "The run_until window was cancelled before its instrument fired."},
	{Code: "run_until_cleanup_failed", Class: errorClassTarget, Origin: errorOriginServer, Description: "The run_until window ended but its temporary instrument could not be removed."},
	{Code: "run_until_preempted", Class: errorClassConflict, Origin: errorOriginServer, Description: "Another actor ended the run_until window before its instrument fired."},
	{Code: "run_until_timeout", Class: errorClassTarget, Origin: errorOriginServer, Description: "The run_until window elapsed without its instrument firing."},
	{Code: "script_disallowed", Class: errorClassUnsupported, Origin: errorOriginServer, Description: "The experiment script is outside the configured scripts directory."},
	{Code: "script_error", Class: errorClassExperiment, Origin: errorOriginServer, Description: "An experiment script failed to run."},
	{Code: "script_kind_unsupported", Class: errorClassUnsupported, Origin: errorOriginExperiment, Description: "The experiment script kind is not supported."},
	{Code: "script_not_found", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The experiment script does not exist in the scripts directory."},
	{Code: "script_too_large", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "The experiment script exceeds the configured size cap."},
	{Code: "session_mismatch", Class: errorClassConflict, Origin: errorOriginServer, Description: "The trace session id does not match the retained session."},
	{Code: "session_not_found", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The trace session id does not resolve."},
	{Code: "shutting_down", Class: errorClassBridge, Origin: errorOriginNative, Description: "The plugin is shutting down and refused the command."},
	{Code: "soft_reset_unavailable", Class: errorClassUnsupported, Origin: errorOriginNative, Description: "The plugin does not implement the soft-reset path."},
	{Code: "state_api_unavailable", Class: errorClassUnsupported, Origin: errorOriginNative, Description: "The plugin cannot access the emulator's state API."},
	{Code: "state_file_missing", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The snapshot file recorded by a state entry is gone from disk."},
	{Code: "state_load_failed", Class: errorClassTarget, Origin: errorOriginNative, Description: "The plugin could not load the snapshot."},
	{Code: "state_not_found", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The snapshot id or name does not resolve in this context."},
	{Code: "state_save_failed", Class: errorClassTarget, Origin: errorOriginNative, Description: "The plugin could not save the snapshot."},
	{Code: "state_store_error", Class: errorClassWorkspace, Origin: errorOriginServer, Description: "Snapshot bookkeeping failed on the server (directory, hash, or metadata)."},
	{Code: "step_failed", Class: errorClassExperiment, Origin: errorOriginExperiment, Description: "One experiment step returned an error."},
	{Code: "target_control_held", Class: errorClassConflict, Origin: errorOriginServer, Description: "Another control lock owns the target, or the supplied control id does not own it."},
	{Code: "target_generation_conflict", Class: errorClassConflict, Origin: errorOriginServer, Description: "The expected target generation no longer matches the live target."},
	{Code: "target_resynchronization_required", Class: errorClassConflict, Origin: errorOriginServer, Description: "A previous ambiguous failure left the target generation unknown; re-observe before mutating."},
	{Code: "too_many_steps", Class: errorClassExperiment, Origin: errorOriginExperiment, Description: "The experiment exceeded the configured step cap."},
	{Code: "tool_args_invalid", Class: errorClassInvalidRequest, Origin: errorOriginExperiment, Description: "An experiment step supplied arguments the addressed tool rejects."},
	{Code: "tool_error", Class: errorClassExperiment, Origin: errorOriginExperiment, Description: "An experiment step's tool call returned an error."},
	{Code: "tool_not_allowed", Class: errorClassUnsupported, Origin: errorOriginExperiment, Description: "The experiment attempted a tool outside the step allowlist."},
	{Code: "trace_busy", Class: errorClassConflict, Origin: errorOriginNative, Description: "A trace is already running in the plugin."},
	{Code: "trace_capture_failed", Class: errorClassTarget, Origin: errorOriginNative, Description: "The plugin's trace capture failed."},
	{Code: "trace_capture_fault", Class: errorClassTarget, Origin: errorOriginNative, Description: "The trace subsystem reported a fault during capture."},
	{Code: "trace_segment_unreadable", Class: errorClassTarget, Origin: errorOriginNative, Description: "A trace segment file could not be read."},
	{Code: "trace_session_failed", Class: errorClassTarget, Origin: errorOriginNative, Description: "A native trace-session operation failed."},
	{Code: "unaligned_request", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "The address or length does not satisfy the declared alignment."},
	{Code: "unknown_annotation", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The annotation id does not resolve in this context."},
	{Code: "unknown_artifact", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The artifact id is invalid or belongs to another context."},
	{Code: "unknown_context", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The analysis context handle does not resolve."},
	{Code: "unknown_freeze", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The freeze id does not resolve."},
	{Code: "unknown_method", Class: errorClassUnsupported, Origin: errorOriginNative, Description: "The plugin does not implement the requested operation."},
	{Code: "unknown_space", Class: errorClassNotFound, Origin: errorOriginNative, Description: "The address space id does not resolve in the live catalog."},
	{Code: "unknown_state", Class: errorClassNotFound, Origin: errorOriginServer, Description: "The snapshot id does not resolve in this context."},
	{Code: "unknown_tool", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "No tool with that name is registered."},
	{Code: "unsupported_parameter", Class: errorClassInvalidRequest, Origin: errorOriginServer, Description: "The addressed tool does not consume that argument."},
	{Code: "unsupported_plugin", Class: errorClassUnsupported, Origin: errorOriginServer, Description: "The connected plugin does not advertise the required operation."},
	{Code: "vdp_not_found", Class: errorClassNotFound, Origin: errorOriginNative, Description: "The target has no VDP device."},
	{Code: "watchpoint_error", Class: errorClassTarget, Origin: errorOriginNative, Description: "The plugin failed to create or remove a watchpoint."},
	{Code: "watchpoint_not_found", Class: errorClassNotFound, Origin: errorOriginNative, Description: "The requested watchpoint id does not exist in the plugin."},
	{Code: "write_fault", Class: errorClassTarget, Origin: errorOriginNative, Description: "The processor or debugger reported a write fault."},
	{Code: "write_not_supported", Class: errorClassUnsupported, Origin: errorOriginServer, Description: "The address space is read-only on the debugger path."},
}

// declaredErrorCodes indexes the registry. It is built once; a duplicate code
// would silently shadow an entry, so TestErrorCodeRegistryIswellFormed fails on
// one instead of relying on this map.
var declaredErrorCodes = func() map[string]errorCode {
	index := make(map[string]errorCode, len(errorCodeRegistry))
	for _, declared := range errorCodeRegistry {
		index[declared.Code] = declared
	}
	return index
}()

// isDeclaredErrorCode reports whether one code belongs to the taxonomy.
func isDeclaredErrorCode(code string) bool {
	_, present := declaredErrorCodes[code]
	return present
}

// errorClassOf returns the declared class of one code, or the internal class
// when the code was never declared.
func errorClassOf(code string) string {
	if declared, present := declaredErrorCodes[code]; present {
		return declared.Class
	}
	return errorClassInternal
}

// normalizeNativeFailure maps one native failure code to a declared code. A
// known plugin code passes through unchanged (clients already branch on those);
// an unknown one becomes native_error with the original value preserved.
func normalizeNativeFailure(code, message string) *toolFailure {
	if isDeclaredErrorCode(code) {
		return &toolFailure{Code: code, Message: message}
	}
	return &toolFailure{
		Code:    errorCodeNativeError,
		Message: message,
		Data:    map[string]any{"native_code": code},
	}
}

// errorCodeDeclaration publishes the taxonomy for clients that want to build
// one conditional over every failure: the code list with class and origin.
func errorCodeDeclaration() map[string]any {
	codes := make([]map[string]any, 0, len(errorCodeRegistry))
	for _, declared := range errorCodeRegistry {
		codes = append(codes, map[string]any{
			"code":   declared.Code,
			"class":  declared.Class,
			"origin": declared.Origin,
		})
	}
	return map[string]any{
		"classes": errorClassVocab.valuesEcho(),
		"codes":   codes,
		"note":    "code is the stable machine-readable failure code; error_class groups codes by what the caller can do. Both are additive: a new code is a new member, never a rename.",
	}
}

// errorCodeNames returns the sorted code list, for deterministic diagnostics.
func errorCodeNames() []string {
	names := make([]string, 0, len(errorCodeRegistry))
	for _, declared := range errorCodeRegistry {
		names = append(names, declared.Code)
	}
	sort.Strings(names)
	return names
}

// validateErrorCodeRegistry is the structural check the conformance test runs:
// unique codes, declared class, declared origin.
func validateErrorCodeRegistry() error {
	seen := make(map[string]bool, len(errorCodeRegistry))
	for _, declared := range errorCodeRegistry {
		if declared.Code == "" {
			return fmt.Errorf("registry contains an empty code")
		}
		if seen[declared.Code] {
			return fmt.Errorf("code %q is declared twice", declared.Code)
		}
		seen[declared.Code] = true
		if !errorClassVocab.accepts(declared.Class) {
			return fmt.Errorf("code %q declares undeclared class %q", declared.Code, declared.Class)
		}
		switch declared.Origin {
		case errorOriginServer, errorOriginNative, errorOriginExperiment:
		default:
			return fmt.Errorf("code %q declares undeclared origin %q", declared.Code, declared.Origin)
		}
		if declared.Description == "" {
			return fmt.Errorf("code %q has no description", declared.Code)
		}
	}
	return nil
}
