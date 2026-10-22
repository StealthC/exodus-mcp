package mcp

import (
	"encoding/json"
	"fmt"
	"time"
)

// cpu_step is the single stepping tool (roadmap issue #17). It absorbs
// m68k_step, z80_step, cpu_step_over and cpu_step_out: the concept is "advance
// one processor by one step", and the processor plus the step mode are
// arguments.
//
// mode=instruction executes exactly one instruction (the legacy single-step
// tools). mode=over/out ask the core to run until it completes the current
// opcode without entering a call, or returns from the current call frame; those
// modes return as soon as the core resumes, so an optional timeout_ms bounds how
// long the merged tool waits for the resulting pause before reporting an
// incomplete step. With no timeout_ms the response is exactly the legacy one.

const (
	cpuStepModeInstruction = "instruction"
	cpuStepModeOver        = "over"
	cpuStepModeOut         = "out"

	// maxCPUStepTimeoutMs bounds the optional wait for a step-over/step-out to
	// reach its internal break.
	maxCPUStepTimeoutMs = 120000
)

// cpuStepModeVocab is the closed mode vocabulary of cpu_step.
var cpuStepModeVocab = newEnumVocab("mode", cpuStepModeInstruction, cpuStepModeOver, cpuStepModeOut)

type cpuStepArgs struct {
	CPU       string  `json:"cpu"`
	Mode      string  `json:"mode"`
	TimeoutMS *uint64 `json:"timeout_ms"`
	guardArgs
}

func cpuStepSpec() toolSpec {
	return toolSpec{
		name:        "cpu_step",
		description: fmt.Sprintf("Advance one processor by exactly one step and leave the system paused. mode \"instruction\" (default) executes one instruction synchronously; mode \"over\" runs until the current opcode completes without entering a call; mode \"out\" runs until the current call frame returns. over/out return as soon as the core resumes, so optional timeout_ms (1-%d) bounds how long the call waits for the resulting pause and reports step_completion: when it is omitted the call returns immediately, exactly like the deprecated cpu_step_over and cpu_step_out. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.", maxCPUStepTimeoutMs),
		schema: objectSchema(map[string]any{
			"cpu":                        cpuVocab.property("Processor to step."),
			"mode":                       cpuStepModeVocab.property("Step mode: instruction executes one instruction, over runs until the current opcode completes without entering a call, out runs until the current call frame returns (default instruction)."),
			"timeout_ms":                 integerProperty(fmt.Sprintf("Wait up to this many milliseconds for an over/out step to reach its pause (cap %d). Omitted means return immediately; rejected for mode instruction, which is synchronous.", maxCPUStepTimeoutMs), 1),
			"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
			"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
		}, []string{"cpu"}),
		run: runCPUStep,
	}
}

func runCPUStep(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[cpuStepArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.CPU == "" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "cpu is required: m68k or z80"}, tc.modern)
	}
	if failure := cpuVocab.validate(parsed.CPU); failure != nil {
		return failureResult(failure, tc.modern)
	}
	mode, failure := cpuStepModeVocab.resolve(parsed.Mode, cpuStepModeInstruction)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.TimeoutMS != nil {
		if mode == cpuStepModeInstruction {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "timeout_ms applies only to mode over and out: an instruction step completes synchronously inside the call"}, tc.modern)
		}
		if *parsed.TimeoutMS < 1 || *parsed.TimeoutMS > maxCPUStepTimeoutMs {
			return failureResult(&toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("timeout_ms must be between 1 and %d", maxCPUStepTimeoutMs),
				Data:    map[string]any{"field": "timeout_ms", "max": maxCPUStepTimeoutMs},
			}, tc.modern)
		}
	}

	legacyArgs := map[string]any{}
	if parsed.ControlID != "" {
		legacyArgs["control_id"] = parsed.ControlID
	}
	if parsed.ExpectedTargetGeneration != nil {
		legacyArgs["expected_target_generation"] = *parsed.ExpectedTargetGeneration
	}
	var handler func(toolContext, json.RawMessage) map[string]any
	switch mode {
	case cpuStepModeOver, cpuStepModeOut:
		legacyArgs["cpu"] = parsed.CPU
		action := "step_over"
		if mode == cpuStepModeOut {
			action = "step_out"
		}
		handler = makeRunCPUControlFromArgs(tc.toolName("cpu_step"), action)
	default:
		handler = makeRunCPUControl(tc.toolName("cpu_step"), parsed.CPU, "step")
	}

	payload, failure := composeTool(tc, handler, legacyArgs)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload["cpu"] = parsed.CPU
	payload["mode"] = mode
	if parsed.TimeoutMS != nil {
		payload["step_completion"] = waitForStepCompletion(tc, time.Duration(*parsed.TimeoutMS)*time.Millisecond)
	}
	return okResult(payload, tc.modern)
}

// waitForStepCompletion polls the observed run state until the core pauses after
// a step-over/step-out, so a caller can act on a completed step instead of
// racing the core. The step itself already succeeded; an unavailable status or
// an elapsed budget is reported, never turned into a failure.
func waitForStepCompletion(tc toolContext, budget time.Duration) map[string]any {
	started := time.Now()
	deadline := started.Add(budget)
	polls := 0
	completed := false
	running := true
	var lastFailure *toolFailure
	for {
		// The native answer may predate the resume, so the cached status must
		// not decide the poll.
		tc.server.invalidateStatusCache()
		status, failure := fetchEmulatorStatus(tc)
		polls++
		if failure != nil {
			lastFailure = failure
			break
		}
		running = status.SystemRunning
		if !running {
			completed = true
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(runUntilPollInterval)
	}
	view := map[string]any{
		"completed":      completed,
		"timed_out":      !completed && lastFailure == nil,
		"poll_count":     polls,
		"waited_ms":      time.Since(started).Milliseconds(),
		"budget_ms":      budget.Milliseconds(),
		"system_running": running,
	}
	if lastFailure != nil {
		view["unavailable"] = unavailableSectionView(lastFailure)
		view["timed_out"] = false
	}
	return view
}
