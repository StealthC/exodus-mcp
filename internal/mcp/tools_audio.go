package mcp

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

const (
	audioMaxDurationMS = 10000
	audioMaxBytes      = 8 << 20
)

type soundStatusArgs struct {
	Component   string `json:"component"`
	CaptureMode string `json:"capture_mode"`
	guardArgs
}
type audioCaptureArgs struct {
	DurationMS int    `json:"duration_ms"`
	SampleRate int    `json:"sample_rate"`
	Channels   int    `json:"channels"`
	Context    string `json:"context"`
}

func audioToolSpecs() []toolSpec { return []toolSpec{soundStatusSpec(), audioCaptureSpec()} }

func soundStatusSpec() toolSpec {
	return toolSpec{
		name:        "sound_status",
		description: "Read-only YM2612 and/or PSG state. Values come from typed Exodus device interfaces; unavailable or write-only fields are reported explicitly and never reconstructed from bus writes.",
		schema: objectSchema(map[string]any{
			"component":    enumProperty("Chip state to read; defaults to both.", []string{"ym2612", "psg", "both"}),
			"capture_mode": enumProperty("live reads the current device state; paused is not currently supported by the native sound reader.", []string{"live"}),
		}, nil),
		run: runSoundStatus,
	}
}

func audioCaptureSpec() toolSpec {
	return toolSpec{
		name:        "audio_capture",
		description: fmt.Sprintf("Capture a bounded mixed-audio WAV artifact (maximum %d ms and %d bytes). The native bridge must provide a bounded PCM capture; failures are reported as unavailable rather than as valid silence.", audioMaxDurationMS, audioMaxBytes),
		schema: objectSchema(map[string]any{
			"duration_ms": integerProperty(fmt.Sprintf("Capture duration in milliseconds (1-%d).", audioMaxDurationMS), 1),
			"sample_rate": map[string]any{"type": "integer", "enum": []int{22050, 44100, 48000}, "description": "Supported output sample rate."},
			"channels":    map[string]any{"type": "integer", "enum": []int{1, 2}, "description": "Output channels."},
			"context":     contextProperty(),
		}, []string{"duration_ms"}),
		run: runAudioCapture,
	}
}

func runSoundStatus(tc toolContext, raw json.RawMessage) map[string]any {
	args, failure := decodeArgs[soundStatusArgs](raw)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	component := strings.TrimSpace(args.Component)
	if component == "" {
		component = "both"
	}
	if args.CaptureMode != "" && args.CaptureMode != "live" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "capture_mode must be live; sound state is not exposed as an atomic capture"}, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "sound_status", map[string]string{"component": component})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["capture_consistency"] = map[string]any{"state": "live", "execution_paused_by_tool": false, "execution_resumed_after": false, "initial_run_state": tc.server.runStateString(), "final_run_state": tc.server.runStateString(), "note": "YM2612/PSG state is sampled through the native device interfaces; it is not temporally atomic with CPU or VDP."}
	payload["target_generation"] = tc.server.target.Generation()
	payload["captured_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	payload["rom_path"] = tc.server.currentROMPath()
	payload["schema_version"] = "sound-status/1"
	return okResult(payload, tc.modern)
}

func wavFrameCount(wav []byte, channels int) (int, bool) {
	if len(wav) < 44 || string(wav[0:4]) != "RIFF" || string(wav[8:12]) != "WAVE" || string(wav[12:16]) != "fmt " || string(wav[36:40]) != "data" {
		return 0, false
	}
	if binary.LittleEndian.Uint16(wav[20:22]) != 1 || int(binary.LittleEndian.Uint16(wav[22:24])) != channels || binary.LittleEndian.Uint16(wav[34:36]) != 16 {
		return 0, false
	}
	dataSize := int(binary.LittleEndian.Uint32(wav[40:44]))
	if dataSize < 0 || 44+dataSize > len(wav) || dataSize%(channels*2) != 0 {
		return 0, false
	}
	return dataSize / (channels * 2), true
}

func runAudioCapture(tc toolContext, raw json.RawMessage) map[string]any {
	args, failure := decodeArgs[audioCaptureArgs](raw)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if args.DurationMS < 1 || args.DurationMS > audioMaxDurationMS {
		return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("duration_ms must be between 1 and %d", audioMaxDurationMS)}, tc.modern)
	}
	rate := args.SampleRate
	if rate == 0 {
		rate = 44100
	}
	if rate != 22050 && rate != 44100 && rate != 48000 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "sample_rate must be 22050, 44100, or 48000"}, tc.modern)
	}
	channels := args.Channels
	if channels == 0 {
		channels = 2
	}
	if channels != 1 && channels != 2 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "channels must be 1 or 2"}, tc.modern)
	}
	estimated := int64(args.DurationMS)*int64(rate)*int64(channels)*2/1000 + 44
	if estimated > audioMaxBytes {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "requested capture exceeds the maximum WAV size"}, tc.modern)
	}
	context, failure := resolveContext(tc.server, args.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "audio_capture", map[string]string{"duration_ms": fmt.Sprint(args.DurationMS), "sample_rate": fmt.Sprint(rate), "channels": fmt.Sprint(channels)})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if payload == nil {
		return failureResult(&toolFailure{Code: "audio_incomplete", Message: "native bridge returned no capture payload"}, tc.modern)
	}
	encoded, ok := payload["wav_base64"].(string)
	if !ok || encoded == "" {
		return failureResult(&toolFailure{Code: "audio_incomplete", Message: "native bridge returned no bounded WAV payload; no silence artifact was created"}, tc.modern)
	}
	wav, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return failureResult(&toolFailure{Code: "audio_incomplete", Message: "native bridge returned invalid WAV data"}, tc.modern)
	}
	if len(wav) > audioMaxBytes {
		return failureResult(&toolFailure{Code: "audio_incomplete", Message: "native bridge exceeded the WAV size cap"}, tc.modern)
	}
	frames, validWAV := wavFrameCount(wav, channels)
	if !validWAV {
		return failureResult(&toolFailure{Code: "audio_incomplete", Message: "native bridge returned a malformed WAV header"}, tc.modern)
	}
	now := time.Now().UTC()
	generation := tc.server.target.Generation()
	consistency := &artifact.CaptureConsistency{State: "composite_non_atomic", InitialRunState: tc.server.runStateString(), FinalRunState: tc.server.runStateString(), Note: "Audio is captured under the native audio clock and is not atomic with CPU or VDP state."}
	captureID := fmt.Sprintf("audio-%d", now.UnixNano())
	provenance := genericProvenance(tc.server, "audio-capture", now)
	provenance.CaptureID = captureID
	provenance.Device = "mixer"
	provenance.ByteOrder = "little-endian PCM"
	provenance.RawByteOrdering = "sample-interleaved"
	provenance.TargetGeneration = &generation
	provenance.CaptureConsistency = consistency
	provenance.CapturedAt = now
	stored, err := tc.server.store.PutWithProvenance(context.ID, "audio-capture", "audio/wav", wav, provenance)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	return okResult(map[string]any{"schema_version": "audio-capture/1", "capture_id": captureID, "duration_requested_ms": args.DurationMS, "sample_rate": rate, "channels": channels, "frames": frames, "state": "complete", "capture_consistency": consistency, "artifact": artifactDescriptor(tc.server, stored, context.ID)}, tc.modern)
}
