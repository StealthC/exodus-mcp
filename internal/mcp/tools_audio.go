package mcp

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	audioMaxDurationMS = 10000
	audioMaxBytes      = 8 << 20
)

// soundOutputVocab is the closed delivery vocabulary of sound_status: the live
// chip state inline, the same state as a JSON artifact, or a bounded PCM capture.
var soundOutputVocab = newEnumVocab("output", "state", "artifact", "wav")

type soundStatusArgs struct {
	Component   string `json:"component"`
	CaptureMode string `json:"capture_mode"`
	Output      string `json:"output"`
	DurationMS  int    `json:"duration_ms"`
	SampleRate  int    `json:"sample_rate"`
	Channels    int    `json:"channels"`
	Context     string `json:"context"`
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
		description: fmt.Sprintf("Read the sound subsystem. output \"state\" (default) returns read-only YM2612 and/or PSG state from typed Exodus device interfaces: unavailable or write-only fields are reported explicitly and never reconstructed from bus writes. output \"artifact\" stores that same state as a versioned JSON artifact and returns a compact summary plus its descriptor, so a large register dump never has to travel inline. output \"wav\" captures a bounded mixed-audio WAV artifact (maximum %d ms and %d bytes) and reports the same failure the deprecated audio_capture alias reports: the pinned bridge answers audio_unavailable rather than fabricating silence. component filters the chip state (ym2612, psg, or both).", audioMaxDurationMS, audioMaxBytes),
		schema: objectSchema(map[string]any{
			"component":    soundComponentVocab.property("Chip state to read; defaults to both."),
			"capture_mode": soundCaptureModeVocab.property("live reads the current device state; paused is not currently supported by the native sound reader."),
			"output":       soundOutputVocab.property("Delivery: \"state\" (default) returns the live chip state inline, \"artifact\" stores the same state as a JSON artifact with a compact summary, \"wav\" captures a bounded PCM WAV artifact. duration_ms selects output wav when output is omitted."),
			"duration_ms":  integerProperty(fmt.Sprintf("output wav: capture duration in milliseconds (1-%d).", audioMaxDurationMS), 1),
			"sample_rate":  audioSampleRateVocab.property("output wav: supported output sample rate (default 44100)."),
			"channels":     audioChannelsVocab.property("output wav: output channels (default 2)."),
			"context":      contextProperty(),
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
			"sample_rate": audioSampleRateVocab.property("Supported output sample rate (default 44100)."),
			"channels":    audioChannelsVocab.property("Output channels (default 2)."),
			"context":     contextProperty(),
		}, []string{"duration_ms"}),
		run: aliasRun("audio_capture", runAudioCapture),
	}
}

func runSoundStatus(tc toolContext, raw json.RawMessage) map[string]any {
	args, failure := decodeArgs[soundStatusArgs](raw)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	output, failure := resolveSoundOutput(*args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, args.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	// producer selects the arguments each output consumes, so a field is never
	// accepted and then dropped.
	if failure := validateSoundArguments(raw, output); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if output == "wav" {
		arguments := map[string]any{"duration_ms": args.DurationMS, "context": args.Context}
		if args.SampleRate != 0 {
			arguments["sample_rate"] = args.SampleRate
		}
		if args.Channels != 0 {
			arguments["channels"] = args.Channels
		}
		result, failure := composeTool(tc, runAudioCapture, arguments)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		return okResult(patchMap(result, "output", output), tc.modern)
	}

	component, failure := soundComponentVocab.resolve(strings.TrimSpace(args.Component), "both")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := soundCaptureModeVocab.validate(strings.TrimSpace(args.CaptureMode)); failure != nil {
		return failureResult(&toolFailure{
			Code:    failure.Code,
			Message: "sound state is not exposed as an atomic capture; " + failure.Message,
			Data:    failure.Data,
		}, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "sound_status", map[string]string{"component": component})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if payload == nil {
		payload = map[string]any{}
	}
	consistency := tc.server.captureConsistencyView(newCaptureConsistency(tc.server, consistencyLive,
		"YM2612/PSG state is sampled through the native device interfaces; it is not temporally atomic with CPU or VDP."))
	payload["capture_consistency"] = consistency
	payload["target_generation"] = tc.server.target.Generation()
	payload["captured_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	payload["rom_path"] = tc.server.currentROMPath()
	payload["schema_version"] = "sound-status/1"
	payload["output"] = output

	if output == "artifact" {
		// The same document, stored instead of inlined: the summary stays small
		// enough for any context, and the register dump is one download away.
		stored, err := putJSONArtifact(tc.server, context.ID, "sound-status", payload, genericProvenance(tc.server, "sound-status", time.Now().UTC()))
		if err != nil {
			return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
		}
		return okResult(map[string]any{
			"output":              output,
			"component":           component,
			"schema_version":      "sound-status/1",
			"capture_consistency": consistency,
			"captured_at":         payload["captured_at"],
			"rom_path":            payload["rom_path"],
			"summary": map[string]any{
				"component":         component,
				"target_generation": payload["target_generation"],
				"note":              "The full YM2612/PSG register dump is the JSON artifact; read it with artifact_get or artifact_preview.",
			},
			"artifact": artifactDescriptor(tc.server, stored, context.ID),
		}, tc.modern)
	}
	return okResult(payload, tc.modern)
}

// resolveSoundOutput applies the documented default and the duration inference.
func resolveSoundOutput(args soundStatusArgs) (string, *toolFailure) {
	if args.Output != "" {
		return soundOutputVocab.resolve(args.Output, "state")
	}
	// A PCM-only argument can only mean a capture; that keeps the argument
	// meaningful instead of rejecting it as unused.
	if args.DurationMS != 0 || args.SampleRate != 0 || args.Channels != 0 {
		return "wav", nil
	}
	return "state", nil
}

// soundConsumers lists the arguments each output consumes.
func soundConsumers() map[string][]string {
	return map[string][]string{
		"output":       {"state", "artifact", "wav"},
		"context":      {"state", "artifact", "wav"},
		"component":    {"state", "artifact"},
		"capture_mode": {"state", "artifact"},
		"duration_ms":  {"wav"},
		"sample_rate":  {"wav"},
		"channels":     {"wav"},
	}
}

// validateSoundArguments rejects an argument the selected output does not
// consume.
func validateSoundArguments(raw json.RawMessage, output string) *toolFailure {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	consumers := soundConsumers()
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		appliesTo, known := consumers[key]
		if !known {
			continue
		}
		consumed := false
		for _, candidate := range appliesTo {
			if candidate == output {
				consumed = true
				break
			}
		}
		if consumed {
			continue
		}
		return &toolFailure{
			Code:    "unsupported_parameter",
			Message: fmt.Sprintf("%q is not consumed by sound_status{output:%q}", key, output),
			Data: map[string]any{
				"field":       key,
				"path":        "$." + key,
				"output":      output,
				"consumed_by": appliesTo,
			},
		}
	}
	return nil
}

// patchMap adds or replaces one field of a composed payload map.
func patchMap(payload map[string]any, key string, value any) map[string]any {
	if payload == nil {
		payload = map[string]any{}
	}
	payload[key] = value
	return payload
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
	rate, failure := audioSampleRateVocab.resolve(args.SampleRate, 44100)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	channels, failure := audioChannelsVocab.resolve(args.Channels, 2)
	if failure != nil {
		return failureResult(failure, tc.modern)
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
	consistency := newCaptureConsistency(tc.server, consistencyCompositeNonAtomic,
		"Audio is captured under the native audio clock and is not atomic with CPU or VDP state.")
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
	return okResult(map[string]any{"schema_version": "audio-capture/1", "capture_id": captureID, "duration_requested_ms": args.DurationMS, "sample_rate": rate, "channels": channels, "frames": frames, "state": "complete", "capture_consistency": tc.server.captureConsistencyView(consistency), "artifact": artifactDescriptor(tc.server, stored, context.ID)}, tc.modern)
}
