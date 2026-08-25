package experiment

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// Experiment and run status values.
const (
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// ToolError is the machine-readable failure returned by Executor.Call; the
// runner forwards it to the script and records it in the manifest.
type ToolError struct {
	Code    string
	Message string
}

func (err *ToolError) Error() string { return err.Code + ": " + err.Message }

// Executor mediates one allowlisted tool call for an experiment. The MCP
// layer implements it by dispatching into the real tool handlers with the
// experiment's context and lease injected; tests use fakes.
type Executor interface {
	Call(ctx context.Context, tool string, arguments map[string]any) (map[string]any, error)
}

// StepRecord is the manifest entry for one executed step.
type StepRecord struct {
	Index     int             `json:"index"`
	ID        string          `json:"id"`
	Tool      string          `json:"tool"`
	Arguments map[string]any  `json:"arguments,omitempty"`
	Status    string          `json:"status"`
	Value     json.RawMessage `json:"value,omitempty"`
	Error     *protocolError  `json:"error,omitempty"`
}

// ArtifactRef summarizes one artifact produced during a run.
type ArtifactRef struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	MimeType  string `json:"mime_type"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	URL       string `json:"url,omitempty"`
}

// Result describes one finished run. It is the single source for the
// experiment manifest and the MCP summary.
type Result struct {
	ExperimentID   string
	ContextID      string
	ScriptName     string
	ScriptKind     string
	ScriptSHA256   string
	Arguments      map[string]any
	InitialStateID string
	FinalStateID   string
	Summary        map[string]any
	StartedAt      time.Time
	DurationMS     int64
	Status         string
	ExitCode       int
	Steps          []StepRecord
	Artifacts      []ArtifactRef
	Error          *protocolError
	OutputText     string

	// Manifest and Output are the stored artifacts; Output is zero-valued
	// when the run produced no captured stderr.
	Manifest artifact.Artifact
	Output   artifact.Artifact
}

// RunRequest is one experiment execution.
type RunRequest struct {
	ExperimentID   string
	ContextID      string
	LeaseID        string
	Script         *Script
	Arguments      map[string]any
	InitialStateID string
	Timeout        time.Duration
	Exec           Executor
}

// Runner executes scripts and fixtures. It is safe for concurrent use.
type Runner struct {
	config Config
	store  *artifact.Store
}

// NewRunner constructs the runner, creates the scripts directory, and
// resolves the interpreter path.
func NewRunner(config Config, store *artifact.Store) (*Runner, error) {
	config = config.normalize()
	if store == nil {
		return nil, errors.New("experiment runner requires an artifact store")
	}
	if err := os.MkdirAll(config.ScriptsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create scripts directory: %w", err)
	}
	return &Runner{config: config, store: store}, nil
}

// ScriptsDir reports the configured scripts root.
func (runner *Runner) ScriptsDir() string { return runner.config.ScriptsDir }

// ResolveTimeout applies the configured default and cap to one requested
// timeout.
func (runner *Runner) ResolveTimeout(requested time.Duration) time.Duration {
	if requested <= 0 {
		requested = runner.config.DefaultTimeout
	}
	if requested > runner.config.MaxTimeout {
		requested = runner.config.MaxTimeout
	}
	return requested
}

// NewID returns a fresh experiment identifier.
func NewID() string {
	buffer := make([]byte, 9)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("generate experiment id: %v", err))
	}
	return "exp_" + base64.RawURLEncoding.EncodeToString(buffer)
}

// Run executes one script or fixture and stores the manifest (and captured
// output, when non-empty) as context-scoped artifacts. The returned Result
// is complete even when the run failed; the manifest always lands in the
// store so failed runs stay diagnosable.
func (runner *Runner) Run(ctx context.Context, request RunRequest) (*Result, error) {
	if request.Exec == nil {
		return nil, errors.New("experiment executor is nil")
	}
	if request.Script == nil {
		return nil, errors.New("experiment script is nil")
	}
	runCtx, cancel := context.WithTimeout(ctx, runner.ResolveTimeout(request.Timeout))
	defer cancel()

	result := &Result{
		ExperimentID:   request.ExperimentID,
		ContextID:      request.ContextID,
		ScriptName:     request.Script.Name,
		ScriptKind:     request.Script.Kind,
		ScriptSHA256:   request.Script.SHA256,
		Arguments:      request.Arguments,
		InitialStateID: request.InitialStateID,
		StartedAt:      time.Now().UTC(),
	}
	switch request.Script.Kind {
	case "json":
		runner.runFixture(runCtx, request, result)
	case "python":
		runner.runPython(runCtx, request, result)
	default:
		result.Status = StatusFailed
		result.Error = &protocolError{Code: "script_kind_unsupported", Message: fmt.Sprintf("unsupported script kind %q", request.Script.Kind)}
	}
	result.DurationMS = time.Since(result.StartedAt).Milliseconds()

	if result.OutputText != "" {
		output, err := runner.store.Put(request.ContextID, "experiment-output", "text/plain; charset=utf-8", []byte(result.OutputText))
		if err != nil {
			return nil, fmt.Errorf("store experiment output: %w", err)
		}
		result.Output = output
		result.Artifacts = append(result.Artifacts, runner.refOf(output))
	}
	manifestBytes, err := json.MarshalIndent(runner.manifestJSON(result), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode experiment manifest: %w", err)
	}
	manifest, err := runner.store.Put(request.ContextID, "experiment-manifest", "application/json", manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("store experiment manifest: %w", err)
	}
	result.Manifest = manifest
	return result, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// Declarative fixtures
// ----------------------------------------------------------------------------------------------------------------------

type fixture struct {
	Version int           `json:"version"`
	Name    string        `json:"name,omitempty"`
	Steps   []fixtureStep `json:"steps"`
}

type fixtureStep struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

func (runner *Runner) runFixture(ctx context.Context, request RunRequest, result *Result) {
	var fixture fixture
	if err := json.Unmarshal(request.Script.Data, &fixture); err != nil {
		failParse(result, "fixture_invalid", "invalid fixture JSON: "+err.Error())
		return
	}
	if fixture.Version != 1 {
		failParse(result, "fixture_invalid", fmt.Sprintf("unsupported fixture version %d (expected 1)", fixture.Version))
		return
	}
	if len(fixture.Steps) == 0 {
		failParse(result, "fixture_invalid", "fixture defines no steps")
		return
	}
	if len(fixture.Steps) > runner.config.MaxSteps {
		failParse(result, "too_many_steps", fmt.Sprintf("fixture defines %d steps; the cap is %d", len(fixture.Steps), runner.config.MaxSteps))
		return
	}
	for index, step := range fixture.Steps {
		value, err := request.Exec.Call(ctx, step.Tool, step.Arguments)
		record := StepRecord{
			Index:     index,
			ID:        fmt.Sprintf("step-%02d", index),
			Tool:      step.Tool,
			Arguments: step.Arguments,
			Status:    "ok",
		}
		if err != nil {
			toolErr := asToolError(err)
			record.Status = "error"
			record.Error = toolErr
			result.Steps = append(result.Steps, record)
			result.Status = StatusFailed
			if ctx.Err() != nil {
				result.Error = &protocolError{Code: endCode(ctx.Err()), Message: "run ended before the fixture finished"}
			} else {
				result.Error = &protocolError{Code: "step_failed", Message: fmt.Sprintf("step %d (%s) failed: %s", index, step.Tool, toolErr.Message)}
			}
			return
		}
		record.Value = capJSON(value, maxStepValueBytes)
		result.Steps = append(result.Steps, record)
		if step.Tool == "state_save" {
			if stateID, _ := value["state_id"].(string); stateID != "" {
				result.FinalStateID = stateID
			}
		}
	}
	result.Status = StatusCompleted
}

// ----------------------------------------------------------------------------------------------------------------------
// Python scripts
// ----------------------------------------------------------------------------------------------------------------------

type lineEvent struct {
	line []byte
	err  error // io.EOF on a clean close, or a scanner error (line too long)
}

func (runner *Runner) runPython(ctx context.Context, request RunRequest, result *Result) {
	commandCtx, kill := context.WithCancel(ctx)
	defer kill()
	command := exec.CommandContext(commandCtx, runner.config.PythonCmd, "-I", request.Script.Path)
	command.Env = runner.pythonEnv()
	stdin, err := command.StdinPipe()
	if err != nil {
		failParse(result, "python_start_failed", "create stdin pipe: "+err.Error())
		return
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		failParse(result, "python_start_failed", "create stdout pipe: "+err.Error())
		return
	}
	stderr := newBoundedBuffer(runner.config.MaxOutputBytes)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		failParse(result, "python_start_failed", err.Error())
		return
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- command.Wait() }()

	initRaw, err := json.Marshal(initMessage{
		Type:         messageInit,
		ExperimentID: request.ExperimentID,
		Script:       request.Script.Name,
		Arguments:    request.Arguments,
		Limits:       limitsView{MaxSteps: runner.config.MaxSteps, MaxOutputBytes: runner.config.MaxOutputBytes},
	})
	if err != nil {
		failParse(result, "python_start_failed", "encode init message: "+err.Error())
		return
	}
	if _, err := stdin.Write(append(initRaw, '\n')); err != nil {
		waitErr := <-waitCh
		result.ExitCode = exitCode(waitErr)
		result.Status = StatusFailed
		result.Error = &protocolError{
			Code:    "python_exited",
			Message: fmt.Sprintf("script exited with code %d before reading the init message", result.ExitCode),
		}
		result.OutputText = sanitizeDiagnosticText(stderr.String())
		return
	}

	lines := make(chan lineEvent, 16)
	go readLines(stdout, lines, runner.maxLineBytes())

	maxMessages := runner.config.MaxSteps + maxArtifactsPerRun + 2
	seen := make(map[string]bool)
	messages := 0
	completed := false
	writeMessage := func(value any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		_, err = stdin.Write(append(raw, '\n'))
		return err
	}
	fatal := func(code, message string) {
		_ = writeMessage(runnerErrorMessage{Type: messageError, Code: code, Message: message})
		result.Status = StatusFailed
		result.Error = &protocolError{Code: code, Message: message}
		kill()
		reap(waitCh, command)
		completed = true
	}
	endBecauseContext := func() {
		result.Status = StatusFailed
		result.Error = &protocolError{Code: endCode(ctx.Err()), Message: "run ended before the script completed"}
		kill()
		reap(waitCh, command)
		completed = true
	}
	finishAfterComplete := func() {
		result.Status = StatusCompleted
		select {
		case waitErr := <-waitCh:
			result.ExitCode = exitCode(waitErr)
		case <-time.After(2 * time.Second):
			kill()
			reap(waitCh, command)
		}
		completed = true
	}

	for !completed {
		select {
		case event := <-lines:
			if event.err != nil {
				if errors.Is(event.err, io.EOF) {
					select {
					case waitErr := <-waitCh:
						result.ExitCode = exitCode(waitErr)
						result.Status = StatusFailed
						result.Error = &protocolError{
							Code:    "python_exited",
							Message: fmt.Sprintf("script closed its output without sending complete (exit code %d)", result.ExitCode),
						}
					case <-time.After(2 * time.Second):
						result.Status = StatusFailed
						result.Error = &protocolError{Code: "python_exited", Message: "script closed its output without completing and did not exit"}
						kill()
						reap(waitCh, command)
					}
					completed = true
					continue
				}
				fatal("output_line_too_long", fmt.Sprintf("script output exceeded the per-line limit of %d bytes", runner.maxLineBytes()))
				continue
			}
			kind, parseErr := messageType(event.line)
			if parseErr != nil {
				fatal("protocol_violation", "invalid message from script: "+excerpt(event.line))
				continue
			}
			messages++
			if messages > maxMessages {
				fatal("too_many_messages", fmt.Sprintf("script sent more than %d messages", maxMessages))
				continue
			}
			switch kind {
			case messageCall:
				var call callMessage
				if err := json.Unmarshal(event.line, &call); err != nil || validateMessageID(call.ID) != nil || call.Tool == "" {
					fatal("protocol_violation", "invalid call message: "+excerpt(event.line))
					continue
				}
				if seen[call.ID] {
					fatal("duplicate_message_id", fmt.Sprintf("message id %q was already used", call.ID))
					continue
				}
				seen[call.ID] = true
				if len(result.Steps) >= runner.config.MaxSteps {
					fatal("too_many_steps", fmt.Sprintf("script requested more than %d steps", runner.config.MaxSteps))
					continue
				}
				value, callErr := request.Exec.Call(ctx, call.Tool, call.Arguments)
				record := StepRecord{
					Index:     len(result.Steps),
					ID:        call.ID,
					Tool:      call.Tool,
					Arguments: call.Arguments,
				}
				if callErr != nil {
					toolErr := asToolError(callErr)
					record.Status = "error"
					record.Error = toolErr
					result.Steps = append(result.Steps, record)
					if ctx.Err() != nil {
						endBecauseContext()
						continue
					}
					if err := writeMessage(resultMessage{Type: messageResult, ID: call.ID, OK: false, Error: toolErr}); err != nil {
						exitWhileReplying(result, waitCh, stdout)
						completed = true
					}
					continue
				}
				record.Status = "ok"
				record.Value = capJSON(value, maxStepValueBytes)
				result.Steps = append(result.Steps, record)
				if call.Tool == "state_save" {
					if stateID, _ := value["state_id"].(string); stateID != "" {
						result.FinalStateID = stateID
					}
				}
				if err := writeMessage(resultMessage{Type: messageResult, ID: call.ID, OK: true, Value: value}); err != nil {
					exitWhileReplying(result, waitCh, stdout)
					completed = true
				}
			case messageArtifact:
				var published artifactMessage
				if err := json.Unmarshal(event.line, &published); err != nil || validateMessageID(published.ID) != nil || validateArtifactMeta(published.Kind, published.MimeType) != nil {
					fatal("protocol_violation", "invalid artifact message: "+excerpt(event.line))
					continue
				}
				if seen[published.ID] {
					fatal("duplicate_message_id", fmt.Sprintf("message id %q was already used", published.ID))
					continue
				}
				seen[published.ID] = true
				if len(result.Artifacts) >= maxArtifactsPerRun {
					fatal("too_many_artifacts", fmt.Sprintf("script published more than %d artifacts", maxArtifactsPerRun))
					continue
				}
				payload, err := base64.StdEncoding.DecodeString(published.DataBase64)
				if err != nil {
					fatal("protocol_violation", "artifact data_base64 is not valid RFC 4648 base64")
					continue
				}
				if int64(len(payload)) > runner.config.MaxOutputBytes {
					fatal("artifact_too_large", fmt.Sprintf("artifact exceeds the %d byte cap", runner.config.MaxOutputBytes))
					continue
				}
				mediaType, _, _ := mime.ParseMediaType(published.MimeType)
				stored, err := runner.store.Put(request.ContextID, published.Kind, mediaType, payload)
				if err != nil {
					fatal("artifact_store_error", "store published artifact: "+err.Error())
					continue
				}
				ref := runner.refOf(stored)
				result.Artifacts = append(result.Artifacts, ref)
				reply := map[string]any{
					"id":           ref.ID,
					"kind":         ref.Kind,
					"mime_type":    ref.MimeType,
					"size_bytes":   ref.SizeBytes,
					"sha256":       ref.SHA256,
					"url":          runner.artifactURL(request.ContextID, ref.ID),
					"resource_uri": "exodus://artifacts/" + ref.ID,
				}
				if err := writeMessage(resultMessage{Type: messageResult, ID: published.ID, OK: true, Value: reply}); err != nil {
					exitWhileReplying(result, waitCh, stdout)
					completed = true
				}
			case messageComplete:
				var complete completeMessage
				if err := json.Unmarshal(event.line, &complete); err != nil {
					fatal("protocol_violation", "invalid complete message: "+excerpt(event.line))
					continue
				}
				result.Summary = complete.Summary
				finishAfterComplete()
			}
		case waitErr := <-waitCh:
			result.ExitCode = exitCode(waitErr)
			if !completed {
				result.Status = StatusFailed
				result.Error = &protocolError{
					Code:    "python_exited",
					Message: fmt.Sprintf("script exited with code %d without completing", result.ExitCode),
				}
				completed = true
			}
		case <-ctx.Done():
			endBecauseContext()
		}
	}
	if result.Status == "" {
		result.Status = StatusFailed
		if result.Error == nil {
			result.Error = &protocolError{Code: "python_exited", Message: "script ended without reporting a status"}
		}
	}
	result.OutputText = sanitizeDiagnosticText(stderr.String())
}

// exitWhileReplying records a run whose script vanished while the runner was
// replying to a message.
func exitWhileReplying(result *Result, waitCh <-chan error, stdout io.Closer) {
	select {
	case waitErr := <-waitCh:
		result.ExitCode = exitCode(waitErr)
		result.Status = StatusFailed
		result.Error = &protocolError{Code: "python_exited", Message: fmt.Sprintf("script exited (code %d) while the server replied", result.ExitCode)}
	case <-time.After(2 * time.Second):
		_ = stdout.Close()
		result.Status = StatusFailed
		result.Error = &protocolError{Code: "python_exited", Message: "script went away while the server replied"}
	}
}

// reap waits for the child process, force-killing it after a short grace
// period. The context deadline normally handles termination already; this is
// the backstop for stubborn children.
func reap(waitCh <-chan error, command *exec.Cmd) {
	select {
	case <-waitCh:
	case <-time.After(2 * time.Second):
		_ = command.Process.Kill()
		select {
		case <-waitCh:
		case <-time.After(2 * time.Second):
		}
	}
}

// endCode maps a finished context to the stable failure code.
func endCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "canceled"
}

// exitCode extracts the process exit code, or -1 when none is available.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// asToolError converts any Call error into the protocol error shape.
func asToolError(err error) *protocolError {
	var toolErr *ToolError
	if errors.As(err, &toolErr) {
		return &protocolError{Code: toolErr.Code, Message: toolErr.Message}
	}
	return &protocolError{Code: "tool_error", Message: err.Error()}
}

// failParse records a pre-execution failure (bad fixture, failed start).
func failParse(result *Result, code, message string) {
	result.Status = StatusFailed
	result.Error = &protocolError{Code: code, Message: message}
}

// capJSON serializes a step value into the manifest, truncating oversized
// results into a valid diagnostic shape instead of echoing unbounded bytes.
func capJSON(value any, limit int) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	if len(raw) <= limit {
		return json.RawMessage(raw)
	}
	preview, err := json.Marshal(string(raw[:limit]))
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(`{"truncated":true,"preview":` + string(preview) + `}`)
}

// refOf summarizes a stored artifact for the manifest and script replies.
func (runner *Runner) refOf(stored artifact.Artifact) ArtifactRef {
	return ArtifactRef{
		ID:        stored.ID,
		Kind:      stored.Kind,
		MimeType:  stored.MimeType,
		SizeBytes: stored.SizeBytes,
		SHA256:    stored.SHA256,
		URL:       runner.artifactURL(stored.ContextID, stored.ID),
	}
}

func (runner *Runner) artifactURL(contextID, id string) string {
	return fmt.Sprintf("%s/artifacts/%s?context=%s", runner.config.ArtifactBaseURL, id, contextID)
}

// maxLineBytes is the per-line cap: large enough for one base64 artifact at
// the configured cap, with slack for the envelope.
func (runner *Runner) maxLineBytes() int {
	limit := int(runner.config.MaxOutputBytes)*2 + 4<<10
	if limit < 64<<10 {
		limit = 64 << 10
	}
	return limit
}

// readLines streams stdout into one bounded event per line, stopping on the
// first too-long line.
func readLines(reader io.Reader, events chan<- lineEvent, maxLine int) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), maxLine)
	for scanner.Scan() {
		line := make([]byte, len(scanner.Bytes()))
		copy(line, scanner.Bytes())
		events <- lineEvent{line: line}
	}
	if err := scanner.Err(); err != nil {
		events <- lineEvent{err: err}
		return
	}
	events <- lineEvent{err: io.EOF}
}

// pythonEnv is a minimal, deterministic environment: an explicit PATH, no
// user-site packages, no bytecode caches, and unbuffered stdout so protocol
// lines reach the server immediately.
func (runner *Runner) pythonEnv() []string {
	binaryDir := filepath.Dir(runner.config.PythonCmd)
	var path string
	if runtime.GOOS == "windows" {
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		path = binaryDir + ";" + filepath.Join(systemRoot, "System32")
	} else {
		path = binaryDir + ":/usr/bin:/bin"
	}
	return []string{
		"PATH=" + path,
		"PYTHONNOUSERSITE=1",
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONUNBUFFERED=1",
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Manifest
// ----------------------------------------------------------------------------------------------------------------------

type manifestScript struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

type manifest struct {
	ExperimentID   string         `json:"experiment_id"`
	Script         manifestScript `json:"script"`
	ContextID      string         `json:"context_id"`
	StartedAt      time.Time      `json:"started_at"`
	DurationMS     int64          `json:"duration_ms"`
	Status         string         `json:"status"`
	ExitCode       int            `json:"exit_code,omitempty"`
	Arguments      map[string]any `json:"arguments,omitempty"`
	InitialStateID string         `json:"initial_state_id,omitempty"`
	FinalStateID   string         `json:"final_state_id,omitempty"`
	Summary        map[string]any `json:"summary,omitempty"`
	Steps          []StepRecord   `json:"steps"`
	Artifacts      []ArtifactRef  `json:"artifacts"`
	Error          *protocolError `json:"error,omitempty"`
}

func (runner *Runner) manifestJSON(result *Result) manifest {
	return manifest{
		ExperimentID:   result.ExperimentID,
		Script:         manifestScript{Name: result.ScriptName, Kind: result.ScriptKind, SHA256: result.ScriptSHA256},
		ContextID:      result.ContextID,
		StartedAt:      result.StartedAt,
		DurationMS:     result.DurationMS,
		Status:         result.Status,
		ExitCode:       result.ExitCode,
		Arguments:      result.Arguments,
		InitialStateID: result.InitialStateID,
		FinalStateID:   result.FinalStateID,
		Summary:        result.Summary,
		Steps:          result.Steps,
		Artifacts:      result.Artifacts,
		Error:          result.Error,
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Bounded stderr capture
// ----------------------------------------------------------------------------------------------------------------------

// boundedBuffer keeps the first limit bytes of a stream and records whether
// the rest was dropped.
type boundedBuffer struct {
	buffer    bytes.Buffer
	limit     int64
	truncated bool
}

func newBoundedBuffer(limit int64) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (buffer *boundedBuffer) Write(payload []byte) (int, error) {
	remaining := buffer.limit - int64(buffer.buffer.Len())
	if remaining > 0 {
		if int64(len(payload)) > remaining {
			buffer.buffer.Write(payload[:remaining])
			buffer.truncated = true
		} else {
			buffer.buffer.Write(payload)
		}
	} else if len(payload) > 0 {
		buffer.truncated = true
	}
	return len(payload), nil
}

func (buffer *boundedBuffer) String() string {
	text := buffer.buffer.String()
	if buffer.truncated {
		return text + fmt.Sprintf("\n[stderr truncated at %d bytes]\n", buffer.limit)
	}
	return text
}
