package mcp

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// inputPortLedger is what this server commanded to one controller port. The
// pinned plugin exposes no operation that reads the current button state (see
// BuildInputSetData: input_set only writes), so "currently pressed" cannot be
// observed. Instead of inventing a read, input_status reports the server's own
// command ledger and says so: verified_by_emulator is false, and a target
// generation change (reset, ROM load, state restore done elsewhere) marks the
// entry stale because the pad may have changed behind the server's back.
type inputPortLedger struct {
	Player     uint64    `json:"player"`
	Buttons    []string  `json:"buttons"`
	Controller string    `json:"controller_instance,omitempty"`
	LastTool   string    `json:"last_tool"`
	UpdatedAt  time.Time `json:"updated_at"`
	Generation uint64    `json:"target_generation"`
}

// inputLedger is the per-server input state, cleared when the target changes
// identity underneath it.
type inputLedger struct {
	mu    sync.Mutex
	ports map[uint64]inputPortLedger
}

func newInputLedger() *inputLedger {
	return &inputLedger{ports: map[uint64]inputPortLedger{}}
}

// set replaces the commanded button set of one port, keeping the controller
// identity the native input_set echo reported.
func (ledger *inputLedger) set(player uint64, buttons []string, controller, tool string, generation uint64) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	entry := ledger.ports[player]
	entry.Player = player
	entry.Buttons = normalizedButtons(buttons)
	if controller != "" {
		entry.Controller = controller
	}
	entry.LastTool = tool
	entry.UpdatedAt = time.Now().UTC()
	entry.Generation = generation
	ledger.ports[player] = entry
}

// clear forgets every port, so an input identity change is never reported as a
// still-pressed button.
func (ledger *inputLedger) clear() {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.ports = map[uint64]inputPortLedger{}
}

// view renders the ledger as a stable, honest response. currentGeneration is
// the live target generation; an entry captured under another generation is
// flagged stale instead of being reported as current.
func (ledger *inputLedger) view(player uint64, currentGeneration uint64) []map[string]any {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ports := make([]uint64, 0, len(ledger.ports))
	for port := range ledger.ports {
		if player != 0 && port != player {
			continue
		}
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	views := make([]map[string]any, 0, len(ports))
	for _, port := range ports {
		entry := ledger.ports[port]
		stale := entry.Generation != currentGeneration
		view := map[string]any{
			"player":                entry.Player,
			"buttons":               append([]string{}, entry.Buttons...),
			"button_count":          len(entry.Buttons),
			"controller_instance":   nil,
			"pad_type":              nil,
			"pad_type_source":       "unknown",
			"verified_by_emulator":  false,
			"last_tool":             entry.LastTool,
			"updated_at":            entry.UpdatedAt,
			"target_generation":     entry.Generation,
			"stale":                 stale,
			"current_generation":    currentGeneration,
			"state_from":            "server_input_ledger",
			"native_read_supported": false,
		}
		if entry.Controller != "" {
			view["controller_instance"] = entry.Controller
			view["pad_type"] = entry.Controller
			view["pad_type_source"] = "native_input_set_echo"
		}
		if stale {
			view["stale_reason"] = "the target generation changed after this command, so the pad may have been reset or restored by another actor"
		}
		views = append(views, view)
	}
	return views
}

// normalizedButtons lowercases, deduplicates, and sorts a button set so the
// ledger output is deterministic.
func normalizedButtons(buttons []string) []string {
	if len(buttons) == 0 {
		return []string{}
	}
	seen := map[string]bool{}
	normalized := make([]string, 0, len(buttons))
	for _, button := range buttons {
		name := strings.ToLower(strings.TrimSpace(button))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		normalized = append(normalized, name)
	}
	sort.Strings(normalized)
	return normalized
}

// recordInputCommand folds one successful native input_set echo into the ledger:
// state "down" adds the buttons to the held set, "up" removes them.
func (server *Server) recordInputCommand(tool string, player uint64, buttons []string, state, controller string) {
	server.inputs.mu.Lock()
	entry := server.inputs.ports[player]
	server.inputs.mu.Unlock()
	held := map[string]bool{}
	for _, button := range entry.Buttons {
		held[button] = true
	}
	for _, button := range buttons {
		name := strings.ToLower(strings.TrimSpace(button))
		if state == "down" {
			held[name] = true
		} else {
			delete(held, name)
		}
	}
	current := make([]string, 0, len(held))
	for button := range held {
		current = append(current, button)
	}
	server.inputs.set(player, current, controller, tool, server.target.Generation())
}

// resetInputLedger forgets every commanded button set. It is called when the
// target identity changes (ROM load, reset), because no command of this server
// describes the new machine's pad state.
func (server *Server) resetInputLedger() {
	if server.inputs == nil {
		return
	}
	server.inputs.clear()
}
