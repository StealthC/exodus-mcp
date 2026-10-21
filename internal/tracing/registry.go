package tracing

import "sync"

// Registry owns the single active-or-retained trace session of one server
// process. The emulator exposes one trace channel per processor, so the
// server keeps one session at a time: starting a new session retires the
// previous one and reports what it discarded instead of silently replacing
// it.
type Registry struct {
	mu      sync.Mutex
	current *Session
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Replace installs session as the current session and returns the previous
// one (nil when there was none). The retired session stays readable through
// the returned pointer.
func (registry *Registry) Replace(session *Session) *Session {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	previous := registry.current
	registry.current = session
	return previous
}

// Current returns the current session, or nil.
func (registry *Registry) Current() *Session {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.current
}

// Clear forgets the current session.
func (registry *Registry) Clear() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.current = nil
}
