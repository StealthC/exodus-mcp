package analysis

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Target tracks the process-local observable machine revision and its
// synchronization state. An Exodus process owns exactly one mutable emulated
// machine, so one Target covers the whole server process.
//
// target_generation is an opaque concurrency token: it starts at 1, advances
// exactly once after every successful target-mutating operation, and is never
// reused during the process. Clients must compare it for equality and must
// not infer ordering across server restarts.
type Target struct {
	mu         sync.Mutex
	generation uint64
	unknown    bool
}

// NewTarget creates the target state at generation 1, known.
func NewTarget() *Target {
	return &Target{generation: 1}
}

// Generation returns the current generation. While the target is in the
// unknown/resynchronization state this is the last known generation, never a
// value that can be trusted as current.
func (target *Target) Generation() uint64 {
	target.mu.Lock()
	defer target.mu.Unlock()
	return target.generation
}

// Unknown reports whether the target revision is unknown because an ambiguous
// native failure (transport error, timeout, undecodable payload) could have
// mutated the machine without the server being able to prove it.
func (target *Target) Unknown() bool {
	target.mu.Lock()
	defer target.mu.Unlock()
	return target.unknown
}

// MarkUnknown records that the outcome of a mutating operation is ambiguous.
// Revision-guarded mutations are rejected while unknown; only a successful
// observation (ResynchronizeIfUnknown) re-establishes the revision.
func (target *Target) MarkUnknown() {
	target.mu.Lock()
	defer target.mu.Unlock()
	target.unknown = true
}

// ResynchronizeIfUnknown re-establishes the revision after an unknown window
// when a successful observation proves the bridge is reachable. The
// generation always advances because the machine may have changed while
// unknown; the old generation is never returned as though the target were
// known unchanged. Returns the new generation, or 0 when already known.
func (target *Target) ResynchronizeIfUnknown() uint64 {
	target.mu.Lock()
	defer target.mu.Unlock()
	if !target.unknown {
		return 0
	}
	target.generation++
	target.unknown = false
	return target.generation
}

// Advance records one successful target mutation and returns the new
// generation. An unguarded mutation may succeed while unknown; advancing
// re-establishes the known state.
func (target *Target) Advance() uint64 {
	target.mu.Lock()
	defer target.mu.Unlock()
	target.generation++
	target.unknown = false
	return target.generation
}

// ----------------------------------------------------------------------------------------------------------------------
// Exclusive target control lock
// ----------------------------------------------------------------------------------------------------------------------

// Control lock defaults and limits. The lock is a short-lived exclusive
// window over the one Exodus instance; conservative TTLs keep contention
// diagnostics honest.
const (
	DefaultControlTTL = 5 * time.Minute
	MaxControlTTL     = 1 * time.Hour
)

// ControlLock is one process-wide exclusive control window over the target.
// The control_id is a capability token: it is returned only to the acquirer
// and must never appear in list or status responses for other callers.
type ControlLock struct {
	ID         string
	Purpose    string
	ContextID  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	TTL        time.Duration
	Generation uint64 // target generation observed at acquisition
}

// ControlHeldError reports that an exclusive control lock is already active.
type ControlHeldError struct {
	Lock *ControlLock
}

func (err *ControlHeldError) Error() string {
	return fmt.Sprintf("target control is held: %q expires at %s", err.Lock.Purpose, err.Lock.ExpiresAt.Format(time.RFC3339))
}

// ControlRegistry owns the single process-wide control lock. Expiry is lazy:
// an expired lock is dropped on the next touch, and the drop hook records why
// it ended.
type ControlRegistry struct {
	mu     sync.Mutex
	lock   *ControlLock
	onDrop func(lock *ControlLock, reason string)
}

// NewControlRegistry creates an empty control registry.
func NewControlRegistry() *ControlRegistry {
	return &ControlRegistry{}
}

// SetDropHook installs the callback invoked whenever an active lock ends for
// any reason (release, TTL expiry, context close, bridge loss). The hook runs
// without the registry lock held, so it may safely write to other stores such
// as the audit stream.
func (registry *ControlRegistry) SetDropHook(hook func(lock *ControlLock, reason string)) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.onDrop = hook
}

// dropLocked ends the active lock and notifies the hook outside the registry
// lock. Callers must hold the registry lock.
func (registry *ControlRegistry) dropLocked(lock *ControlLock, reason string) {
	registry.lock = nil
	hook := registry.onDrop
	if hook == nil {
		return
	}
	registry.mu.Unlock()
	defer registry.mu.Lock()
	hook(lock, reason)
}

// activeLocked drops an expired lock and returns the live one; callers must
// hold the registry lock.
func (registry *ControlRegistry) activeLocked() *ControlLock {
	if registry.lock == nil {
		return nil
	}
	if time.Now().UTC().After(registry.lock.ExpiresAt) {
		registry.dropLocked(registry.lock, "ttl_expired")
		return nil
	}
	return registry.lock
}

// Acquire takes the exclusive control window. purpose must be non-empty; ttl
// defaults to DefaultControlTTL and is capped at MaxControlTTL. generation is
// the target generation observed at acquisition. When another lock is active,
// acquisition fails with a ControlHeldError carrying the incumbent.
func (registry *ControlRegistry) Acquire(purpose, contextID string, ttl time.Duration, generation uint64) (*ControlLock, error) {
	if strings.TrimSpace(purpose) == "" {
		return nil, errors.New("control purpose must not be empty")
	}
	if ttl <= 0 {
		ttl = DefaultControlTTL
	}
	if ttl > MaxControlTTL {
		ttl = MaxControlTTL
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if existing := registry.activeLocked(); existing != nil {
		return nil, &ControlHeldError{Lock: existing}
	}
	lock := &ControlLock{
		ID:         newControlID(),
		Purpose:    purpose,
		ContextID:  contextID,
		CreatedAt:  time.Now().UTC(),
		TTL:        ttl,
		Generation: generation,
	}
	lock.ExpiresAt = lock.CreatedAt.Add(ttl)
	registry.lock = lock
	return lock, nil
}

// Renew extends the active lock. The caller must present the exact live
// control id, otherwise the lock is left untouched.
func (registry *ControlRegistry) Renew(id string, ttl time.Duration) (*ControlLock, error) {
	if ttl <= 0 {
		ttl = DefaultControlTTL
	}
	if ttl > MaxControlTTL {
		ttl = MaxControlTTL
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	lock := registry.activeLocked()
	if lock == nil {
		return nil, errors.New("no active control lock; acquire one with target_control_acquire")
	}
	if lock.ID != id {
		return nil, errors.New("control id does not own the active lock")
	}
	lock.ExpiresAt = time.Now().UTC().Add(ttl)
	lock.TTL = ttl
	copy := *lock
	return &copy, nil
}

// Release ends the active lock early. Presenting the wrong id is an error so
// a stale agent cannot revoke the current owner. reason is recorded through
// the drop hook.
func (registry *ControlRegistry) Release(id, reason string) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	lock := registry.lock
	if lock == nil {
		return errors.New("no active control lock; acquire one with target_control_acquire")
	}
	if lock.ID != id {
		return errors.New("control id does not own the active lock")
	}
	registry.dropLocked(lock, reason)
	return nil
}

// DropIf ends the active lock when match accepts it, recording reason through
// the drop hook. Reports whether a lock was dropped.
func (registry *ControlRegistry) DropIf(match func(*ControlLock) bool, reason string) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	lock := registry.activeLocked()
	if lock == nil || !match(lock) {
		return false
	}
	registry.dropLocked(lock, reason)
	return true
}

// Active returns a copy of the live lock, or nil. Expired locks are dropped
// lazily here.
func (registry *ControlRegistry) Active() *ControlLock {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	lock := registry.activeLocked()
	if lock == nil {
		return nil
	}
	copy := *lock
	return &copy
}

// Valid reports whether id owns the live lock right now.
func (registry *ControlRegistry) Valid(id string) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	lock := registry.activeLocked()
	return lock != nil && lock.ID == id
}

func newControlID() string {
	buffer := make([]byte, 9)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("generate control id: %v", err))
	}
	return "ctl_" + base64.RawURLEncoding.EncodeToString(buffer)
}
