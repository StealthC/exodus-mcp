package analysis

import (
	"strings"
	"testing"
	"time"
)

func TestTargetGenerationStartsAtOneAndAdvances(t *testing.T) {
	target := NewTarget()
	if target.Generation() != 1 {
		t.Fatalf("initial generation = %d, want 1", target.Generation())
	}
	if target.Advance() != 2 {
		t.Fatalf("advance = %d, want 2", target.Advance())
	}
	if target.Unknown() {
		t.Fatal("a successful advance must leave the target known")
	}
}

func TestTargetUnknownBlocksGuardedMutationsUntilResync(t *testing.T) {
	target := NewTarget()
	target.MarkUnknown()
	if !target.Unknown() {
		t.Fatal("MarkUnknown must set the unknown state")
	}
	// The last known generation is still reported, never as current.
	if target.Generation() != 1 {
		t.Fatalf("last known generation = %d, want 1", target.Generation())
	}
	// A successful observation resynchronizes and advances; the old
	// generation must never be treated as current again.
	if target.ResynchronizeIfUnknown() != 2 {
		t.Fatalf("resync generation = %d, want 2", target.ResynchronizeIfUnknown())
	}
	if target.Unknown() {
		t.Fatal("resync must clear the unknown state")
	}
	// A known target does not resync.
	if target.ResynchronizeIfUnknown() != 0 {
		t.Fatal("ResynchronizeIfUnknown on a known target must be a no-op")
	}
}

func TestTargetUnguardedMutationRecoversFromUnknown(t *testing.T) {
	target := NewTarget()
	target.MarkUnknown()
	if target.Advance() != 2 {
		t.Fatalf("advance from unknown = %d, want 2", target.Advance())
	}
	if target.Unknown() {
		t.Fatal("a successful advance must clear the unknown state")
	}
}

func TestControlAcquireExclusiveAndRelease(t *testing.T) {
	registry := NewControlRegistry()
	lock, err := registry.Acquire("state experiment", "ctx_a", DefaultControlTTL, 7)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !strings.HasPrefix(lock.ID, "ctl_") {
		t.Fatalf("control id %q lacks ctl_ prefix", lock.ID)
	}
	if lock.Purpose != "state experiment" || lock.ContextID != "ctx_a" || lock.Generation != 7 {
		t.Fatalf("unexpected lock: %+v", lock)
	}
	if !lock.ExpiresAt.After(lock.CreatedAt) {
		t.Fatalf("expiry %s not after creation %s", lock.ExpiresAt, lock.CreatedAt)
	}
	if _, err := registry.Acquire("second owner", "ctx_b", DefaultControlTTL, 7); err == nil {
		t.Fatal("acquiring while a lock is active must fail")
	} else if held, ok := err.(*ControlHeldError); !ok || held.Lock.ID != lock.ID {
		t.Fatalf("conflict must be ControlHeldError naming the incumbent, got %v", err)
	}
	if !registry.Valid(lock.ID) {
		t.Fatal("fresh lock must be valid")
	}
	if registry.Valid("ctl_wrong") {
		t.Fatal("wrong control id must be invalid")
	}
	if err := registry.Release("ctl_wrong", "test"); err == nil {
		t.Fatal("releasing a foreign id must fail")
	}
	if err := registry.Release(lock.ID, "caller_released"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if registry.Active() != nil {
		t.Fatal("released lock must be gone")
	}
	if err := registry.Release(lock.ID, "test"); err == nil {
		t.Fatal("double release must fail")
	}
}

func TestControlRenewExtendsExpiry(t *testing.T) {
	registry := NewControlRegistry()
	lock, err := registry.Acquire("experiment", "ctx_a", time.Minute, 3)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	original := lock.ExpiresAt
	time.Sleep(2 * time.Millisecond)
	renewed, err := registry.Renew(lock.ID, time.Hour)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !renewed.ExpiresAt.After(original) {
		t.Fatalf("renewal must extend expiry: %s -> %s", original, renewed.ExpiresAt)
	}
	if _, err := registry.Renew("ctl_wrong", time.Minute); err == nil {
		t.Fatal("renewing with a foreign id must fail")
	}
}

func TestControlExpiryIsLazy(t *testing.T) {
	var dropped []string
	registry := NewControlRegistry()
	registry.SetDropHook(func(lock *ControlLock, reason string) {
		dropped = append(dropped, lock.ID+":"+reason)
	})
	lock, err := registry.Acquire("short", "ctx_a", time.Millisecond, 1)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !registry.Valid(lock.ID) {
		t.Fatal("lock must be valid before expiry")
	}
	time.Sleep(5 * time.Millisecond)
	if registry.Valid(lock.ID) {
		t.Fatal("expired lock must be invalid")
	}
	if registry.Active() != nil {
		t.Fatal("expired lock must be dropped")
	}
	if len(dropped) != 1 || !strings.HasSuffix(dropped[0], ":ttl_expired") {
		t.Fatalf("drop hook must record ttl_expired, got %v", dropped)
	}
	// The expired lock must not block a new acquisition.
	second, err := registry.Acquire("second", "ctx_a", DefaultControlTTL, 1)
	if err != nil {
		t.Fatalf("acquire after expiry: %v", err)
	}
	if second.ID == lock.ID {
		t.Fatal("new acquisition must mint a fresh id")
	}
}

func TestControlDefaultsAndLimits(t *testing.T) {
	registry := NewControlRegistry()
	zero, err := registry.Acquire("zero", "", 0, 1)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if zero.TTL != DefaultControlTTL {
		t.Fatalf("zero ttl should default to %v, got %v", DefaultControlTTL, zero.TTL)
	}
	_ = registry.Release(zero.ID, "test")

	huge, err := registry.Acquire("huge", "", 24*time.Hour, 1)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if huge.TTL != MaxControlTTL {
		t.Fatalf("oversized ttl should clamp to %v, got %v", MaxControlTTL, huge.TTL)
	}
	_ = registry.Release(huge.ID, "test")

	if _, err := registry.Acquire("", "", time.Minute, 1); err == nil {
		t.Fatal("empty purpose must fail")
	}
}

func TestControlDropIfMatchesContext(t *testing.T) {
	registry := NewControlRegistry()
	lock, err := registry.Acquire("ctx work", "ctx_a", time.Minute, 1)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if registry.DropIf(func(candidate *ControlLock) bool { return candidate.ContextID == "ctx_other" }, "context_closed") {
		t.Fatal("DropIf must not drop a lock of another context")
	}
	if !registry.DropIf(func(candidate *ControlLock) bool { return candidate.ContextID == "ctx_a" }, "context_closed") {
		t.Fatal("DropIf must drop the matching lock")
	}
	if registry.Active() != nil {
		t.Fatal("lock must be gone after DropIf")
	}
	_ = lock
}
