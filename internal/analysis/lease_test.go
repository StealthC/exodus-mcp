package analysis

import (
	"strings"
	"testing"
	"time"
)

func TestLeaseAcquireExclusiveAndRelease(t *testing.T) {
	registry := newLeaseRegistry()
	lease, err := registry.Acquire("ctx_a", "state experiment", DefaultLeaseTTL)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !strings.HasPrefix(lease.ID, "lease_") {
		t.Fatalf("lease id %q lacks lease_ prefix", lease.ID)
	}
	if lease.ContextID != "ctx_a" || lease.Purpose != "state experiment" {
		t.Fatalf("unexpected lease: %+v", lease)
	}
	if !lease.ExpiresAt.After(lease.CreatedAt) {
		t.Fatalf("lease expiry %s not after creation %s", lease.ExpiresAt, lease.CreatedAt)
	}

	if _, err := registry.Acquire("ctx_a", "second owner", DefaultLeaseTTL); err == nil {
		t.Fatal("second acquire on the same context must fail")
	}

	if !registry.Valid("ctx_a", lease.ID) {
		t.Fatal("fresh lease must be valid")
	}
	if registry.Valid("ctx_a", "lease_wrong") {
		t.Fatal("wrong lease id must be invalid")
	}
	if registry.Active("ctx_b") != nil {
		t.Fatal("context without a lease must report none")
	}

	if err := registry.Release("ctx_a", "lease_wrong"); err == nil {
		t.Fatal("releasing a foreign lease id must fail")
	}
	if err := registry.Release("ctx_a", lease.ID); err != nil {
		t.Fatalf("release: %v", err)
	}
	if registry.Active("ctx_a") != nil {
		t.Fatal("released lease must be gone")
	}
	// Releasing again reports no active lease.
	if err := registry.Release("ctx_a", lease.ID); err == nil {
		t.Fatal("double release must fail")
	}
}

func TestLeaseRenewExtendsExpiry(t *testing.T) {
	registry := newLeaseRegistry()
	lease, err := registry.Acquire("ctx_a", "experiment", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	original := lease.ExpiresAt
	time.Sleep(2 * time.Millisecond)
	renewed, err := registry.Renew("ctx_a", lease.ID, time.Hour)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !renewed.ExpiresAt.After(original) {
		t.Fatalf("renewal did not extend expiry: %s -> %s", original, renewed.ExpiresAt)
	}
	if _, err := registry.Renew("ctx_a", "lease_wrong", time.Minute); err == nil {
		t.Fatal("renewing with a foreign id must fail")
	}
}

func TestLeaseExpiryIsLazy(t *testing.T) {
	registry := newLeaseRegistry()
	lease, err := registry.Acquire("ctx_a", "short", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.Valid("ctx_a", lease.ID) {
		t.Fatal("lease must be valid before expiry")
	}
	time.Sleep(5 * time.Millisecond)
	if registry.Valid("ctx_a", lease.ID) {
		t.Fatal("expired lease must be invalid")
	}
	// The expired lease must not block a new acquisition.
	if _, err := registry.Acquire("ctx_a", "second", DefaultLeaseTTL); err != nil {
		t.Fatalf("acquire after expiry: %v", err)
	}
}

func TestLeaseDefaultsAndLimits(t *testing.T) {
	registry := newLeaseRegistry()
	zero, err := registry.Acquire("ctx_a", "zero ttl", 0)
	if err != nil {
		t.Fatal(err)
	}
	if zero.TTL != DefaultLeaseTTL {
		t.Fatalf("zero ttl should default to %v, got %v", DefaultLeaseTTL, zero.TTL)
	}
	huge, err := registry.Acquire("ctx_b", "huge ttl", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if huge.TTL != MaxLeaseTTL {
		t.Fatalf("oversized ttl should clamp to %v, got %v", MaxLeaseTTL, huge.TTL)
	}
	if _, err := registry.Acquire("ctx_c", "", time.Minute); err == nil {
		t.Fatal("empty purpose must fail")
	}
}

func TestLeaseReleaseAll(t *testing.T) {
	registry := newLeaseRegistry()
	lease, err := registry.Acquire("ctx_a", "experiment", DefaultLeaseTTL)
	if err != nil {
		t.Fatal(err)
	}
	registry.ReleaseAll("ctx_a")
	if registry.Active("ctx_a") != nil {
		t.Fatal("ReleaseAll must drop the lease")
	}
	_ = lease
}

func TestContextCloseReleasesLease(t *testing.T) {
	registry := NewRegistry()
	context, err := registry.Create("experiment")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := registry.Leases.Acquire(context.ID, "experiment", DefaultLeaseTTL)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.Leases.Valid(context.ID, lease.ID) {
		t.Fatal("lease must be valid while the context is open")
	}
	if _, err := registry.Close(context.ID); err != nil {
		t.Fatal(err)
	}
	if registry.Leases.Active(context.ID) != nil {
		t.Fatal("closing the context must release its lease")
	}
}
