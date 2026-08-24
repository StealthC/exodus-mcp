package analysis

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Lease is an exclusive mutation right on one analysis context. At most one
// lease can be active per context: acquiring a new lease while another is
// active fails, so two agents cannot mutate the same emulator system
// concurrently through the same context.
type Lease struct {
	ID        string        `json:"id"`
	ContextID string        `json:"context_id"`
	Purpose   string        `json:"purpose"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	TTL       time.Duration `json:"ttl_ms"`
}

// Lease defaults and limits.
const (
	DefaultLeaseTTL = 5 * time.Minute
	MaxLeaseTTL     = 1 * time.Hour
)

// LeaseRegistry tracks the active lease of every context. Expiry is lazy:
// expired leases are dropped on the next touch so a crashed agent cannot
// block its own context forever.
type LeaseRegistry struct {
	mu     sync.Mutex
	leases map[string]*Lease
}

func newLeaseRegistry() *LeaseRegistry {
	return &LeaseRegistry{leases: make(map[string]*Lease)}
}

// Acquire takes the exclusive lease of one context. It fails when a lease is
// already active, including one that has not expired yet.
func (registry *LeaseRegistry) Acquire(contextID, purpose string, ttl time.Duration) (*Lease, error) {
	if purpose == "" {
		return nil, fmt.Errorf("lease purpose must not be empty")
	}
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	if ttl > MaxLeaseTTL {
		ttl = MaxLeaseTTL
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.dropExpiredLocked(contextID)
	if existing := registry.leases[contextID]; existing != nil {
		return nil, fmt.Errorf("context %q already holds lease %q until %s", contextID, existing.ID, existing.ExpiresAt.Format(time.RFC3339))
	}
	now := time.Now().UTC()
	lease := &Lease{
		ID:        newLeaseID(),
		ContextID: contextID,
		Purpose:   purpose,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		TTL:       ttl,
	}
	registry.leases[contextID] = lease
	return lease, nil
}

// Renew extends an active lease. The caller must present the exact lease id
// that owns the context, otherwise the lease is left untouched.
func (registry *LeaseRegistry) Renew(contextID, leaseID string, ttl time.Duration) (*Lease, error) {
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	if ttl > MaxLeaseTTL {
		ttl = MaxLeaseTTL
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.dropExpiredLocked(contextID)
	lease := registry.leases[contextID]
	if lease == nil {
		return nil, fmt.Errorf("context %q holds no active lease", contextID)
	}
	if lease.ID != leaseID {
		return nil, fmt.Errorf("lease %q does not own context %q", leaseID, contextID)
	}
	lease.ExpiresAt = time.Now().UTC().Add(ttl)
	lease.TTL = ttl
	return lease, nil
}

// Release ends an active lease. Releasing the wrong id is an error so a
// stale agent cannot revoke a newer owner.
func (registry *LeaseRegistry) Release(contextID, leaseID string) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.dropExpiredLocked(contextID)
	lease := registry.leases[contextID]
	if lease == nil {
		return fmt.Errorf("context %q holds no active lease", contextID)
	}
	if lease.ID != leaseID {
		return fmt.Errorf("lease %q does not own context %q", leaseID, contextID)
	}
	delete(registry.leases, contextID)
	return nil
}

// ReleaseAll drops every lease of one context; used when the context closes.
func (registry *LeaseRegistry) ReleaseAll(contextID string) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	delete(registry.leases, contextID)
}

// Active returns the live lease of a context, or nil. Expired leases are
// dropped as a side effect.
func (registry *LeaseRegistry) Active(contextID string) *Lease {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.dropExpiredLocked(contextID)
	return registry.leases[contextID]
}

// Valid reports whether leaseID is the live lease of the context right now.
func (registry *LeaseRegistry) Valid(contextID, leaseID string) bool {
	lease := registry.Active(contextID)
	return lease != nil && lease.ID == leaseID
}

// dropExpiredLocked removes an expired lease; callers must hold the lock.
func (registry *LeaseRegistry) dropExpiredLocked(contextID string) {
	lease := registry.leases[contextID]
	if lease != nil && time.Now().UTC().After(lease.ExpiresAt) {
		delete(registry.leases, contextID)
	}
}

func newLeaseID() string {
	buffer := make([]byte, 9)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("generate lease id: %v", err))
	}
	return "lease_" + base64.RawURLEncoding.EncodeToString(buffer)
}
