package symbols

import "testing"

func TestSetListClear(t *testing.T) {
	store := NewStore()
	written, err := store.Set([]Symbol{
		{Name: "main", SpaceID: "m68k-bus", Address: 8356},
		{Name: "start", Address: 512},
	})
	if err != nil || written != 2 {
		t.Fatalf("set failed: %d %v", written, err)
	}
	listed := store.List("")
	if listed[0].Name != "start" || listed[1].Name != "main" {
		t.Fatalf("order wrong: %+v", listed)
	}
	if store.List("MAI")[0].Name != "main" {
		t.Fatal("prefix filter is case-insensitive by contract")
	}

	written, _ = store.Set([]Symbol{{Name: "main", Address: 9000}})
	if written != 1 {
		t.Fatalf("upsert count wrong: %d", written)
	}
	main := store.List("main")[0]
	if main.Address != 9000 {
		t.Fatalf("upsert did not replace: %+v", main)
	}

	if removed := store.Clear(); removed != 2 {
		t.Fatalf("clear removed %d", removed)
	}
	if len(store.List("")) != 0 {
		t.Fatal("store must be empty after clear")
	}
}

func TestSetRejectsEmptyNames(t *testing.T) {
	store := NewStore()
	if _, err := store.Set([]Symbol{{Name: "", Address: 1}}); err == nil {
		t.Fatal("empty symbol name must be rejected")
	}
	if _, err := store.Set(nil); err != nil {
		t.Fatalf("nil batch must be a no-op: %v", err)
	}
}

// TestSetPreservesBothCoordinates guards the data model: a symbol stored
// space-relative must keep the space coordinate the caller supplied next to the
// resolved processor-bus coordinate. Set previously rebuilt symbols field by
// field, which silently dropped anything added to Symbol.
func TestSetPreservesBothCoordinates(t *testing.T) {
	store := NewStore()
	written, err := store.Set([]Symbol{{
		Name:       "score",
		SpaceID:    "mem-ram",
		Address:    0x1000,
		BusSpaceID: "m68k-bus",
		BusAddress: 0xFF1000,
	}})
	if err != nil || written != 1 {
		t.Fatalf("set failed: %d %v", written, err)
	}
	stored := store.List("")[0]
	if stored.SpaceID != "mem-ram" || stored.Address != 0x1000 {
		t.Fatalf("space coordinate lost: %+v", stored)
	}
	if stored.BusSpaceID != "m68k-bus" || stored.BusAddress != 0xFF1000 {
		t.Fatalf("bus coordinate lost: %+v", stored)
	}
	if spaceID, address, ok := stored.BusCoordinate(); !ok || spaceID != "m68k-bus" || address != 0xFF1000 {
		t.Fatalf("BusCoordinate() = %q, %#x, %v", spaceID, address, ok)
	}
}

// TestBusCoordinateAbsentForLegacySymbol pins the backward-compatibility rule:
// a symbol written with only SpaceID/Address reports no recorded bus
// coordinate, so resolution derives it from the space mapping.
func TestBusCoordinateAbsentForLegacySymbol(t *testing.T) {
	legacy := Symbol{Name: "main", SpaceID: "m68k-bus", Address: 0x2064}
	if _, _, ok := legacy.BusCoordinate(); ok {
		t.Fatalf("legacy symbol must not report a recorded bus coordinate: %+v", legacy)
	}
	untyped := Symbol{Name: "raw", Address: 0x100}
	if _, _, ok := untyped.BusCoordinate(); ok {
		t.Fatalf("untyped symbol must not report a bus coordinate: %+v", untyped)
	}
}
