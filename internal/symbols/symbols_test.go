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
