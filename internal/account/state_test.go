package account

import (
	"testing"
	"time"
)

func TestLoadOrCreatePersistsCloudAccountID(t *testing.T) {
	store, err := NewStore(t.TempDir(), Credentials{
		Name:     "unit",
		Username: "user",
		Password: "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(123)
	state, err := store.LoadOrCreate(now)
	if err != nil {
		t.Fatal(err)
	}
	if state.Installation.CloudAccountID == "" {
		t.Fatal("new installation has no cloud account ID")
	}
	cloudAccountID := state.Installation.CloudAccountID

	restored, err := store.LoadOrCreate(now)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Installation.CloudAccountID != cloudAccountID {
		t.Fatalf("cloud account ID changed across reload: got %q, want %q", restored.Installation.CloudAccountID, cloudAccountID)
	}
}
