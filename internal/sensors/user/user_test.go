// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestUserSensor(t *testing.T) {
	tmpDir := t.TempDir()

	// Setup fake /etc
	etcDir := filepath.Join(tmpDir, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}

	passwdContent := `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice User:/home/alice:/bin/bash
bob:x:1001:1001:Bob User:/home/bob:/bin/sh
`
	if err := os.WriteFile(filepath.Join(etcDir, "passwd"), []byte(passwdContent), 0644); err != nil {
		t.Fatal(err)
	}

	groupContent := `root:x:0:
sudo:x:27:alice
users:x:100:alice,bob
`
	if err := os.WriteFile(filepath.Join(etcDir, "group"), []byte(groupContent), 0644); err != nil {
		t.Fatal(err)
	}

	sudoersContent := `bob ALL=(ALL:ALL) ALL
`
	if err := os.WriteFile(filepath.Join(etcDir, "sudoers"), []byte(sudoersContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Setup alice .ssh/authorized_keys
	aliceSSH := filepath.Join(tmpDir, "home", "alice", ".ssh")
	if err := os.MkdirAll(aliceSSH, 0700); err != nil {
		t.Fatal(err)
	}
	authKeys := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGSECRETKEYDATA alice@workstation
# comment
command="ls" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCSECRET bob-key
`
	if err := os.WriteFile(filepath.Join(aliceSSH, "authorized_keys"), []byte(authKeys), 0600); err != nil {
		t.Fatal(err)
	}

	sensor := NewSensor(tmpDir)
	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if obs.Status != "ok" {
		t.Fatalf("expected status ok, got %s: %s", obs.Status, obs.Reason)
	}

	if len(obs.Items) != 3 {
		t.Fatalf("expected 3 users, got %d", len(obs.Items))
	}

	var alice *UserData
	var bob *UserData
	for _, it := range obs.Items {
		u := it.Data.(UserData)
		if u.Username == "alice" {
			alice = &u
		} else if u.Username == "bob" {
			bob = &u
		}
	}

	if alice == nil || bob == nil {
		t.Fatal("missing alice or bob")
	}

	if !alice.HasSudo {
		t.Errorf("alice should have sudo (member of sudo group)")
	}
	if !bob.HasSudo {
		t.Errorf("bob should have sudo (in sudoers)")
	}

	if len(alice.AuthorizedKeys) != 2 {
		t.Fatalf("expected 2 authorized keys for alice, got %d", len(alice.AuthorizedKeys))
	}

	k1 := alice.AuthorizedKeys[0]
	if k1.KeyType != "ssh-ed25519" || k1.Comment != "alice@workstation" {
		t.Errorf("unexpected key meta: %+v", k1)
	}
	k2 := alice.AuthorizedKeys[1]
	if k2.KeyType != "ssh-rsa" || k2.Comment != "bob-key" {
		t.Errorf("unexpected key meta with options: %+v", k2)
	}
}
