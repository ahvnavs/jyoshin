// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/jyoshin/internal/fs"
)

func TestNetworkSensor_SocketParsing(t *testing.T) {
	root := t.TempDir()

	mustWrite := func(relPath, content string) {
		full := filepath.Join(root, relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// 127.0.0.1:7777 (7777 decimal = 1E61 hex, 127.0.0.1 = 0100007F)
	// State 0A (LISTEN), inode 445566
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:1E61 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 445566 1 0000000000000000 100 0 0 10 0                     
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 112233 1 0000000000000000 100 0 0 10 0                     
   2: 0100007F:1E61 0100007F:9ABC 01 00000000:00000000 00:00000000 00000000  1000        0 778899 1 0000000000000000 100 0 0 10 0                     
`
	mustWrite("/proc/net/tcp", tcpContent)

	// Mock PID 1024 holding socket inode 445566
	mustWrite("/proc/1024/comm", "jyoshin\n")
	proc1024Fd := filepath.Join(root, "proc/1024/fd")
	if err := os.MkdirAll(proc1024Fd, 0755); err != nil {
		t.Fatal(err)
	}
	// Symlink socket:[445566]
	if err := os.Symlink("socket:[445566]", filepath.Join(proc1024Fd, "3")); err != nil {
		t.Fatal(err)
	}

	rfs := fs.NewRootedFS(root)
	sensor := New(rfs)

	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected collect error: %v", err)
	}

	report := obs.Items[0].Data.(NetworkReport)
	if len(report.Listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(report.Listeners))
	}
	if report.EstablishedCount != 1 {
		t.Fatalf("expected 1 established connection, got %d", report.EstablishedCount)
	}

	var foundJyoshinListener bool
	for _, l := range report.Listeners {
		if l.LocalPort == 7777 {
			foundJyoshinListener = true
			if l.PID != 1024 || l.ProcessName != "jyoshin" {
				t.Errorf("expected PID 1024 / jyoshin, got PID %d / %s", l.PID, l.ProcessName)
			}
			if l.ExposureClass != ExposureLoopback {
				t.Errorf("expected loopback exposure for 127.0.0.1, got %s", l.ExposureClass)
			}
		}
	}

	if !foundJyoshinListener {
		t.Errorf("did not find port 7777 listener")
	}
}
