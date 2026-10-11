// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/kazeshini/internal/fs"
)

func TestContainerSensor(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "var/run")
	_ = os.MkdirAll(runDir, 0755)

	socketPath := filepath.Join(runDir, "docker.sock")

	// Start a mock Unix socket server simulating Docker daemon API
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create mock unix listener: %v", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/containers/json" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode([]map[string]any{
					{
						"Id":      "c1234567890abcdef",
						"Names":   []string{"/web-nginx"},
						"Image":   "nginx:alpine",
						"ImageID": "sha256:1234567890",
						"State":   "running",
						"Status":  "Up 2 hours",
						"Created": 1700000000,
						"Ports": []map[string]any{
							{
								"IP":          "0.0.0.0",
								"PrivatePort": 80,
								"PublicPort":  8080,
								"Type":        "tcp",
							},
						},
						"Mounts": []map[string]any{
							{
								"Type":        "bind",
								"Source":      "/etc/nginx",
								"Destination": "/etc/nginx",
								"Mode":        "ro",
								"RW":          false,
							},
						},
					},
				})
				return
			}
			http.NotFound(w, r)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	rfs := fs.NewRootedFS(root)
	sensor := New(rfs)

	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(obs.Items) != 1 {
		t.Fatalf("expected 1 container item, got %d", len(obs.Items))
	}

	info, ok := obs.Items[0].Data.(ContainerInfo)
	if !ok {
		t.Fatalf("unexpected data type: %T", obs.Items[0].Data)
	}

	if info.Image != "nginx:alpine" || info.Runtime != "docker" {
		t.Errorf("container info mismatch: %+v", info)
	}
	if len(info.Ports) != 1 || info.Ports[0].PublicPort != 8080 {
		t.Errorf("ports mismatch: %+v", info.Ports)
	}
}
