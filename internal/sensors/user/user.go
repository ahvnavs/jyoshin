// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package user

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors"
)

// UserData holds information about a local system user.
type UserData struct {
	Username       string       `json:"username"`
	UID            int          `json:"uid"`
	GID            int          `json:"gid"`
	HomeDir        string       `json:"home_dir"`
	Shell          string       `json:"shell"`
	Groups         []string     `json:"groups"`
	HasSudo        bool         `json:"has_sudo"`
	AuthorizedKeys []SSHKeyMeta `json:"authorized_keys,omitempty"` // Metadata ONLY - NEVER key material!
}

// SSHKeyMeta holds metadata about an SSH public key (strictly metadata, NEVER secret or public key bytes).
type SSHKeyMeta struct {
	KeyType  string `json:"key_type"`          // e.g. "ssh-ed25519", "ssh-rsa"
	Comment  string `json:"comment,omitempty"` // e.g. "admin@workstation"
	AgeDays  int    `json:"age_days"`          // File modification age in days
	FilePath string `json:"file_path"`         // Path to authorized_keys
}

// Sensor collects user, group, sudoers, and SSH metadata.
type Sensor struct {
	rootDir string
}

// NewSensor creates a new user sensor rooted at rootDir.
func NewSensor(rootDir string) *Sensor {
	if rootDir == "" {
		rootDir = "/"
	}
	return &Sensor{rootDir: rootDir}
}

func (s *Sensor) Name() string {
	return "user"
}

func (s *Sensor) Interval() time.Duration {
	return 300 * time.Second
}

func (s *Sensor) Collect(ctx context.Context) (sensors.Observation, error) {
	start := time.Now()
	obs := sensors.Observation{
		SensorName: s.Name(),
		Timestamp:  start,
		Status:     sensors.StatusSuccess,
	}

	passwdPath := filepath.Join(s.rootDir, "etc", "passwd")
	passwdFile, err := os.Open(passwdPath)
	if err != nil {
		obs.Status = sensors.StatusUnknown
		obs.Reason = fmt.Sprintf("cannot read %s: %v", passwdPath, err)
		obs.Duration = time.Since(start)
		return obs, nil
	}
	defer func() {
		_ = passwdFile.Close()
	}()

	// Parse /etc/group
	userGroups := make(map[string][]string)
	s.parseGroups(userGroups)

	// Check sudoers presence / group sudo/wheel
	sudoUsers := s.findSudoersUsers()

	scanner := bufio.NewScanner(passwdFile)
	var items []sensors.Item

	for scanner.Scan() {
		if ctx.Err() != nil {
			obs.Status = sensors.StatusError
			obs.Reason = ctx.Err().Error()
			obs.Duration = time.Since(start)
			return obs, ctx.Err()
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		homeDir := parts[5]
		shell := parts[6]

		groups := userGroups[username]
		hasSudo := sudoUsers[username] || s.isSudoGroupMember(groups)

		// Scan ~/.ssh/authorized_keys metadata only
		authKeys := s.scanAuthorizedKeys(homeDir)

		u := UserData{
			Username:       username,
			UID:            uid,
			GID:            gid,
			HomeDir:        homeDir,
			Shell:          shell,
			Groups:         groups,
			HasSudo:        hasSudo,
			AuthorizedKeys: authKeys,
		}

		items = append(items, sensors.Item{
			ID:   fmt.Sprintf("user:%s", username),
			Type: "user",
			Data: u,
			Evidence: []graph.Evidence{
				{
					Source:    passwdPath,
					Collector: "user",
					Details:   fmt.Sprintf("User %s (uid %d) defined in /etc/passwd", username, uid),
					Timestamp: start,
					Certainty: graph.CertaintyObserved,
				},
			},
			Certainty: graph.CertaintyObserved,
		})
	}

	obs.Items = items
	obs.TotalSeen = len(items)
	obs.Duration = time.Since(start)
	return obs, nil
}

func (s *Sensor) parseGroups(userGroups map[string][]string) {
	groupPath := filepath.Join(s.rootDir, "etc", "group")
	f, err := os.Open(groupPath)
	if err != nil {
		return
	}
	defer func() {
		_ = f.Close()
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		grpName := parts[0]
		members := strings.Split(parts[3], ",")
		for _, m := range members {
			m = strings.TrimSpace(m)
			if m != "" {
				userGroups[m] = append(userGroups[m], grpName)
			}
		}
	}
}

func (s *Sensor) isSudoGroupMember(groups []string) bool {
	for _, g := range groups {
		if g == "sudo" || g == "wheel" || g == "admin" {
			return true
		}
	}
	return false
}

func (s *Sensor) findSudoersUsers() map[string]bool {
	sudoUsers := make(map[string]bool)
	sudoersPath := filepath.Join(s.rootDir, "etc", "sudoers")
	s.scanSudoersFile(sudoersPath, sudoUsers)

	sudoersD := filepath.Join(s.rootDir, "etc", "sudoers.d")
	entries, err := os.ReadDir(sudoersD)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") && !strings.HasSuffix(e.Name(), "~") {
				s.scanSudoersFile(filepath.Join(sudoersD, e.Name()), sudoUsers)
			}
		}
	}
	return sudoUsers
}

func (s *Sensor) scanSudoersFile(path string, sudoUsers map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && !strings.HasPrefix(fields[0], "%") && !strings.HasPrefix(fields[0], "Defaults") {
			sudoUsers[fields[0]] = true
		}
	}
}

// scanAuthorizedKeys extracts metadata ONLY from ~/.ssh/authorized_keys.
// NEVER returns or stores key material.
func (s *Sensor) scanAuthorizedKeys(homeDir string) []SSHKeyMeta {
	if homeDir == "" || homeDir == "/dev/null" {
		return nil
	}

	relHome := strings.TrimPrefix(homeDir, "/")
	sshFile := filepath.Join(s.rootDir, relHome, ".ssh", "authorized_keys")

	fi, err := os.Stat(sshFile)
	if err != nil {
		return nil
	}

	ageDays := int(time.Since(fi.ModTime()).Hours() / 24)
	if ageDays < 0 {
		ageDays = 0
	}

	f, err := os.Open(sshFile)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var metas []SSHKeyMeta
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		keyType := ""
		comment := ""

		// Format: [options] <key-type> <base64-key> [comment]
		if strings.HasPrefix(fields[0], "ssh-") || strings.HasPrefix(fields[0], "ecdsa-") {
			keyType = fields[0]
			if len(fields) >= 3 {
				comment = strings.Join(fields[2:], " ")
			}
		} else if len(fields) >= 3 && (strings.HasPrefix(fields[1], "ssh-") || strings.HasPrefix(fields[1], "ecdsa-")) {
			// Options preceded key type
			keyType = fields[1]
			if len(fields) >= 4 {
				comment = strings.Join(fields[3:], " ")
			}
		} else {
			continue
		}

		metas = append(metas, SSHKeyMeta{
			KeyType:  keyType,
			Comment:  comment,
			AgeDays:  ageDays,
			FilePath: filepath.Join(homeDir, ".ssh", "authorized_keys"),
		})
	}

	return metas
}
