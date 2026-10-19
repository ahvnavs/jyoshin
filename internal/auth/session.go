// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/rbac"
)

// Session holds authenticated state for browser cookie sessions.
type Session struct {
	ID        string       `json:"id"`
	CSRFToken string       `json:"csrf_token"`
	Subject   rbac.Subject `json:"subject"`
	CreatedAt time.Time    `json:"created_at"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// SessionManager enforces HttpOnly, SameSite=Strict cookies, CSRF protection,
// short session lifetimes, and concurrent session limits.
type SessionManager struct {
	mu           sync.RWMutex
	sessions     map[string]*Session
	userSessions map[string][]string // user ID -> session IDs
	sessionTTL   time.Duration
	maxPerUser   int
}

// NewSessionManager creates a browser session controller.
func NewSessionManager(ttl time.Duration, maxPerUser int) *SessionManager {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if maxPerUser <= 0 {
		maxPerUser = 5
	}
	return &SessionManager{
		sessions:     make(map[string]*Session),
		userSessions: make(map[string][]string),
		sessionTTL:   ttl,
		maxPerUser:   maxPerUser,
	}
}

// CreateSession generates a new session and returns its ID and CSRF token.
func (sm *SessionManager) CreateSession(sub rbac.Subject) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 1. Enforce concurrent session limit per user
	existing := sm.userSessions[sub.ID]
	if len(existing) >= sm.maxPerUser {
		// Evict oldest session
		oldest := existing[0]
		delete(sm.sessions, oldest)
		sm.userSessions[sub.ID] = existing[1:]
	}

	// 2. Generate random Session ID and CSRF Token
	sidBytes := make([]byte, 32)
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(sidBytes); err != nil {
		return nil, err
	}
	if _, err := rand.Read(csrfBytes); err != nil {
		return nil, err
	}

	sid := hex.EncodeToString(sidBytes)
	csrfToken := hex.EncodeToString(csrfBytes)
	now := time.Now().UTC()

	sess := &Session{
		ID:        sid,
		CSRFToken: csrfToken,
		Subject:   sub,
		CreatedAt: now,
		ExpiresAt: now.Add(sm.sessionTTL),
	}

	sm.sessions[sid] = sess
	sm.userSessions[sub.ID] = append(sm.userSessions[sub.ID], sid)
	return sess, nil
}

// GetSession retrieves and validates an unexpired session.
func (sm *SessionManager) GetSession(sid string, now time.Time) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sess, ok := sm.sessions[sid]
	if !ok {
		return nil, false
	}
	if now.After(sess.ExpiresAt) {
		return nil, false
	}
	return sess, true
}

// ValidateCSRF verifies the request CSRF token against the session using constant-time comparison.
func (sm *SessionManager) ValidateCSRF(sess *Session, candidate string) bool {
	if sess == nil || candidate == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sess.CSRFToken), []byte(candidate)) == 1
}

// DestroySession revokes a session ID.
func (sm *SessionManager) DestroySession(sid string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sess, ok := sm.sessions[sid]; ok {
		delete(sm.sessions, sid)
		// Clean up from user index
		userSess := sm.userSessions[sess.Subject.ID]
		var updated []string
		for _, s := range userSess {
			if s != sid {
				updated = append(updated, s)
			}
		}
		sm.userSessions[sess.Subject.ID] = updated
	}
}

// SetSessionCookie sets a secure, HttpOnly, SameSite=Strict cookie on the response.
func SetSessionCookie(w http.ResponseWriter, sid string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "kazeshini_session",
		Value:    sid,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie clears the browser session cookie.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "kazeshini_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}
