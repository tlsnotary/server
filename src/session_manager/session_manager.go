package session_manager

import (
	"log"
	"notary/session"
	"os"
	"sync"
	"time"
)

// smItem is stored internally by SessionManager
type smItem struct {
	session      *session.Session
	lastSeen     int64 // timestamp of last activity
	creationTime int64 // timestamp
}

// SessionManager manages TLSNotary sessions from multiple users. When a user
// sends a request, SessionManager extracts the unique id of the user from the
// request, and calls the matching session.
type SessionManager struct {
	// string looks like 123.123.44.44:23409
	sessions    map[string]*smItem
	destroyChan chan string
	sync.Mutex
}

func (sm *SessionManager) Init() {
	sm.sessions = make(map[string]*smItem)
	go sm.monitorSessions()
	sm.destroyChan = make(chan string)
	go sm.monitorDestroyChan()
}

// addSession creates a new session and sets its creation time
func (sm *SessionManager) AddSession(key string) *session.Session {
	if _, ok := sm.sessions[key]; ok {
		log.Println("Error: session already exists ", key)
	}
	s := new(session.Session)
	s.Sid = key
	s.DestroyChan = sm.destroyChan
	now := int64(time.Now().UnixNano() / 1e9)
	sm.Lock()
	defer sm.Unlock()
	sm.sessions[key] = &smItem{s, now, now}
	return s
}

// get an already-existing session associated with the key
// and update the last-seen time
func (sm *SessionManager) GetSession(key string) *session.Session {
	val, ok := sm.sessions[key]
	if !ok {
		log.Println("Error: the requested session does not exist ", key)
		return nil
	}
	val.lastSeen = int64(time.Now().UnixNano() / 1e9)
	return val.session
}

// removeSession removes the session and associated storage data
func (sm *SessionManager) removeSession(key string) {
	s, ok := sm.sessions[key]
	if !ok {
		log.Println("Cannot remove: session does not exist ", key)
	}
	err := os.RemoveAll(s.session.StorageDir)
	if err != nil {
		log.Println("Error while removing session ", key)
		log.Println(err)
	}
	for _, f := range s.session.Tt {
		err = os.Remove(f.Name())
		if err != nil {
			log.Println("Error while removing session ", key)
			log.Println(err)
		}
	}
	for _, f := range s.session.Dt {
		err = os.Remove(f.Name())
		if err != nil {
			log.Println("Error while removing session ", key)
			log.Println(err)
		}
	}
	sm.Lock()
	defer sm.Unlock()
	delete(sm.sessions, key)
}

// monitorSessions removes sessions which have been inactive or which have
// been too long-running
func (sm *SessionManager) monitorSessions() {
	for {
		time.Sleep(time.Second)
		now := int64(time.Now().UnixNano() / 1e9)
		for k, v := range sm.sessions {
			if now-v.lastSeen > 120 || now-v.creationTime > 300 {
				log.Println("will remove stale session ", k)
				sm.removeSession(k)
			}
		}
	}
}

// monitorDestroyChan waits on a chan for a signal from a session to destroy it
func (sm *SessionManager) monitorDestroyChan() {
	for {
		sid := <-sm.destroyChan
		log.Println("monitorDestroyChan will destroy sid: ", sid)
		sm.removeSession(sid)
	}
}
