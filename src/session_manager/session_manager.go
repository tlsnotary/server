package session_manager

import (
	"log"
	"notary/session"
	"os"
	"sync"
	"time"
)

type method func([]byte) []byte

// smItem is stored internally by SessionManager
type smItem struct {
	session *session.Session
	// methodLookup is a map used to look up the session's method by its name
	methodLookup map[string]method
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
	methodLookup := map[string]method{
		"init1": s.Init1,
		"init2": s.Init2,

		"getUploadProgress": s.GetUploadProgress,

		//  step1 thru step4 deal with Paillier 2PC
		"step1": s.Step1,
		"step2": s.Step2,
		"step3": s.Step3,
		"step4": s.Step4,

		// // c1_step1 thru c1_step1 deal with TLS Handshake
		"c1_step1": s.C1_step1,
		"c1_step2": s.C1_step2,
		"c1_step3": s.C1_step3,
		"c1_step4": s.C1_step4,
		"c1_step5": s.C1_step5,

		// // c2_step1 thru c2_step4 deal with TLS Handshake
		"c2_step1": s.C2_step1,
		"c2_step2": s.C2_step2,
		"c2_step3": s.C2_step3,
		"c2_step4": s.C2_step4,

		// // c3_step1 thru c4_step3 deal with TLS Handshake and also prepare data
		// // needed to send Client Finished
		"c3_step1": s.C3_step1,
		"c3_step2": s.C3_step2,
		"c4_step1": s.C4_step1,
		"c4_step2": s.C4_step2,
		"c4_step3": s.C4_step3,

		// // c5_pre1 thru c5_step3 check Server Finished
		"c5_pre1":  s.C5_pre1,
		"c5_step1": s.C5_step1,
		"c5_step2": s.C5_step2,
		"c5_step3": s.C5_step3,

		// // c6_step1 thru c6_step2 prepare encrypted counter blocks for the
		// // client's request to the webserver
		"c6_step1": s.C6_step1,
		"c6_pre2":  s.C6_pre2,
		"c6_step2": s.C6_step2,

		// // c7_step1 thru c7_step2 prepare the GCTR block needed to compute the MAC
		// // for the client's request
		"c7_step1": s.C7_step1,
		"c7_step2": s.C7_step2,

		// // steps ghash_step1 thru ghash_step3 compute the GHASH output needed to
		// // compute the MAC for the client's request
		"ghash_step1": s.Ghash_step1,
		"ghash_step2": s.Ghash_step2,
		"ghash_step3": s.Ghash_step3,

		"commitHash": s.CommitHash,
	}
	sm.Lock()
	defer sm.Unlock()
	sm.sessions[key] = &smItem{s, methodLookup, now, now}
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

// GetMethod looks up and return Session's method corresponding to the method
// string
func (sm *SessionManager) GetMethod(methodStr string, key string) method {
	val, ok := sm.sessions[key]
	if !ok {
		log.Println("Error: the requested session does not exist ", key)
		panic("Error: the requested session does not exist")
	}
	f, ok2 := val.methodLookup[methodStr]
	if !ok2 {
		log.Println("Error: the requested method does not exist ", key)
		panic("Error: the requested method does not exist")
	}
	return f
}

// removeSession removes the session and associated storage data
func (sm *SessionManager) removeSession(key string) {
	s, ok := sm.sessions[key]
	if !ok {
		log.Println("Cannot remove: session does not exist ", key)
		return
	}
	err := os.RemoveAll(s.session.StorageDir)
	if err != nil {
		log.Println("Error while removing session ", key)
		log.Println(err)
	}
	for _, sliceOfFiles := range s.session.Tt {
		for _, f := range sliceOfFiles {
			err = os.Remove(f.Name())
			if err != nil {
				log.Println("Error while removing session ", key)
				log.Println(err)
			}
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
