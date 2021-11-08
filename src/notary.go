// ./notary & sleep 5 && curl --data-binary '@URLFetcherDoc' 127.0.0.1:8091/setURLFetcherDoc && fg

package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"net/http"
	_ "net/http/pprof"
	"notary/garbled_pool"
	"notary/key_manager"
	"notary/session"

	"time"
)

var sm *SessionManager
var gp *garbled_pool.GarbledPool
var km *key_manager.KeyManager

// URLFetcherDoc is the document returned by the deterministic URLFetcher enclave
// https://github.com/tlsnotary/URLFetcher
// It contains AWS HTTP API requests with Amazon's attestation
var URLFetcherDoc []byte

type smItem struct {
	session      *session.Session
	lastSeen     int64 // timestamp of last activity
	creationTime int64 // timestamp
}

type SessionManager struct {
	// string looks like 123.123.44.44:23409
	sessions map[string]*smItem
	sync.Mutex
}

func (sm *SessionManager) Init() {
	sm.sessions = make(map[string]*smItem)
	go sm.monitorSessions()
}

func (sm *SessionManager) addSession(key string) *session.Session {
	if _, ok := sm.sessions[key]; ok {
		log.Println(key)
		panic("session already exists")
	}
	s := new(session.Session)
	now := int64(time.Now().UnixNano() / 1e9)
	sm.Lock()
	defer sm.Unlock()
	sm.sessions[key] = &smItem{s, now, now}
	return s
}

// get an already-existing session associated with the key
// and update the last-seen time
func (sm *SessionManager) getSession(key string) *session.Session {
	val, ok := sm.sessions[key]
	if !ok {
		log.Println(key)
		panic("session does not exist")
	}
	val.lastSeen = int64(time.Now().UnixNano() / 1e9)
	return val.session
}

func (sm *SessionManager) removeSession(key string) {
	s, ok := sm.sessions[key]
	if !ok {
		log.Println(key)
		panic("cannot remove: session does not exist")
	}
	err := os.RemoveAll(s.session.StorageDir)
	if err != nil {
		panic(err)
	}
	sm.Lock()
	defer sm.Unlock()
	delete(sm.sessions, key)
}

// remove sessions which have been inactive for 60 sec
func (sm *SessionManager) monitorSessions() {
	for {
		time.Sleep(time.Second)
		now := int64(time.Now().UnixNano() / 1e9)
		for k, v := range sm.sessions {
			if now-v.lastSeen > 120 || now-v.creationTime > 300 {
				log.Println("deleting session from monitorSessions")
				sm.removeSession(k)
			}
		}
	}
}

// read request body
func readBody(req *http.Request) []byte {
	defer req.Body.Close()
	log.Println("begin ReadAll")
	body, err := ioutil.ReadAll(req.Body)
	log.Println("finished ReadAll ", len(body))
	if err != nil {
		panic("can't read request body")
	}
	return body
}

func writeResponse(resp []byte, w http.ResponseWriter) {
	//w.Header().Set("Connection", "close")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resp)
}

func getURLFetcherDoc(w http.ResponseWriter, req *http.Request) {
	log.Println("in getURLFetcherDoc", req.RemoteAddr)
	writeResponse(URLFetcherDoc, w)
}

func ot_AllB(w http.ResponseWriter, req *http.Request) {
	log.Println("in ot_AllB", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).OT_AllB(body)
	writeResponse(out, w)
}

func ot_encLabelsForEval(w http.ResponseWriter, req *http.Request) {
	log.Println("in ot_encLabelsForEval", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).OT_encLabelsForEval(body)
	writeResponse(out, w)
}

func step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in step1", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Step1(body)
	writeResponse(out, w)
}

func step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in step2", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Step2(body)
	writeResponse(out, w)
}

func step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in step3", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Step3(body)
	writeResponse(out, w)
}

func step4(w http.ResponseWriter, req *http.Request) {
	log.Println("in step4", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Step4(body)
	writeResponse(out, w)
}

func preInit(w http.ResponseWriter, req *http.Request) {
	log.Println("in preInit", req.RemoteAddr)
	body := readBody(req)
	s := sm.addSession(string(req.URL.RawQuery))
	// copying data so that it doesn't change from under us if
	// ephemeral key happens to change while this session is running
	km.Lock()
	blob := make([]byte, len(km.Blob))
	copy(blob, km.Blob)
	key := *km.PrivKey
	km.Unlock()
	out := s.PreInit(body, blob, key)
	writeResponse(out, w)
}

func initNow(w http.ResponseWriter, req *http.Request) {
	log.Println("in initNow", req.RemoteAddr)
	out := sm.getSession(string(req.URL.RawQuery)).Init(gp)
	writeResponse(out, w)
}

func getBlobChunk(w http.ResponseWriter, req *http.Request) {
	log.Println("in getBlobChunk", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).GetBlobChunk(body)
	writeResponse(out, w)
}

func setBlobChunk(w http.ResponseWriter, req *http.Request) {
	log.Println("in setBlobChunk", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).SetBlobChunk(body)
	writeResponse(out, w)
}

func c1_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step1", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C1_step1(body)
	writeResponse(out, w)
}

func c1_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step2", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C1_step2(body)
	writeResponse(out, w)
}

func c1_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step3", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C1_step3(body)
	writeResponse(out, w)
}

func c1_step4(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step4", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C1_step4(body)
	writeResponse(out, w)
}

func c1_step5(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step5", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C1_step5(body)
	writeResponse(out, w)
}

func c2_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c2_step1", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C2_step1(body)
	writeResponse(out, w)
}

func c2_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c2_step2", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C2_step2(body)
	writeResponse(out, w)
}

func c2_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in c2_step3", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C2_step3(body)
	writeResponse(out, w)
}

func c2_step4(w http.ResponseWriter, req *http.Request) {
	log.Println("in c2_step4", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C2_step4(body)
	writeResponse(out, w)
}

func c3_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c3_step1", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C3_step1(body)
	writeResponse(out, w)
}

func c3_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c3_step2", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C3_step2(body)
	writeResponse(out, w)
}

func c3_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in c3_step3", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C3_step3(body)
	writeResponse(out, w)
}

func c4_pre1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c4_pre1", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C4_pre1(body)
	writeResponse(out, w)
}

func c4_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c4_step1", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C4_step1(body)
	writeResponse(out, w)
}

func c4_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c4_step2", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C4_step2(body)
	writeResponse(out, w)
}

func c4_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in c4_step3", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C4_step3(body)
	writeResponse(out, w)
}

func c5_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c5_step1", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C5_step1(body)
	writeResponse(out, w)
}

func c5_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c5_step2", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C5_step2(body)
	writeResponse(out, w)
}

func c6_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c6_step1", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C6_step1(body)
	writeResponse(out, w)
}

func c6_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c6_step2", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).C6_step2(body)
	writeResponse(out, w)
}

func checkC6Commit(w http.ResponseWriter, req *http.Request) {
	log.Println("in checkC6Commit", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).CheckC6Commit(body)
	writeResponse(out, w)
}

func ghash_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in ghash_step1", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Ghash_step1(body)
	writeResponse(out, w)
}

func ghash_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in ghash_step2", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Ghash_step2(body)
	writeResponse(out, w)
}

func ghash_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in ghash_step3", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Ghash_step3(body)
	writeResponse(out, w)
}

func ghash_step4(w http.ResponseWriter, req *http.Request) {
	log.Println("in ghash_step4", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Ghash_step4(body)
	writeResponse(out, w)
}

func ghash_step5(w http.ResponseWriter, req *http.Request) {
	log.Println("in ghash_step5", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Ghash_step5(body)
	writeResponse(out, w)
}

func ghash_step6(w http.ResponseWriter, req *http.Request) {
	log.Println("in ghash_step6", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).Ghash_step6(body)
	writeResponse(out, w)
}

func commitHash(w http.ResponseWriter, req *http.Request) {
	log.Println("in commitHash", req.RemoteAddr)
	body := readBody(req)
	out := sm.getSession(string(req.URL.RawQuery)).CommitHash(body)
	writeResponse(out, w)
	sm.removeSession(string(req.URL.RawQuery))
}

// when notary starts we expect the admin to upload a URLFetcher document
func awaitURLFetcherDoc() {
	serverMux := http.NewServeMux()
	srv := &http.Server{Addr: ":10012", Handler: serverMux}
	signal := make(chan struct{})
	serverMux.HandleFunc("/setURLFetcherDoc", func(w http.ResponseWriter, req *http.Request) {
		URLFetcherDoc = readBody(req)
		log.Println("got URLFetcher doc", string(URLFetcherDoc[:100]))
		close(signal)
	})
	// start a server and wait for signal from HandleFunc
	go func() {
		srv.ListenAndServe()
	}()
	<-signal
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(ctx)
}

// getPubKey sends notary's public key to the client
// only useful when running as a regular non-sandboxed server
func getPubKey(w http.ResponseWriter, req *http.Request) {
	log.Println("in getPubKey", req.RemoteAddr)
	writeResponse(km.MasterPubKeyPEM, w)
}

func assembleCircuits() {
	curDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	baseDir := filepath.Dir(curDir)
	circuitsDir := filepath.Join(baseDir, "circuits")
	if _, err := os.Stat(filepath.Join(circuitsDir, "c1.out")); os.IsNotExist(err) {
		cmd := exec.Command("node", "assemble.js")
		cmd.Dir = circuitsDir
		log.Println("Assembling circuits. This will take a few seconds...")
		if err := cmd.Run(); err != nil {
			log.Println("Error. Could not run: node assemble.js. Please make sure that node is installed on your system.")
			os.Exit(1)
		}
	}
}

func main() {
	// defer profile.Start(profile.MemProfile).Stop()
	// go func() {
	// 	http.ListenAndServe(":8080", nil)
	// }()
	noSandbox := flag.Bool("no-sandbox", false, "Must be set when not running in a sandboxed environment.")
	flag.Parse()
	log.Println("noSandbox", *noSandbox)

	km = new(key_manager.KeyManager)
	km.Init()
	assembleCircuits()
	sm = new(SessionManager)
	sm.Init()
	gp = new(garbled_pool.GarbledPool)
	gp.Init(*noSandbox)

	if !*noSandbox {
		http.HandleFunc("/getURLFetcherDoc", getURLFetcherDoc)
		go awaitURLFetcherDoc()
	}
	// although getPubKey is only used in noSandbox cases, it still
	// can be useful when debugging sandboxed notary
	http.HandleFunc("/getPubKey", getPubKey)

	http.HandleFunc("/preInit", preInit)
	http.HandleFunc("/init", initNow)
	http.HandleFunc("/getBlobChunk", getBlobChunk)
	http.HandleFunc("/setBlobChunk", setBlobChunk)

	http.HandleFunc("/ot_AllB", ot_AllB)
	http.HandleFunc("/ot_encLabelsForEval", ot_encLabelsForEval)

	http.HandleFunc("/step1", step1)
	http.HandleFunc("/step2", step2)
	http.HandleFunc("/step3", step3)
	http.HandleFunc("/step4", step4)

	http.HandleFunc("/c1_step1", c1_step1)
	http.HandleFunc("/c1_step2", c1_step2)
	http.HandleFunc("/c1_step3", c1_step3)
	http.HandleFunc("/c1_step4", c1_step4)
	http.HandleFunc("/c1_step5", c1_step5)

	http.HandleFunc("/c2_step1", c2_step1)
	http.HandleFunc("/c2_step2", c2_step2)
	http.HandleFunc("/c2_step3", c2_step3)
	http.HandleFunc("/c2_step4", c2_step4)

	http.HandleFunc("/c3_step1", c3_step1)
	http.HandleFunc("/c3_step2", c3_step2)
	http.HandleFunc("/c3_step3", c3_step3)

	http.HandleFunc("/c4_pre1", c4_pre1)
	http.HandleFunc("/c4_step1", c4_step1)
	http.HandleFunc("/c4_step2", c4_step2)
	http.HandleFunc("/c4_step3", c4_step3)

	http.HandleFunc("/c5_step1", c5_step1)
	http.HandleFunc("/c5_step2", c5_step2)

	http.HandleFunc("/c6_step1", c6_step1)
	http.HandleFunc("/c6_step2", c6_step2)
	http.HandleFunc("/checkC6Commit", checkC6Commit)

	http.HandleFunc("/ghash_step1", ghash_step1)
	http.HandleFunc("/ghash_step2", ghash_step2)
	http.HandleFunc("/ghash_step3", ghash_step3)
	http.HandleFunc("/ghash_step4", ghash_step4)
	http.HandleFunc("/ghash_step5", ghash_step5)
	http.HandleFunc("/ghash_step6", ghash_step6)

	http.HandleFunc("/commitHash", commitHash)

	http.ListenAndServe("0.0.0.0:10011", nil)
}
