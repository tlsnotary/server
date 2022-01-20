package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"

	"net/http"
	_ "net/http/pprof"
	"notary/garbled_pool"
	"notary/key_manager"
	"notary/session"
	"notary/session_manager"

	"time"
)

var sm *session_manager.SessionManager
var gp *garbled_pool.GarbledPool
var km *key_manager.KeyManager

// URLFetcherDoc is the document returned by the deterministic URLFetcher enclave
// https://github.com/tlsnotary/URLFetcher
// It contains AWS HTTP API requests with Amazon's attestation
var URLFetcherDoc []byte

// readBody extracts the HTTP request's body
func readBody(req *http.Request) []byte {
	defer req.Body.Close()
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic("can't read request body")
	}
	return body
}

// writeResponse appends the CORS headers needed to keep the browser happy
// and writes data to the wire
func writeResponse(resp []byte, w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resp)
	log.Println("wrote response of size: ", len(resp))
}

func getURLFetcherDoc(w http.ResponseWriter, req *http.Request) {
	log.Println("in getURLFetcherDoc", req.RemoteAddr)
	writeResponse(URLFetcherDoc, w)
}

// destroyOnPanic will be called on panic(). It will destroy the session which
// caused the panic
func destroyOnPanic(s *session.Session) {
	r := recover()
	if r == nil {
		return // there was no panic
	}
	fmt.Println("caught a panic message: ", r)
	debug.PrintStack()
	s.DestroyChan <- s.Sid
}

func init1(w http.ResponseWriter, req *http.Request) {
	log.Println("in init1", req.RemoteAddr)
	s := sm.AddSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	s.Gp = gp
	// copying data so that it doesn't change from under us if
	// ephemeral key happens to change while this session is running
	km.Lock()
	blob := make([]byte, len(km.Blob))
	copy(blob, km.Blob)
	key := *km.PrivKey
	km.Unlock()
	out := s.Init1(body, blob, key)
	writeResponse(out, w)
}

func init2(w http.ResponseWriter, req *http.Request) {
	log.Println("in init2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.Init2(body)
	writeResponse(out, w)
}

func getBlob(w http.ResponseWriter, req *http.Request) {
	log.Println("in getBlob", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	tt, dt := s.GetBlob(body)
	// send headers first
	writeResponse(nil, w)
	// stream decoding table directly from file
	for _, f := range dt {
		_, err := io.Copy(w, f)
		if err != nil {
			panic("err != nil")
		}
	}
	// stream decoding table directly from file
	for _, f := range tt {
		_, err := io.Copy(w, f)
		if err != nil {
			panic("err != nil")
		}
	}
}

func setBlob(w http.ResponseWriter, req *http.Request) {
	log.Println("in setBlob", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	out := s.SetBlob(req.Body)
	writeResponse(out, w)
}

func getUploadProgress(w http.ResponseWriter, req *http.Request) {
	log.Println("in getUploadProgress", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	out := s.GetUploadProgress()
	writeResponse(out, w)
}

func step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in step1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.Step1(body)
	writeResponse(out, w)
}

func step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in step2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.Step2(body)
	writeResponse(out, w)
}

func step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in step3", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.Step3(body)
	writeResponse(out, w)
}

func step4(w http.ResponseWriter, req *http.Request) {
	log.Println("in step4", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.Step4(body)
	writeResponse(out, w)
}

func c1_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C1_step1(body)
	writeResponse(out, w)
}

func c1_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C1_step2(body)
	writeResponse(out, w)
}

func c1_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step3", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C1_step3(body)
	writeResponse(out, w)
}

func c1_step4(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step4", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C1_step4(body)
	writeResponse(out, w)
}

func c1_step5(w http.ResponseWriter, req *http.Request) {
	log.Println("in c1_step5", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C1_step5(body)
	writeResponse(out, w)
}

func c2_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c2_step1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C2_step1(body)
	writeResponse(out, w)
}

func c2_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c2_step2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C2_step2(body)
	writeResponse(out, w)
}

func c2_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in c2_step3", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C2_step3(body)
	writeResponse(out, w)
}

func c2_step4(w http.ResponseWriter, req *http.Request) {
	log.Println("in c2_step4", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C2_step4(body)
	writeResponse(out, w)
}

func c3_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c3_step1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C3_step1(body)
	writeResponse(out, w)
}

func c3_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c3_step2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C3_step2(body)
	writeResponse(out, w)
}

func c4_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c4_step1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C4_step1(body)
	writeResponse(out, w)
}

func c4_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c4_step2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C4_step2(body)
	writeResponse(out, w)
}

func c4_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in c4_step3", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C4_step3(body)
	writeResponse(out, w)
}

func c5_pre1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c5_pre1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C5_pre1(body)
	writeResponse(out, w)
}

func c5_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c5_step1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C5_step1(body)
	writeResponse(out, w)
}

func c5_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c5_step2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C5_step2(body)
	writeResponse(out, w)
}

func c5_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in c5_step3", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C5_step3(body)
	writeResponse(out, w)
}

func c6_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c6_step1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C6_step1(body)
	writeResponse(out, w)
}

func c6_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c6_step2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C6_step2(body)
	writeResponse(out, w)
}

func c7_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in c7_step1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C7_step1(body)
	writeResponse(out, w)
}

func c7_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in c7_step2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.C7_step2(body)
	writeResponse(out, w)
}

func checkC7Commit(w http.ResponseWriter, req *http.Request) {
	log.Println("in checkC7Commit", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.CheckC7Commit(body)
	writeResponse(out, w)
}

func ghash_step1(w http.ResponseWriter, req *http.Request) {
	log.Println("in ghash_step1", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.Ghash_step1(body)
	writeResponse(out, w)
}

func ghash_step2(w http.ResponseWriter, req *http.Request) {
	log.Println("in ghash_step2", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.Ghash_step2(body)
	writeResponse(out, w)
}

func ghash_step3(w http.ResponseWriter, req *http.Request) {
	log.Println("in ghash_step3", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.Ghash_step3(body)
	writeResponse(out, w)
}

func commitHash(w http.ResponseWriter, req *http.Request) {
	log.Println("in commitHash", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	out := s.CommitHash(body)
	writeResponse(out, w)
	s.DestroyChan <- s.Sid
}

// when notary starts we expect the admin to upload a URLFetcher document
// it can be uploaded e.g. with:
// curl --data-binary '@URLFetcherDoc' 127.0.0.1:10012/setURLFetcherDoc

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

// initially the circuits are in the human-readable c*.casm format; assemble.js
// converts them into a "Bristol fashion" format and write to disk c*.out files
func assembleCircuits() {
	curDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	baseDir := filepath.Dir(curDir)
	circuitsDir := filepath.Join(baseDir, "circuits")
	// if c1.out does not exist, proceed to assemble
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
	// uncomment the below to profile the process's RAM usage
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
	sm = new(session_manager.SessionManager)
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

	http.HandleFunc("/init1", init1)
	http.HandleFunc("/init2", init2)
	http.HandleFunc("/getBlob", getBlob)
	http.HandleFunc("/setBlob", setBlob)
	http.HandleFunc("/getUploadProgress", getUploadProgress)

	// step1 thru step4 deal with Paillier 2PC
	http.HandleFunc("/step1", step1)
	http.HandleFunc("/step2", step2)
	http.HandleFunc("/step3", step3)
	http.HandleFunc("/step4", step4)

	// c1_step1 thru c1_step1 deal with TLS Handshake
	http.HandleFunc("/c1_step1", c1_step1)
	http.HandleFunc("/c1_step2", c1_step2)
	http.HandleFunc("/c1_step3", c1_step3)
	http.HandleFunc("/c1_step4", c1_step4)
	http.HandleFunc("/c1_step5", c1_step5)

	// c2_step1 thru c2_step4 deal with TLS Handshake
	http.HandleFunc("/c2_step1", c2_step1)
	http.HandleFunc("/c2_step2", c2_step2)
	http.HandleFunc("/c2_step3", c2_step3)
	http.HandleFunc("/c2_step4", c2_step4)

	// c3_step1 thru c4_step3 deal with TLS Handshake and also prepare data
	// needed to send Client Finished
	http.HandleFunc("/c3_step1", c3_step1)
	http.HandleFunc("/c3_step2", c3_step2)

	http.HandleFunc("/c4_step1", c4_step1)
	http.HandleFunc("/c4_step2", c4_step2)
	http.HandleFunc("/c4_step3", c4_step3)

	// c5_pre1 thru c5_step3 check Server Finished
	http.HandleFunc("/c5_pre1", c5_pre1)
	http.HandleFunc("/c5_step1", c5_step1)
	http.HandleFunc("/c5_step2", c5_step2)
	http.HandleFunc("/c5_step3", c5_step3)

	// c6_step1 thru c6_step2 prepare encrypted counter blocks for the
	// client's request to the webserver
	http.HandleFunc("/c6_step1", c6_step1)
	http.HandleFunc("/c6_step2", c6_step2)

	// c7_step1 thru c7_step2 prepare the GCTR block needed to compute the MAC
	// for the client's request
	http.HandleFunc("/c7_step1", c7_step1)
	http.HandleFunc("/c7_step2", c7_step2)
	http.HandleFunc("/checkC7Commit", checkC7Commit)

	// steps ghash_step1 thru ghash_step3 compute the GHASH output needed to
	// compute the MAC for the client's request
	http.HandleFunc("/ghash_step1", ghash_step1)
	http.HandleFunc("/ghash_step2", ghash_step2)
	http.HandleFunc("/ghash_step3", ghash_step3)

	http.HandleFunc("/commitHash", commitHash)

	http.ListenAndServe("0.0.0.0:10011", nil)
}
