package garbled_pool

import (
	"io/ioutil"
	"log"
	"notary/garbler"
	"notary/meta"
	u "notary/utils"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// gc describes a garbled circuit file
// id is the name of the file
// keyIdx is the index of a key in g.keys used to encrypt this gc
type gc struct {
	id     string
	keyIdx int
}

// Blob is what is returned when gc is read from disk
type Blob struct {
	Il *[]byte
	// we dont return bytes of tt and dt because we gonna be streaming the file
	// directly into the HTTP response to save memory
	TtFile *os.File
	DtFile *os.File
}

type GarbledPool struct {
	// gPDirPath is full path to the garbled pool dir
	gPDirPath string
	// AES-GCM keys to encrypt/authenticate circuits' labels.
	// We need to encrypt them in case we want to store them outside the enclave.
	// When the encryption key changes, older keys are kept because we still
	// have labels on disk encrypted with old keys.
	// monitor() sets old keys which are not used anymore to nil, thus releasing
	// the memory.
	keys [][]byte
	// key is the current key in use. It is always keys[len(keys)-1]
	key []byte
	// encryptedSoFar show how many bytes were encrypted using key
	// NIST recommends re-keying after 64GB
	encryptedSoFar int
	// we change key after rekeyAfter bytes were encrypted
	rekeyAfter int
	// pool contains metadata of all circuits. key is circuit number.
	pool map[string][]gc
	// poolSize is how many concurrent TLSNotary sessions we want to support
	// the server will maintain a pool of garbled circuits depending on this value
	// the amount of c5 circuits will be poolSize*100 because on average one
	// session needs that many garbled c5 circuits
	poolSize int
	// Circuits's count starts from 1
	Circuits []*meta.Circuit
	grb      garbler.Garbler
	// noSandbox is set to true when not running in a sandboxed environment
	noSandbox bool
	sync.Mutex
}

func (g *GarbledPool) Init(noSandbox bool) {
	g.noSandbox = noSandbox
	g.encryptedSoFar = 0
	g.rekeyAfter = 1024 * 1024 * 1024 * 64 // 64GB
	g.poolSize = 1
	g.pool = make(map[string][]gc, 7)
	for _, v := range []string{"1", "2", "3", "4", "5", "6", "7"} {
		g.pool[v] = []gc{}
	}
	g.Circuits = make([]*meta.Circuit, 8)
	for _, idx := range []int{1, 2, 3, 4, 5, 6, 7} {
		g.Circuits[idx] = g.parseCircuit(idx)
		g.Circuits[idx].OutputsSizes = meta.GetOutputSizes(idx)
	}
	curDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	g.gPDirPath = filepath.Join(filepath.Dir(curDir), "garbledPool")
	if !g.noSandbox {
		// running in an enclave, need to encrypt input labels
		g.key = u.GetRandom(16)
	}
	g.keys = append(g.keys, g.key)

	if _, err = os.Stat(g.gPDirPath); os.IsNotExist(err) {
		// the dir does not exist, create
		err = os.Mkdir(g.gPDirPath, 0755)
		if err != nil {
			panic(err)
		}
		for _, idx := range []string{"1", "2", "3", "4", "5", "6", "7"} {
			err = os.Mkdir(filepath.Join(g.gPDirPath, "c"+idx), 0755)
			if err != nil {
				panic(err)
			}
		}
	} else {
		// the dir already exists
		if !g.noSandbox {
			panic("Error. Garbled pool must not exist.")
		} else {
			g.loadPoolFromDisk()
		}
	}
	go g.monitor()
}

// returns 1 garbling of each circuit and c5Count garblings for circuit 5
func (g *GarbledPool) GetBlobs(c6Count int) []Blob {
	if c6Count > 1026 {
		panic("c6Count > 1026")
	}
	var allBlobs []Blob

	// fetch blobs
	for i := 1; i < len(g.Circuits); i++ {
		iStr := strconv.Itoa(i)
		var count int
		if i == 6 {
			count = c6Count
		} else {
			count = 1
		}
		if len(g.pool[iStr]) < count {
			// give monitorPool some time to fill up the pool, then repeat
			log.Println("pool is not ready, sleeping", iStr)
			time.Sleep(time.Second)
			i = i - 1
			continue
		}
		for j := 0; j < count; j++ {
			g.Lock()
			gc := g.pool[iStr][0]
			g.pool[iStr] = g.pool[iStr][1:]
			g.Unlock()
			blob := g.fetchBlob(iStr, gc)
			allBlobs = append(allBlobs, blob)
		}
	}
	return allBlobs
}

func (g *GarbledPool) loadPoolFromDisk() {
	for _, idx := range []string{"1", "2", "3", "4", "5", "6", "7"} {
		files, err := ioutil.ReadDir(filepath.Join(g.gPDirPath, "c"+idx))
		if err != nil {
			panic(err)
		}
		var gcs []gc
		for _, file := range files {
			if strings.HasSuffix(file.Name(), "_il") {
				nameNoSuffix := strings.Split(file.Name(), "_")[0]
				gcs = append(gcs, gc{id: nameNoSuffix, keyIdx: 0})
			}
		}
		g.pool[idx] = gcs
		log.Println("loaded ", len(g.pool[idx]), " garbled circuits for circuit ", idx)
	}
}

// monitor replenishes the garbled pool when needed
// and re-keys the encryption key
func (g *GarbledPool) monitor() {
	loopCount := 0
	for {
		loopCount += 1
		// check every 60sec if stale keys are present and free memory
		if loopCount%60 == 0 {
			g.Lock()
			for i := 0; i < len(g.keys); i++ {
				if g.keys[i] != nil {
					found := false
					// check if index i is in use by any gc of the pool
					for _, gcs := range g.pool {
						for _, v := range gcs {
							if v.keyIdx == i {
								found = true
							}
						}
					}
					if !found {
						g.keys[i] = nil
					}
				}
			}
			g.Unlock()
		}
		// check if encryption key needs to be renewed
		if g.encryptedSoFar > g.rekeyAfter {
			g.key = u.GetRandom(16)
			g.keys = append(g.keys, g.key)
			g.encryptedSoFar = 0
		}
		// check if gc pool needs to be replenished
		diff := 0
		var k string
		var v []gc
		for k, v = range g.pool {
			if k != "6" {
				if len(v) >= g.poolSize {
					continue
				} else {
					diff = g.poolSize - len(v)
					break
				}
			} else {
				// for circuit 6 we need at least 1026 garblings for a max possible
				// TLS record size of 16KB
				max := u.Max(g.poolSize*100, 1026)
				if len(v) >= max {
					continue
				} else {
					diff = max - len(v)
					break
				}
			}
		}
		// golang doesnt allow to modify map while iterating it
		// that's why we broke the iteration and got here
		if diff > 0 {
			// need to replenish the pool
			for i := 0; i < diff; i++ {
				kInt, _ := strconv.Atoi(k)
				il, tt, dt := g.grb.Garble(g.Circuits[kInt])
				randName := u.RandString()
				g.saveBlob(filepath.Join(g.gPDirPath, "c"+k, randName), il, tt, dt)
				g.Lock()
				g.pool[k] = append(g.pool[k], gc{id: randName, keyIdx: len(g.keys) - 1})
				g.Unlock()
			}
			// don't sleep because we may have other circuits which are waiting
			// to be replenished
			continue
		}
		time.Sleep(time.Second)
	}
}

func (g *GarbledPool) saveBlob(path string, il *[]byte, tt *[]byte, dt *[]byte) {
	var ilToWrite *[]byte
	// we only encrypt input labels
	if !g.noSandbox {
		ilEnc := u.AESGCMencrypt(g.key, *il)
		ilToWrite = &ilEnc
	} else {
		ilToWrite = il
	}
	err := os.WriteFile(path+"_il", *ilToWrite, 0644)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(path+"_tt", *tt, 0644)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(path+"_dt", *dt, 0644)
	if err != nil {
		panic(err)
	}
}

// fetches the blob from disk and deletes it
func (g *GarbledPool) fetchBlob(circuitNo string, c gc) Blob {
	fullPath := filepath.Join(g.gPDirPath, "c"+circuitNo, c.id)
	il, err := os.ReadFile(fullPath + "_il")
	if err != nil {
		panic(err)
	}
	err = os.Remove(fullPath + "_il")
	if err != nil {
		panic(err)
	}
	// only the file handle of truth tables and decoding tables is returned,
	// so that the file could be streamed (avoiding a full copy into memory)
	// The session which receives this handle will be responsible for
	// deleting the file
	ttFile, err3 := os.Open(fullPath + "_tt")
	if err3 != nil {
		panic(err3)
	}
	dtFile, err4 := os.Open(fullPath + "_dt")
	if err4 != nil {
		panic(err4)
	}
	var ilToReturn = &il
	if !g.noSandbox {
		// decrypt data from disk when in a sandbox
		ilDec := u.AESGCMdecrypt(g.keys[c.keyIdx], il)
		ilToReturn = &ilDec
	}
	return Blob{ilToReturn, ttFile, dtFile}
}

// Convert the circuits from the "Bristol fashion" format into a compact
// binary representation which can be loaded into RAM and processed gate-by-gate
func (g *GarbledPool) parseCircuit(cNo_ int) *meta.Circuit {
	cNo := strconv.Itoa(cNo_)
	curDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	baseDir := filepath.Dir(curDir)
	jiggDir := filepath.Join(baseDir, "circuits")
	cBytes, err := ioutil.ReadFile(filepath.Join(jiggDir, "c"+cNo+".out"))
	if err != nil {
		panic(err)
	}
	text := string(cBytes)
	lines := strings.Split(text, "\n")
	c := meta.Circuit{}
	wireCount, _ := strconv.ParseInt(strings.Split(lines[0], " ")[1], 10, 32)
	gi, _ := strconv.ParseInt(strings.Split(lines[1], " ")[1], 10, 32)
	ei, _ := strconv.ParseInt(strings.Split(lines[1], " ")[2], 10, 32)
	out, _ := strconv.ParseInt(strings.Split(lines[2], " ")[1], 10, 32)

	c.WireCount = int(wireCount)
	c.NotaryInputSize = int(gi)
	c.ClientInputSize = int(ei)
	c.OutputSize = int(out)

	gates := make([]meta.Gate, len(lines)-3)
	andGateCount := 0
	opBytes := map[string]byte{"XOR": 0, "AND": 1, "INV": 2}

	for i, line := range lines[3:] {
		items := strings.Split(line, " ")
		var g meta.Gate
		g.Operation = opBytes[items[len(items)-1]]
		g.Id = uint32(i)
		if g.Operation == 0 || g.Operation == 1 {
			inp1, _ := strconv.ParseInt(items[2], 10, 32)
			inp2, _ := strconv.ParseInt(items[3], 10, 32)
			out, _ := strconv.ParseInt(items[4], 10, 32)
			g.InputWires = []uint32{uint32(inp1), uint32(inp2)}
			g.OutputWire = uint32(out)
			if g.Operation == 1 {
				andGateCount += 1
			}
		} else { // INV gate
			inp1, _ := strconv.ParseInt(items[2], 10, 32)
			out, _ := strconv.ParseInt(items[3], 10, 32)
			g.InputWires = []uint32{uint32(inp1)}
			g.OutputWire = uint32(out)
		}
		gates[i] = g
	}
	c.Gates = gates
	c.AndGateCount = int(andGateCount)
	return &c
}
