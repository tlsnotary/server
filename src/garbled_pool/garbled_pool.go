package garbled_pool

import (
	"encoding/binary"
	"io/ioutil"
	"log"
	"notary/garbler"
	u "notary/utils"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// gc describes a garbled circuit file
// id is the name of the file (for c5 this is the name of the dir)
// keyIdx is the index of a key in g.key used to encrypt the gc
type gc struct {
	id     string
	keyIdx int
}

type GarbledPool struct {
	// gPDirPath is full path to the garbled pool dir
	gPDirPath string
	// AES-GCM keys to encrypt/authenticate garbled circuits
	// we need to encrypt them in case we want to store them outside the enclave
	// when the encryption key changes, older keys are kept because we still
	// have gc on disk encrypted with old keys
	// keysCleanup sets old keys which are not used anymore to nil, thus releasing
	// the memory
	keys [][]byte
	// key is the current key in use. It is always keys[len(keys)-1]
	key []byte
	// encryptedSoFar show how many bytes were encrypted using key
	// NIST recommends re-keying after 64GB
	encryptedSoFar int
	// we change key after rekeyAfter bytes were encrypted
	rekeyAfter int
	// c5 subdirs' names are "50, 100, 150 ..." indicating how many garblings of
	// a circuit there are in the dir
	c5subdirs []string
	// pool contains all non-c5 circuits
	pool map[string][]gc
	// poolc5 is like pool except map's <key> is one of g.c5subdirs and gc.id
	// is a dir containing <key> amount of garblings
	poolc5 map[string][]gc
	// poolSize is how many pre-garblings of each circuit we want to have
	poolSize int
	Circuits []*garbler.Circuit
	grb      garbler.Garbler
	// all circuits, count starts with 1 to avoid confusion
	Cs []garbler.CData
	// noSandbox is set to true when not running in a sandboxed environment
	noSandbox bool
	sync.Mutex
}

func (g *GarbledPool) Init(noSandbox bool) {
	g.noSandbox = noSandbox
	g.encryptedSoFar = 0
	g.rekeyAfter = 1024 * 1024 * 1024 * 64 // 64GB
	g.poolSize = 1
	g.c5subdirs = []string{"50", "100", "150", "200", "300"}
	g.pool = make(map[string][]gc, 5)
	for _, v := range []string{"1", "2", "3", "4", "6"} {
		g.pool[v] = []gc{}
	}
	g.poolc5 = make(map[string][]gc, len(g.c5subdirs))
	for _, v := range g.c5subdirs {
		g.poolc5[v] = []gc{}
	}
	g.Circuits = make([]*garbler.Circuit, 7)
	for _, idx := range []int{1, 2, 3, 4, 5, 6} {
		g.Circuits[idx] = g.grb.ParseCircuit(idx)
	}
	g.Cs = make([]garbler.CData, 7)
	g.Cs[1].Init(512, 256, 512, 256, 512)
	g.Cs[2].Init(512, 256, 640, 384, 512)
	g.Cs[3].Init(832, 256, 1568, 768, 800)
	g.Cs[4].Init(672, 416, 960, 480, 480)
	g.Cs[5].Init(160, 0, 308, 160, 128)
	g.Cs[6].Init(288, 0, 304, 160, 128)
	curDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	g.gPDirPath = filepath.Join(filepath.Dir(curDir), "garbledPool")
	if g.noSandbox {
		g.key = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}
	} else {
		g.key = u.GetRandom(16)
	}
	g.keys = append(g.keys, g.key)

	if _, err = os.Stat(g.gPDirPath); os.IsNotExist(err) {
		// the dir does not exist, create
		err = os.Mkdir(g.gPDirPath, 0755)
		if err != nil {
			panic(err)
		}
		for _, idx := range []string{"1", "2", "3", "4", "5", "6"} {
			err = os.Mkdir(filepath.Join(g.gPDirPath, "c"+idx), 0755)
			if err != nil {
				panic(err)
			}
		}
		// for c5 we need different sizes
		for _, idx := range g.c5subdirs {
			err = os.Mkdir(filepath.Join(g.gPDirPath, "c5", idx), 0755)
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

// returns Blobs struct for each circuit
func (g *GarbledPool) GetBlobs(c5Count int) []garbler.Blobs {
	if c5Count > 1024 {
		panic("c5Count > 1024")
	}
	allBlobs := make([]garbler.Blobs, len(g.Cs))

	// fetch non-c5 blobs
	for i := 1; i < len(allBlobs); i++ {
		iStr := strconv.Itoa(i)
		if i == 5 {
			continue // we will deal with c5 below
		}
		if len(g.pool[iStr]) == 0 {
			// give monitorPool some time to fill up the pool, then repeat
			log.Println("pool is not ready, sleeping", iStr)
			time.Sleep(time.Second)
			i = i - 1
			continue
		} else {
			g.Lock()
			gc := g.pool[iStr][0]
			g.pool[iStr] = g.pool[iStr][1:]
			g.Unlock()
			blob := g.fetchBlob(iStr, gc)
			il, tt, ol := g.deBlob(blob)
			allBlobs[i].Il = g.grb.SeparateLabels(il, g.Cs[i])
			allBlobs[i].Tt = tt
			allBlobs[i].Ol = ol
		}
	}
	// fetch c5 blobs. Find out from which subdir to fetch
	var dirToFetch string
	for _, dirToFetch = range g.c5subdirs {
		dirInt, _ := strconv.Atoi(dirToFetch)
		if c5Count <= dirInt {
			break
		}
	}
	// loop until there is something to fetch
	for {
		if len(g.poolc5[dirToFetch]) == 0 {
			// give monitorPool some time to fill up the pool, then repeat
			log.Println("pool is not ready, sleeping", dirToFetch)
			time.Sleep(time.Second)
			continue
		} else {
			break
		}
	}
	g.Lock()
	gc := g.poolc5[dirToFetch][0]
	g.poolc5[dirToFetch] = g.poolc5[dirToFetch][1:]
	g.Unlock()
	blobs := g.fetchC5Blobs(dirToFetch, gc, c5Count)
	il, tt, ol := g.deBlob(blobs[0])
	allBlobs[5].Il = g.grb.SeparateLabels(il, g.Cs[5])
	allBlobs[5].Tt = tt
	allBlobs[5].Ol = ol
	// all circuits after 1st have only ClientFixed input labels
	// because all other labels from 1st are reused
	for i := 1; i < len(blobs); i++ {
		il, tt, ol := g.deBlob(blobs[i])
		allBlobs[5].Tt = append(allBlobs[5].Tt, tt...)
		allBlobs[5].Ol = append(allBlobs[5].Ol, ol...)
		allBlobs[5].Il.ClientFixed = append(allBlobs[5].Il.ClientFixed, il...)
	}
	return allBlobs
}

func (g *GarbledPool) loadPoolFromDisk() {
	for _, idx := range []string{"1", "2", "3", "4", "6"} {
		files, err := ioutil.ReadDir(filepath.Join(g.gPDirPath, "c"+idx))
		if err != nil {
			panic(err)
		}
		var gcs []gc
		for _, file := range files {
			gcs = append(gcs, gc{id: file.Name(), keyIdx: 0})
		}
		g.pool[idx] = gcs
	}
	for _, idx := range g.c5subdirs {
		files, err := ioutil.ReadDir(filepath.Join(g.gPDirPath, "c5", idx))
		if err != nil {
			panic(err)
		}
		var gcs []gc
		for _, file := range files {
			gcs = append(gcs, gc{id: file.Name(), keyIdx: 0})
		}
		g.poolc5[idx] = gcs
	}
	log.Println(g.pool)
	log.Println(g.poolc5)
}

// garbles a circuit and returns a blob
func (g *GarbledPool) garbleCircuit(cNo int) []byte {
	tt, il, ol, _ := g.grb.OfflinePhase(g.grb.ParseCircuit(cNo), nil, nil, nil)
	return g.makeBlob(il, tt, ol)
}

// garbles a batch of count c5 circuits and return the garbled blobs
func (g *GarbledPool) garbleC5Circuits(count int) [][]byte {
	var blobs [][]byte
	tt, il, ol, R := g.grb.OfflinePhase(g.Circuits[5], nil, nil, nil)
	labels := g.grb.SeparateLabels(il, g.Cs[5])
	blobs = append(blobs, g.makeBlob(il, tt, ol))

	// for all other circuits we only need ClientFixed input labels
	ilReused := u.Concat(labels.NotaryFixed, labels.ClientNonFixed)
	reuseIndexes := u.ExpandRange(0, 320)
	for i := 2; i <= count; i++ {
		tt, il, ol, _ := g.grb.OfflinePhase(g.Circuits[5], R, ilReused, reuseIndexes)
		labels := g.grb.SeparateLabels(il, g.Cs[5])
		blobs = append(blobs, g.makeBlob(labels.ClientFixed, tt, ol))
	}
	return blobs
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
		for k, v := range g.pool {
			if len(v) < g.poolSize {
				diff := g.poolSize - len(v)
				for i := 0; i < diff; i++ {
					//log.Println("in monitorPool adding c", k)
					kInt, _ := strconv.Atoi(k)
					blob := g.garbleCircuit(kInt)
					randName := u.RandString()
					g.saveBlob(filepath.Join(g.gPDirPath, "c"+k, randName), blob)
					g.Lock()
					g.pool[k] = append(g.pool[k], gc{id: randName, keyIdx: len(g.keys) - 1})
					g.Unlock()
				}
			}
		}
		for k, v := range g.poolc5 {
			if len(v) < g.poolSize {
				diff := g.poolSize - len(v)
				for i := 0; i < diff; i++ {
					//log.Println("in monitorPool adding c5", k)
					kInt, _ := strconv.Atoi(k)
					blobs := g.garbleC5Circuits(kInt)
					randName := u.RandString()
					g.saveC5Blobs(filepath.Join(g.gPDirPath, "c5", k, randName), blobs)
					g.Lock()
					g.poolc5[k] = append(g.poolc5[k], gc{id: randName, keyIdx: len(g.keys) - 1})
					g.Unlock()
				}
			}
		}
		time.Sleep(120 * time.Second)
	}
}

// packs data into a blob with length prefixes
func (g *GarbledPool) makeBlob(il []byte, tt *[]byte, ol []byte) []byte {
	ilSize := make([]byte, 4)
	binary.BigEndian.PutUint32(ilSize, uint32(len(il)))
	ttSize := make([]byte, 4)
	binary.BigEndian.PutUint32(ttSize, uint32(len(*tt)))
	olSize := make([]byte, 4)
	binary.BigEndian.PutUint32(olSize, uint32(len(ol)))
	return u.Concat(ilSize, il, ttSize, *tt, olSize, ol)
}

func (g *GarbledPool) deBlob(blob []byte) ([]byte, []byte, []byte) {
	offset := 0
	ilSize := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	offset += 4
	il := blob[offset : offset+ilSize]
	offset += ilSize
	ttSize := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	offset += 4
	tt := blob[offset : offset+ttSize]
	offset += ttSize
	olSize := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	offset += 4
	ol := blob[offset : offset+olSize]
	return il, tt, ol
}

func (g *GarbledPool) saveBlob(path string, blob []byte) {
	enc := u.AESGCMencrypt(g.key, blob)
	g.encryptedSoFar += len(blob)
	err := os.WriteFile(path, enc, 0644)
	if err != nil {
		panic(err)
	}
}

// fetches the blob from disk and deletes it
func (g *GarbledPool) fetchBlob(circuitNo string, c gc) []byte {
	fullPath := filepath.Join(g.gPDirPath, "c"+circuitNo, c.id)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		panic(err)
	}
	err = os.Remove(fullPath)
	if err != nil {
		panic(err)
	}
	return u.AESGCMdecrypt(g.keys[c.keyIdx], data)
}

// fetches count blobs from folder and then removes it
func (g *GarbledPool) fetchC5Blobs(subdir string, c gc, count int) [][]byte {
	var rawBlobs [][]byte
	dirPath := filepath.Join(g.gPDirPath, "c5", subdir, c.id)
	for i := 0; i < count; i++ {
		iStr := strconv.Itoa(i + 1)
		data, err := os.ReadFile(filepath.Join(dirPath, iStr))
		if err != nil {
			panic(err)
		}
		rawBlobs = append(rawBlobs, u.AESGCMdecrypt(g.keys[c.keyIdx], data))
	}
	err := os.RemoveAll(dirPath)
	if err != nil {
		panic(err)
	}
	return rawBlobs
}

func (g *GarbledPool) saveC5Blobs(path string, blobs [][]byte) {
	err := os.Mkdir(path, 0755)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(blobs); i++ {
		fileName := strconv.Itoa(i + 1)
		enc := u.AESGCMencrypt(g.key, blobs[i])
		g.encryptedSoFar += len(blobs[i])
		err := os.WriteFile(filepath.Join(path, fileName), enc, 0644)
		if err != nil {
			panic(err)
		}
	}
}
