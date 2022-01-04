package evaluator

import (
	"bytes"
	"encoding/binary"
	"log"
	"math"
	"math/rand"
	"notary/garbler"
	u "notary/utils"
	"time"

	"github.com/bwesterb/go-ristretto"
)

type Evaluator struct {
	g *garbler.Garbler
	// fixed inputs for each circuit (circuit count starts at 1)
	FixedInputs [][]int
	// OT for bits 0/1 format: ({k:[]byte, B:[]byte})
	OT0            []OTmap
	OT1            []OTmap
	A              []byte // client-garbler's A
	fixedLabels    [][][]byte
	OTFixedK       [][]byte
	ttBlobs        [][]byte // truth table blobs for each circuit
	olBlobs        [][]byte // output labels blobs for each circuit
	nonFixedOTBits [][]OTmap
	Salt           [][]byte // commitment salt for each circuit
	CommitHash     [][]byte // hash of output for each circuit
}

type OTmap struct {
	K   []byte
	B   []byte
	idx int
}

func (e *Evaluator) Init(g *garbler.Garbler) {
	e.g = g
	e.FixedInputs = make([][]int, len(g.Cs))
	e.fixedLabels = make([][][]byte, len(g.Cs))
	e.ttBlobs = make([][]byte, len(g.Cs))
	e.olBlobs = make([][]byte, len(g.Cs))
	e.Salt = make([][]byte, len(g.Cs))
	e.CommitHash = make([][]byte, len(g.Cs))
	e.nonFixedOTBits = make([][]OTmap, len(g.Cs))
}

// SetFixedInputs is called after we know the amount of c6 circuits
// consult .casm file for each circuit for explanation what mask does what
func (e *Evaluator) SetFixedInputs() {
	for i := 1; i < len(e.g.Cs); i++ {
		c := e.g.Cs[i]
		if i == 1 {
			e.FixedInputs[1] = u.BytesToBits(c.Masks[1])
			log.Println("e.FixedInputs[1] ", len(e.FixedInputs[1]))
		}
		if i == 2 {
			e.FixedInputs[2] = u.BytesToBits(c.Masks[1])
			log.Println("e.FixedInputs[2] ", len(e.FixedInputs[2]))
		}
		if i == 3 {
			var allMasks []byte
			allMasks = append(allMasks, c.Masks[6]...)
			allMasks = append(allMasks, c.Masks[5]...)
			allMasks = append(allMasks, c.Masks[4]...)
			allMasks = append(allMasks, c.Masks[3]...)
			allMasks = append(allMasks, c.Masks[2]...)
			allMasks = append(allMasks, c.Masks[1]...)
			e.FixedInputs[3] = u.BytesToBits(allMasks)
			log.Println("e.FixedInputs[3] ", len(e.FixedInputs[3]))
		}
		if i == 4 {
			var allMasks []byte
			allMasks = append(allMasks, c.Masks[2]...)
			allMasks = append(allMasks, c.Masks[1]...)
			e.FixedInputs[4] = u.BytesToBits(allMasks)
			log.Println("e.FixedInputs[4] ", len(e.FixedInputs[4]))
		}
		if i == 5 {
			var allMasks []byte
			allMasks = append(allMasks, e.g.Cs[3].Masks[4]...) // civ mask
			allMasks = append(allMasks, e.g.Cs[3].Masks[2]...) // cwk mask
			e.FixedInputs[5] = u.BytesToBits(allMasks)
			log.Println("e.FixedInputs[5] ", len(e.FixedInputs[5]))
		}
		if i == 6 {
			var allMasks []byte
			for i := e.g.C6Count; i > 0; i-- {
				allMasks = append(allMasks, e.g.Cs[6].Masks[i]...)
			}
			allMasks = append(allMasks, e.g.Cs[3].Masks[4]...) // civ mask
			allMasks = append(allMasks, e.g.Cs[3].Masks[2]...) // cwk mask
			e.FixedInputs[6] = u.BytesToBits(allMasks)
			log.Println("e.FixedInputs[6] ", len(e.FixedInputs[6]))
		}
	}
}

// client's A for OT must be available at this point
func (e *Evaluator) PreComputeOT() []byte {
	var allFixedInputs []int
	allNonFixedInputsSize := 0
	for i := 1; i < len(e.g.Cs); i++ {
		allFixedInputs = append(allFixedInputs, e.FixedInputs[i]...)
		allNonFixedInputsSize += e.g.Cs[i].NotaryNonFixedInputSize
	}
	log.Println("len(allFixedInputs)", len(allFixedInputs))
	log.Println("allNonFixedInputsSize", allNonFixedInputsSize)

	var buf [32]byte
	copy(buf[:], e.A[:])
	A := new(ristretto.Point)
	A.SetBytes(&buf)

	e.OTFixedK = nil
	var OTFixedB [][]byte
	for i := 0; i < len(allFixedInputs); i++ {
		bit := allFixedInputs[i]
		b := new(ristretto.Scalar).Rand()
		B := new(ristretto.Point).ScalarMultBase(b)
		if bit == 1 {
			B = new(ristretto.Point).Add(A, B)
		}
		k := u.Generichash(16, new(ristretto.Point).ScalarMult(A, b).Bytes())
		e.OTFixedK = append(e.OTFixedK, k)
		OTFixedB = append(OTFixedB, B.Bytes())
	}

	// we prepare OT for 55% of 1s and 55% of 0s for all non-fixed inputs
	// because we don't know in advance exactly how many 1s and 0s we'll have in the non-fixed
	// inputs
	e.OT0 = nil
	e.OT1 = nil
	for i := 0; i < int(math.Ceil(float64(allNonFixedInputsSize/2)*1.2))+3000; i++ {
		b := new(ristretto.Scalar).Rand()
		B := new(ristretto.Point).ScalarMultBase(b)
		k := u.Generichash(16, new(ristretto.Point).ScalarMult(A, b).Bytes())
		var m OTmap
		m.K = k
		m.B = B.Bytes()
		e.OT0 = append(e.OT0, m)
	}
	for i := 0; i < int(math.Ceil(float64(allNonFixedInputsSize/2)*1.2))+3000; i++ {
		b := new(ristretto.Scalar).Rand()
		B := new(ristretto.Point).ScalarMultBase(b)
		B = new(ristretto.Point).Add(A, B)
		k := u.Generichash(16, new(ristretto.Point).ScalarMult(A, b).Bytes())
		var m OTmap
		m.K = k
		m.B = B.Bytes()
		e.OT1 = append(e.OT1, m)
	}
	log.Println("e.OT0/1 len is", len(e.OT0), len(e.OT1))

	//send remaining OT in random sequence but remember the index in that sequence.
	var OTNonFixedToSend []byte = nil

	allOTLen := len(e.OT0) + len(e.OT1)
	var idxSeen []int

	for i := 0; i < allOTLen; i++ {
		var ot *[]OTmap
		rand.Seed(time.Now().UnixNano())
		randIdx := rand.Intn(allOTLen)
		if isIntInArray(randIdx, idxSeen) {
			// this index was already seen, try again
			i--
			continue
		}
		idxSeen = append(idxSeen, randIdx)
		if randIdx >= len(e.OT0) {
			ot = &e.OT1
			// adjust the index to become an OT1 index
			randIdx = randIdx - len(e.OT0)
		} else {
			ot = &e.OT0
		}
		(*ot)[randIdx].idx = i
		OTNonFixedToSend = append(OTNonFixedToSend, (*ot)[randIdx].B...)
	}

	var payload []byte
	for i := 0; i < len(OTFixedB); i++ {
		payload = append(payload, OTFixedB[i]...)
	}
	payload = append(payload, OTNonFixedToSend...)
	log.Println("returning payload for garbler, size ", len(payload))
	return payload
}

func (e *Evaluator) SetA(A []byte) {
	e.A = A
}

func (e *Evaluator) ProcessEncryptedLabels(labelsBlob []byte) {
	allFICount := 0 //count of all fixed inputs from all circuits
	for i := 1; i < len(e.g.Cs); i++ {
		allFICount += len(e.FixedInputs[i])
	}

	if len(labelsBlob) != allFICount*32 {
		log.Println(len(labelsBlob), allFICount)
		panic("len(labelsBlob) != allFICount*32")
	}
	idx := 0
	for i := 1; i < len(e.g.Cs); i++ {
		e.fixedLabels[i] = make([][]byte, len(e.FixedInputs[i]))
		for j := 0; j < len(e.FixedInputs[i]); j++ {
			bit := e.FixedInputs[i][j]
			if bit != 0 && bit != 1 {
				panic("bit != 0 || bit != 1")
			}
			e_ := labelsBlob[idx*32+16*bit : idx*32+16*bit+16]
			inputLabel := u.Decrypt_generic(e_, e.OTFixedK[idx], 0)
			idx += 1
			e.fixedLabels[i][j] = inputLabel
		}
	}
}

func (e *Evaluator) SetBlob(blob []byte) {
	offset := 0
	for i := 1; i < len(e.g.Cs); i++ {
		ttLen := e.g.Cs[i].Circuit.AndGateCount * 48
		olLen := e.g.Cs[i].Circuit.OutputSize * 32
		if i == 5 {
			ttLen = e.g.C5Count * ttLen
			olLen = e.g.C5Count * olLen
		}
		if i == 6 {
			ttLen = e.g.C6Count * ttLen
			olLen = e.g.C6Count * olLen
		}
		e.ttBlobs[i] = blob[offset : offset+ttLen]
		offset += ttLen
		e.olBlobs[i] = blob[offset : offset+olLen]
		offset += olLen
	}
	if len(blob) != offset {
		panic("len(blob) != offset")
	}
}

func (e *Evaluator) GetNonFixedIndexes(cNo int) []byte {
	c := &e.g.Cs[cNo]
	nonFixedBits := c.InputBits[:c.NotaryNonFixedInputSize]
	//get OT indexes for bits in the non-fixed inputs
	idxArray, otArray := e.DoGetNonFixedIndexes(nonFixedBits)
	e.nonFixedOTBits[cNo] = otArray
	return idxArray
}

// return indexes from the OT pool as well as OTmap for each OT
func (e *Evaluator) DoGetNonFixedIndexes(bits []int) ([]byte, []OTmap) {
	var idxArray []byte //flat array of 2-byte indexes
	otArray := make([]OTmap, len(bits))

	for i := 0; i < len(bits); i++ {
		bit := bits[i]
		if bit == 0 {
			// take element from the end of slice and shrink slice
			ot0 := e.OT0[len(e.OT0)-1]
			e.OT0 = e.OT0[:len(e.OT0)-1]
			idx := make([]byte, 2)
			binary.BigEndian.PutUint16(idx, uint16(ot0.idx))
			idxArray = append(idxArray, idx...)
			otArray[i] = ot0
		} else {
			// take element from the end of slice and shrink slice
			ot1 := e.OT1[len(e.OT1)-1]
			e.OT1 = e.OT1[:len(e.OT1)-1]
			idx := make([]byte, 2)
			binary.BigEndian.PutUint16(idx, uint16(ot1.idx))
			idxArray = append(idxArray, idx...)
			otArray[i] = ot1
		}
	}
	if len(e.OT0) < 1 || len(e.OT1) < 1 {
		panic("len(e.OT0) < 1 || len(e.OT1) < 1")
	}
	return idxArray, otArray
}

func (e *Evaluator) Evaluate(cNo int, notaryLabelsBlob, clientLabelsBlob, ttBlob, olBlob []byte) []byte {
	type batchType struct {
		ga *[][]byte
		tt *[]byte
	}

	c := &e.g.Cs[cNo]
	nlBatch := u.SplitIntoChunks(notaryLabelsBlob, c.NotaryInputSize*16)
	clBatch := u.SplitIntoChunks(clientLabelsBlob, c.ClientInputSize*16)
	ttBatch := u.SplitIntoChunks(ttBlob, c.Circuit.AndGateCount*48)

	// exeCount is how many executions of this circuit we need
	exeCount := []int{0, 1, 1, 1, 1, e.g.C5Count, 1, e.g.C6Count}[cNo]
	batch := make([]batchType, exeCount)
	for r := 0; r < exeCount; r++ {
		// put all labels into garbling assignment
		ga := make([][]byte, c.Circuit.WireCount)
		copy(ga, u.SplitIntoChunks(u.Concat(nlBatch[r], clBatch[r]), 16))
		batch[r] = batchType{&ga, &ttBatch[r]}
	}

	batchOutputLabels := make([][][]byte, exeCount)
	for r := 0; r < exeCount; r++ {
		evaluate(c.Circuit, batch[r].ga, batch[r].tt)
		outputLabels := (*batch[r].ga)[len((*batch[r].ga))-c.Circuit.OutputSize:]
		batchOutputLabels[r] = outputLabels
	}

	var output []byte
	for r := 0; r < exeCount; r++ {
		outputLabels := batchOutputLabels[r]
		outBits := make([]int, c.Circuit.OutputSize)
		outputSizeBytes := c.Circuit.OutputSize * 32
		allOutputLabelsBlob := olBlob[r*outputSizeBytes : (r+1)*outputSizeBytes]

		for i := 0; i < len(outBits); i++ {
			out := outputLabels[i]
			if bytes.Equal(out, allOutputLabelsBlob[i*32:i*32+16]) {
				outBits[i] = 0
			} else if bytes.Equal(out, allOutputLabelsBlob[i*32+16:i*32+32]) {
				outBits[i] = 1
			} else {
				log.Println("incorrect output label")
			}
		}
		outBytes := u.BitsToBytes(outBits)
		output = append(output, outBytes...)
	}

	c.Output = output
	e.CommitHash[cNo] = u.Sha256(c.Output)
	e.Salt[cNo] = u.GetRandom(32)
	return u.Sha256(u.Concat(e.CommitHash[cNo], e.Salt[cNo]))
}

func evaluate(c *garbler.Circuit, garbledAssignment *[][]byte, tt *[]byte) {
	andGateIdx := 0
	// gate type XOR==0 AND==1 INV==2
	for i := 0; i < len(c.Gates); i++ {
		g := c.Gates[i]
		if g.Operation == 1 {
			evaluateAnd(g, garbledAssignment, tt, andGateIdx)
			andGateIdx += 1
		} else if g.Operation == 0 {
			evaluateXor(g, garbledAssignment)
		} else if g.Operation == 2 {
			evaluateInv(g, garbledAssignment)
		} else {
			panic("Unknown gate")
		}
	}
}

func evaluateAnd(g garbler.Gate, ga *[][]byte, tt *[]byte, andGateIdx int) {
	// get wire numbers
	in1 := g.InputWires[0]
	in2 := g.InputWires[1]
	out := g.OutputWire

	label1 := (*ga)[in1]
	label2 := (*ga)[in2]

	var cipher []byte
	point := 2*getPoint(label1) + getPoint(label2)
	if point == 3 {
		// GRR3: all rows with point sum of 3 have been reduced
		// their encryption is an all-zero bytestring
		cipher = make([]byte, 16)
	} else {
		offset := andGateIdx*48 + 16*point
		cipher = (*tt)[offset : offset+16]
	}
	(*ga)[out] = u.Decrypt(label1, label2, g.Id, cipher)
}

func evaluateXor(g garbler.Gate, ga *[][]byte) {
	in1 := g.InputWires[0]
	in2 := g.InputWires[1]
	out := g.OutputWire

	(*ga)[out] = xorBytes((*ga)[in1], (*ga)[in2])
}

func evaluateInv(g garbler.Gate, ga *[][]byte) {
	in1 := g.InputWires[0]
	out := g.OutputWire
	(*ga)[out] = (*ga)[in1]
}

func getPoint(arr []byte) int {
	return int(arr[15]) & 0x01
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("len(a) != len(b)")
	}
	c := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func isIntInArray(a int, arr []int) bool {
	for _, b := range arr {
		if b == a {
			return true
		}
	}
	return false
}
