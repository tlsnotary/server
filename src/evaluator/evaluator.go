package evaluator

import (
	"notary/meta"
	u "notary/utils"
)

type Evaluator struct {
	// the total amount of c6 circuit executions for this session
	C6Count int
	// all circuits, count starts with 1 to avoid confusion
	// they are meant to be read-only for evaluator
	meta    []*meta.Circuit
	ttBlobs [][]byte // truth table blobs for each circuit
}

func (e *Evaluator) Init(circuits []*meta.Circuit, c6Count int) {
	e.C6Count = c6Count
	e.meta = circuits
	e.ttBlobs = make([][]byte, len(e.meta))
}

// Evaluate evaluates a circuit number cNo
func (e *Evaluator) Evaluate(cNo int, notaryLabels, clientLabels,
	truthTables []byte) []byte {
	type batch_t struct {
		// wl is wire labels
		wl *[][]byte
		// tt is truth tables
		tt *[]byte
	}

	c := (e.meta)[cNo]
	// split into a batch for multiple executions
	nlBatch := u.SplitIntoChunks(notaryLabels, c.NotaryInputSize*16)
	clBatch := u.SplitIntoChunks(clientLabels, c.ClientInputSize*16)
	ttBatch := u.SplitIntoChunks(truthTables, c.AndGateCount*48)

	// exeCount is how many executions of this circuit we need
	exeCount := []int{0, 1, 1, 1, 1, 1, e.C6Count, 1}[cNo]
	batch := make([]batch_t, exeCount)
	for r := 0; r < exeCount; r++ {
		// put all input labels into wire labels
		wireLabels := make([][]byte, c.WireCount)
		copy(wireLabels, u.SplitIntoChunks(u.Concat(nlBatch[r], clBatch[r]), 16))
		batch[r] = batch_t{&wireLabels, &ttBatch[r]}
	}

	encodedOutput := make([][]byte, exeCount)
	for r := 0; r < exeCount; r++ {
		encodedOutput[r] = evaluate(c, batch[r].wl, batch[r].tt)
	}
	return u.Concat(encodedOutput...)
}

func evaluate(c *meta.Circuit, wireLabels *[][]byte, truthTables *[]byte) []byte {
	andGateIdx := 0
	// gate type XOR==0 AND==1 INV==2
	for i := 0; i < len(c.Gates); i++ {
		g := c.Gates[i]
		if g.Operation == 1 {
			evaluateAnd(g, wireLabels, truthTables, andGateIdx)
			andGateIdx += 1
		} else if g.Operation == 0 {
			evaluateXor(g, wireLabels)
		} else if g.Operation == 2 {
			evaluateInv(g, wireLabels)
		} else {
			panic("Unknown gate")
		}
	}
	// return encoded output
	outLSBs := make([]int, c.OutputSize)
	for i := 0; i < c.OutputSize; i++ {
		outLSBs[i] = int((*wireLabels)[c.WireCount-c.OutputSize+i][15]) & 1
	}
	return u.BitsToBytes(outLSBs)
}

func evaluateAnd(g meta.Gate, wireLabels *[][]byte, truthTables *[]byte, andGateIdx int) {
	// get wire numbers
	in1 := g.InputWires[0]
	in2 := g.InputWires[1]
	out := g.OutputWire
	label1 := (*wireLabels)[in1]
	label2 := (*wireLabels)[in2]

	var cipher []byte
	point := 2*getPoint(label1) + getPoint(label2)
	if point == 3 {
		// GRR3: all rows with point sum of 3 have been reduced
		// their encryption is an all-zero bytestring
		cipher = make([]byte, 16)
	} else {
		offset := andGateIdx*48 + 16*point
		cipher = (*truthTables)[offset : offset+16]
	}
	(*wireLabels)[out] = u.Decrypt(label1, label2, g.Id, cipher)
}

func evaluateXor(g meta.Gate, wireLabels *[][]byte) {
	in1 := g.InputWires[0]
	in2 := g.InputWires[1]
	out := g.OutputWire
	(*wireLabels)[out] = u.XorBytes((*wireLabels)[in1], (*wireLabels)[in2])
}

func evaluateInv(g meta.Gate, wireLabels *[][]byte) {
	in1 := g.InputWires[0]
	out := g.OutputWire
	(*wireLabels)[out] = (*wireLabels)[in1]
}

func getPoint(arr []byte) int {
	return int(arr[15]) & 0x01
}
