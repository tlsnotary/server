package garbler

import (
	"notary/meta"
	u "notary/utils"
)

// Garbler implement the role of the notary as the  garbler of the binary circuit.
// This is a fixed-key-cipher garbling scheme BHKR13
//  https://eprint.iacr.org/2013/426.pdf

type Garbler struct {
	// the total amount of c6 circuit executions for this session
	C6Count int
	// all circuits, count starts with 1 to avoid confusion
	Cs []CData
}

// CData is data for one circuit
type CData struct {
	// Il contains a flat slice of all input labels for all executions of
	// one circuit
	Il []byte
	// InputBits is notary's input for this circuit. Starts with the least
	// input bit at index [0].
	InputBits []int
	// Masks are notary's masks. They are inputs to the circuit. Their purpose
	// is to mask the circuit's output. Mask numbering starts with 1 for
	// convenience. Consult circuits/*.casm files for description of what each
	// mask does.
	Masks [][]byte
	Meta  *meta.Circuit
}

// Init puts input labels into correspondign circuits and creates masks for
// notary's inputs to the circuits.
// il contains input labels for each execution of each circuit
func (g *Garbler) Init(il [][][]byte, circuits []*meta.Circuit, c6Count int) {
	g.C6Count = c6Count
	g.Cs = make([]CData, len(circuits))
	for i := 1; i < len(g.Cs); i++ {
		g.Cs[i].Il = u.Concat(il[i]...)
		g.Cs[i].Meta = circuits[i]

		if i == 1 {
			g.Cs[i].Masks = make([][]byte, 2)
			g.Cs[i].Masks[1] = u.GetRandom(32)
		}
		if i == 2 {
			g.Cs[i].Masks = make([][]byte, 2)
			g.Cs[i].Masks[1] = u.GetRandom(32)
		}
		if i == 3 {
			g.Cs[i].Masks = make([][]byte, 5)
			g.Cs[i].Masks[1] = u.GetRandom(16)
			g.Cs[i].Masks[2] = u.GetRandom(16)
			g.Cs[i].Masks[3] = u.GetRandom(4)
			g.Cs[i].Masks[4] = u.GetRandom(4)
		}
		if i == 4 {
			g.Cs[i].Masks = make([][]byte, 3)
			g.Cs[i].Masks[1] = u.GetRandom(16)
			g.Cs[i].Masks[2] = u.GetRandom(16)
		}
		if i == 5 {
			g.Cs[i].Masks = make([][]byte, 3)
			g.Cs[i].Masks[1] = u.GetRandom(16)
			g.Cs[i].Masks[2] = u.GetRandom(16)
		}
		if i == 7 {
			g.Cs[i].Masks = make([][]byte, 2)
			g.Cs[i].Masks[1] = u.GetRandom(16)
		}
	}
}

// Garble garbles a circuit. Returns input labels, truth tables, decoding table
func (g *Garbler) Garble(c *meta.Circuit) (*[]byte, *[]byte, *[]byte) {
	// R is also called the circuit's delta
	R := u.GetRandom(16)
	// set the last bit of R to 1 for point-and-permute
	// this guarantees that 2 labels of the same wire will have the opposite last bits
	R[15] = R[15] | 0x01

	inputCount := c.ClientInputSize + c.NotaryInputSize
	wireLabels := make([][][]byte, c.WireCount)
	// put input labels into wire labels
	copy(wireLabels, *generateInputLabels(inputCount, R))

	// a truth table contains 3 rows 16 bytes each
	truthTables := make([]byte, c.AndGateCount*48)
	garble(c, &wireLabels, &truthTables, &R)
	if len(wireLabels) != c.WireCount {
		panic("len(wireLabels) != c.WireCount")
	}

	inputLabels := make([]byte, inputCount*32)
	for i := 0; i < inputCount; i++ {
		copy(inputLabels[i*32:i*32+16], wireLabels[i][0])
		copy(inputLabels[i*32+16:i*32+32], wireLabels[i][1])
	}
	// get decoding table: LSB of label0 for each output wire
	outLSB := make([]int, c.OutputSize)
	for i := 0; i < c.OutputSize; i++ {
		outLSB[i] = int(wireLabels[c.WireCount-c.OutputSize+i][0][15]) & 1
	}
	decodingTable := u.BitsToBytes(outLSB)
	return &inputLabels, &truthTables, &decodingTable
}

// Client's inputs always come after the Notary's inputs in the circuit
func (g *Garbler) GetClientLabels(cNo int) []byte {
	// exeCount is how many executions of this circuit we need
	exeCount := []int{0, 1, 1, 1, 1, 1, g.C6Count, 1}[cNo]
	c := g.Cs[cNo]
	// chunkSize is the bytesize of input labels for one circuit execution
	chunkSize := (c.Meta.NotaryInputSize + c.Meta.ClientInputSize) * 32
	if chunkSize*exeCount != len(c.Il) {
		panic("(chunkSize * exeCount != len(c.Il))")
	}
	var allIl []byte
	for i := 0; i < exeCount; i++ {
		allIl = append(allIl, c.Il[i*chunkSize+c.Meta.NotaryInputSize*32:(i+1)*chunkSize]...)
	}
	return allIl
}

// GetNotaryLabels returns notary's input labels for the circuit
func (g *Garbler) GetNotaryLabels(cNo int) []byte {
	// exeCount is how many executions of this circuit we need
	exeCount := []int{0, 1, 1, 1, 1, 1, g.C6Count, 1}[cNo]
	c := g.Cs[cNo]
	// chunkSize is the bytesize of input labels for one circuit execution
	chunkSize := (c.Meta.NotaryInputSize + c.Meta.ClientInputSize) * 32
	if chunkSize*exeCount != len(c.Il) {
		panic("(chunkSize * exeCount != len(c.Il))")
	}
	var inputLabelBlob []byte
	for i := 0; i < exeCount; i++ {
		inputLabelBlob = append(inputLabelBlob,
			c.Il[i*chunkSize:i*chunkSize+c.Meta.NotaryInputSize*32]...)
	}
	if len(inputLabelBlob) != len(c.InputBits)*32 {
		panic("len(inputLabelBlob) != len(c.InputBits)*32")
	}
	// pick either label0 or label1 depending on our input bit
	var inputLabels []byte
	for i := 0; i < len(c.InputBits); i++ {
		var label []byte
		if c.InputBits[i] == 0 {
			label = inputLabelBlob[i*32 : i*32+16]
		} else {
			label = inputLabelBlob[i*32+16 : i*32+32]
		}
		inputLabels = append(inputLabels, label...)
	}
	return inputLabels
}

func generateInputLabels(count int, R []byte) *[][][]byte {
	newLabels := make([][][]byte, count)
	for i := 0; i < count; i++ {
		label1 := u.GetRandom(16)
		label2 := u.XorBytes(label1, R)
		newLabels[i] = [][]byte{label1, label2}
	}
	return &newLabels
}

func garble(c *meta.Circuit, wireLabels *[][][]byte, truthTables *[]byte, R *[]byte) {
	var andGateIdx int = 0
	for i := 0; i < len(c.Gates); i++ {
		gate := c.Gates[i]
		if gate.Operation == 1 {
			tt := garbleAnd(gate, wireLabels, R)
			copy((*truthTables)[andGateIdx*48:(andGateIdx+1)*48], tt[0:48])
			andGateIdx += 1
		} else if gate.Operation == 0 {
			garbleXor(gate, wireLabels, R)
		} else if gate.Operation == 2 {
			garbleInv(gate, wireLabels)
		}
	}
}

func getPoint(arr []byte) int {
	return int(arr[15]) & 0x01
}

func garbleAnd(g meta.Gate, wireLabels *[][][]byte, R *[]byte) []byte {
	// get wire numbers
	in1 := g.InputWires[0]
	in2 := g.InputWires[1]
	out := g.OutputWire

	// get labels of each wire
	in1_0 := (*wireLabels)[in1][0]
	in1_1 := (*wireLabels)[in1][1]
	in2_0 := (*wireLabels)[in2][0]
	in2_1 := (*wireLabels)[in2][1]

	// output wires will be assigned labels later
	var out_0, out_1 []byte
	// rows is wire labels in a canonical order
	var rows = [4][3]*[]byte{
		{&in1_0, &in2_0, &out_0},
		{&in1_0, &in2_1, &out_0},
		{&in1_1, &in2_0, &out_0},
		{&in1_1, &in2_1, &out_1}}

	// GRR3: garbled row reduction
	// We want to reduce a row where both labels' points are set to 1.
	// We first need to encrypt those labels with a dummy all-zero output label. The
	// result X will be the actual value of the output label that we need to set.
	// After we set the output label to X and encrypt again, the result will be 0 (but
	// we don't actually need to encrypt it again, we just know that the result will be 0)

	// idxToReduce is the index of the row that will be reduced
	idxToReduce := -1
	for i := 0; i < len(rows); i++ {
		if getPoint(*rows[i][0]) == 1 && getPoint(*rows[i][1]) == 1 {
			zeroWire := make([]byte, 16)
			outWire := u.Encrypt(*rows[i][0], *rows[i][1], g.Id, zeroWire)
			if i == 3 {
				out_1 = outWire
				out_0 = u.XorBytes(outWire, *R)
			} else {
				out_0 = outWire
				out_1 = u.XorBytes(outWire, *R)
			}
			idxToReduce = i
			break
		}
	}
	(*wireLabels)[out] = [][]byte{out_0, out_1}
	if idxToReduce == -1 {
		panic(idxToReduce == -1)
	}

	truthTable := make([][]byte, 3)
	for i := 0; i < len(rows); i++ {
		if i == idxToReduce {
			// not encrypting this row because we already know that its encryption is 0
			// and the sum of its points is 3
			continue
		}
		value := u.Encrypt(*rows[i][0], *rows[i][1], g.Id, *rows[i][2])
		point := 2*getPoint(*rows[i][0]) + getPoint(*rows[i][1])
		truthTable[point] = value
	}
	return u.Flatten(truthTable)
}

func garbleXor(g meta.Gate, wireLabels *[][][]byte, R *[]byte) {
	in1 := g.InputWires[0]
	in2 := g.InputWires[1]
	out := g.OutputWire

	out1 := u.XorBytes((*wireLabels)[in1][0], (*wireLabels)[in2][0])
	out2 := u.XorBytes(u.XorBytes((*wireLabels)[in1][1], (*wireLabels)[in2][1]), *R)
	(*wireLabels)[out] = [][]byte{out1, out2}
}

func garbleInv(g meta.Gate, wireLabels *[][][]byte) {
	in1 := g.InputWires[0]
	out := g.OutputWire
	(*wireLabels)[out] = [][]byte{(*wireLabels)[in1][1], (*wireLabels)[in1][0]}
}
