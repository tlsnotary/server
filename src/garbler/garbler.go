package garbler

import (
	"crypto/rand"
	"encoding/binary"
	"io/ioutil"
	"log"
	"math/big"
	u "notary/utils"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bwesterb/go-ristretto"
)

type Garbler struct {
	P1_vd                []byte // client verify data
	Server_verify_data   []byte // server verify data
	Server_iv, Client_iv []byte
	R, One, Zero         *big.Int // will be set in Preprocess, used by ghash
	// the total amount of c5 circuits for this session
	C5Count int
	// the total amount of c6 circuits for this session
	C6Count           int
	SwkMaskedByClient []byte
	Ot_a              *ristretto.Scalar
	A                 *ristretto.Point
	AllNonFixedOT     [][][]byte

	// this is the mask that we apply before sending cwk masked twice to the client
	// this is done so that the client could change the mask
	cwkSecondMask     []byte
	CwkMaskedByClient []byte //this is notary's input to c5

	// all circuits, count starts with 1 to avoid confusion
	Cs []CData
}

type CData struct {
	OT                      []OTstruct // parsed OT
	Ol                      []byte     // output labels
	Il                      Labels     // input labels
	Tt                      []byte     // truth table
	NotaryInputSize         int        // in bits
	NotaryNonFixedInputSize int
	NotaryFixedInputSize    int
	ClientInputSize         int // in bits
	ClientNonFixedInputSize int
	ClientFixedInputSize    int
	OutputSize              int    // in bits
	Output                  []byte // garbler+evaluator output of circuit
	Input                   []byte // garbler's input for this circuit
	PmsOuterHash            []byte // only for c1
	MsOuterHash             []byte // output from c2
	Masks                   [][]byte
	Circuit                 *Circuit
	TagSharesBlob           []byte
	FixedInputs             []int // array of 0 and 1 for evaluator's fixed inputs
}

func (p *CData) Init(nis, nnfis, cis, cnfis, os int) {
	p.NotaryInputSize = nis
	p.NotaryNonFixedInputSize = nnfis
	p.NotaryFixedInputSize = p.NotaryInputSize - p.NotaryNonFixedInputSize
	p.ClientInputSize = cis
	p.ClientNonFixedInputSize = cnfis
	p.ClientFixedInputSize = p.ClientInputSize - p.ClientNonFixedInputSize
	p.OutputSize = os
}

type OTstruct struct {
	Ot_a   *ristretto.Scalar
	A      *ristretto.Point
	Ot_b   *ristretto.Scalar
	B      *ristretto.Point
	AplusB *ristretto.Point
	K      *ristretto.Point
	M0     []byte
	M1     []byte
	C      int
}

type Gate struct {
	Id         uint32
	Operation  uint8
	InputWires []uint32
	OutputWire uint32
}

type Circuit struct {
	WireCount          int
	GarblerInputSize   int
	EvaluatorInputSize int
	OutputSize         int
	AndGateCount       int
	Gates              []Gate
}

type Labels struct {
	NotaryNonFixed []byte
	NotaryFixed    []byte
	ClientNonFixed []byte
	ClientFixed    []byte
}

type Blobs struct {
	Il Labels // input labels
	Tt []byte // truth table
	Ol []byte // output labels
	R  []byte
}

func (g *Garbler) Init(ilBlobs []Labels, circuits []*Circuit) {
	g.Cs = make([]CData, 7)
	g.Cs[1].Init(512, 256, 512, 256, 512)
	g.Cs[2].Init(512, 256, 640, 384, 512)
	g.Cs[3].Init(832, 256, 1568, 768, 800)
	g.Cs[4].Init(672, 416, 960, 480, 480)
	g.Cs[5].Init(160, 0, 308, 160, 128)
	g.Cs[6].Init(288, 0, 304, 160, 128)

	for i := 1; i < len(g.Cs); i++ {
		c := &g.Cs[i]
		c.Il = ilBlobs[i]
		c.Circuit = circuits[i]

		if i == 1 {
			c.Masks = make([][]byte, 2)
			c.Masks[1] = u.GetRandom(32)
		}
		if i == 2 {
			c.Masks = make([][]byte, 2)
			c.Masks[1] = u.GetRandom(32)
		}
		if i == 3 {
			c.Masks = make([][]byte, 7)
			c.Masks[1] = u.GetRandom(16)
			c.Masks[2] = u.GetRandom(16)
			c.Masks[3] = u.GetRandom(4)
			c.Masks[4] = u.GetRandom(4)
			c.Masks[5] = u.GetRandom(16)
			c.Masks[6] = u.GetRandom(16)
		}
		if i == 4 {
			c.Masks = make([][]byte, 3)
			c.Masks[1] = u.GetRandom(16)
			c.Masks[2] = u.GetRandom(16)
		}
		if i == 6 {
			c.Masks = make([][]byte, g.C6Count+1)
			for j := 1; j < g.C6Count+1; j++ {
				c.Masks[j] = u.GetRandom(16)
			}
		}
	}
}

// PrepareA is done before Init so that we could send A to the client as soon as possible
func (g *Garbler) PrepareA() {
	g.Ot_a = new(ristretto.Scalar).Rand()
	g.A = new(ristretto.Point).ScalarMultBase(g.Ot_a)
}

func (g *Garbler) Ot_GetA() []byte {
	return g.A.Bytes()
}

// internal method
func (g *Garbler) separateLabels(blob []byte, cNo int) Labels {
	c := g.Cs[cNo]
	return g.SeparateLabels(blob, c)
}

// separate one continuous blob of input labels into 4 blobs as in Labels struct
func (g *Garbler) SeparateLabels(blob []byte, c CData) Labels {
	if len(blob) != (c.NotaryInputSize+c.ClientInputSize)*32 {
		panic("in separateLabels")
	}
	var labels Labels
	offset := 0
	labels.NotaryNonFixed = make([]byte, c.NotaryNonFixedInputSize*32)
	copy(labels.NotaryNonFixed, blob[offset:offset+c.NotaryNonFixedInputSize*32])
	offset += c.NotaryNonFixedInputSize * 32

	labels.NotaryFixed = make([]byte, c.NotaryFixedInputSize*32)
	copy(labels.NotaryFixed, blob[offset:offset+c.NotaryFixedInputSize*32])
	offset += c.NotaryFixedInputSize * 32

	labels.ClientNonFixed = make([]byte, c.ClientNonFixedInputSize*32)
	copy(labels.ClientNonFixed, blob[offset:offset+c.ClientNonFixedInputSize*32])
	offset += c.ClientNonFixedInputSize * 32

	labels.ClientFixed = make([]byte, c.ClientFixedInputSize*32)
	copy(labels.ClientFixed, blob[offset:offset+c.ClientFixedInputSize*32])
	offset += c.ClientFixedInputSize * 32
	return labels
}

func (g *Garbler) C_getEncNonFixedLabels(cNo int, idxBlob []byte) []byte {
	c := &g.Cs[cNo]
	if len(idxBlob) != 2*c.ClientNonFixedInputSize {
		log.Println(cNo)
		panic("len(idxArr)!= 2*256")
	}

	var encLabels []byte
	for i := 0; i < c.ClientNonFixedInputSize; i++ {
		idx := int(binary.BigEndian.Uint16(idxBlob[i*2 : i*2+2]))
		k0 := g.AllNonFixedOT[idx][0]
		k1 := g.AllNonFixedOT[idx][1]
		m0 := c.Il.ClientNonFixed[i*32 : i*32+16]
		m1 := c.Il.ClientNonFixed[i*32+16 : i*32+32]
		e0 := u.Encrypt_generic(m0, k0, 0)
		e1 := u.Encrypt_generic(m1, k1, 0)
		encLabels = append(encLabels, e0...)
		encLabels = append(encLabels, e1...)
	}
	return encLabels
}

//  C_getInputLabels returns notary's input labels for the circuit
func (g *Garbler) C_getInputLabels(cNo int) []byte {
	c := &g.Cs[cNo]
	inputBytes := c.Input

	if (cNo != 6 && len(inputBytes)*8 != c.NotaryInputSize) ||
		(cNo == 6 && len(inputBytes)*8 != 160+128*g.C6Count) {
		log.Println("inputBytes", inputBytes)
		log.Println("len(inputBytes)", len(inputBytes))
		panic("len(inputBytes)*8 != c.NotaryInputSiz")
	}

	input := new(big.Int).SetBytes(inputBytes)
	inputLabelBlob := u.Concat(c.Il.NotaryNonFixed, c.Il.NotaryFixed)
	var inputLabels []byte
	for i := 0; i < len(inputBytes)*8; i++ {
		bit := int(input.Bit(i))
		label := inputLabelBlob[i*32+bit*16 : i*32+bit*16+16]
		inputLabels = append(inputLabels, label...)
	}
	return inputLabels
}

func (g *Garbler) ParseCircuit(cNo_ int) *Circuit {
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
	c := Circuit{}
	wireCount, _ := strconv.ParseInt(strings.Split(lines[0], " ")[1], 10, 32)
	gi, _ := strconv.ParseInt(strings.Split(lines[1], " ")[1], 10, 32)
	ei, _ := strconv.ParseInt(strings.Split(lines[1], " ")[2], 10, 32)
	out, _ := strconv.ParseInt(strings.Split(lines[2], " ")[1], 10, 32)

	c.WireCount = int(wireCount)
	c.GarblerInputSize = int(gi)
	c.EvaluatorInputSize = int(ei)
	c.OutputSize = int(out)

	gates := make([]Gate, len(lines)-3)
	andGateCount := 0
	opBytes := map[string]byte{"XOR": 0, "AND": 1, "INV": 2}

	for i, line := range lines[3:] {
		items := strings.Split(line, " ")
		var g Gate
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

// garble a circuit and optionally reuse 1 ) R values 2) inputs with indexes
func (g *Garbler) OfflinePhase(c *Circuit, rReused []byte, inputsReused []byte, reuseIndexes []int) (*[]byte, []byte, []byte, []byte) {
	var R []byte
	if rReused != nil {
		R = rReused
	} else {
		R = make([]byte, 16)
		rand.Read(R)
		//R = u.GetRandom(16)
		R[15] = R[15] | 0x01
	}

	if len(reuseIndexes) != len(inputsReused)/32 {
		panic("len(reuseIndexes) != len(ilReused)/32")
	}

	inputCount := c.EvaluatorInputSize + c.GarblerInputSize
	//garbled assignment
	ga := make([][][]byte, c.WireCount)
	newInputs := generateInputLabels(inputCount-len(reuseIndexes), R)

	// set both new and reused labels into ga
	reusedCount := 0    //how many reused inputs were already put into ga
	newInputsCount := 0 //how many new inputs were already put into ga
	for i := 0; i < inputCount; i++ {
		if u.Contains(i, reuseIndexes) {
			ga[i] = [][]byte{
				inputsReused[reusedCount*32 : reusedCount*32+16],
				inputsReused[reusedCount*32+16 : reusedCount*32+32]}
			reusedCount += 1
		} else {
			ga[i] = (*newInputs)[newInputsCount]
			newInputsCount += 1
		}
	}

	andGateCount := c.AndGateCount
	//log.Println("andGateCount is", andGateCount)
	truthTable := make([]byte, andGateCount*64)
	garble(c, &ga, R, &truthTable)
	if len(ga) != c.WireCount {
		panic("len(*ga) != c.wireCount")
	}

	var inputLabels []byte
	for i := 0; i < inputCount; i++ {
		inputLabels = append(inputLabels, ga[i][0]...)
		inputLabels = append(inputLabels, ga[i][1]...)
	}
	var outputLabels []byte
	for i := 0; i < c.OutputSize; i++ {
		outputLabels = append(outputLabels, ga[c.WireCount-c.OutputSize+i][0]...)
		outputLabels = append(outputLabels, ga[c.WireCount-c.OutputSize+i][1]...)
	}
	return &truthTable, inputLabels, outputLabels, R
}

func generateInputLabels(count int, R []byte) *[][][]byte {
	newLabels := make([][][]byte, count)
	for i := 0; i < count; i++ {
		label1 := make([]byte, 16)
		rand.Read(label1)
		label2 := u.XorBytes(label1, R)
		newLabels[i] = [][]byte{label1, label2}
	}
	return &newLabels
}

func garble(c *Circuit, garbledAssignment *[][][]byte, R []byte, truthTable *[]byte) {
	var andGateIdx int = 0

	// gate type XOR==0 AND==1 INV==2
	for i := 0; i < len(c.Gates); i++ {
		gate := c.Gates[i]
		if gate.Operation == 1 {
			tt := garbleAnd(gate, R, garbledAssignment)
			copy((*truthTable)[andGateIdx*64:andGateIdx*64+64], tt[0:64])
			andGateIdx += 1
		} else if gate.Operation == 0 {
			garbleXor(gate, R, garbledAssignment)
		} else if gate.Operation == 2 {
			garbleInv(gate, garbledAssignment)
		}
	}
}

func getPoint(arr []byte) int {
	return int(arr[15]) & 0x01
}

func garbleAnd(g Gate, R []byte, ga *[][][]byte) []byte {
	in1 := g.InputWires[0]
	in2 := g.InputWires[1]
	out := g.OutputWire

	randomLabel := make([]byte, 16)
	rand.Read(randomLabel)

	(*ga)[out] = [][]byte{randomLabel, u.XorBytes(randomLabel, R)}

	v0 := u.Encrypt((*ga)[in1][0], (*ga)[in2][0], g.Id, (*ga)[out][0])
	v1 := u.Encrypt((*ga)[in1][0], (*ga)[in2][1], g.Id, (*ga)[out][0])
	v2 := u.Encrypt((*ga)[in1][1], (*ga)[in2][0], g.Id, (*ga)[out][0])
	v3 := u.Encrypt((*ga)[in1][1], (*ga)[in2][1], g.Id, (*ga)[out][1])

	p0 := 2*getPoint((*ga)[in1][0]) + getPoint((*ga)[in2][0])
	p1 := 2*getPoint((*ga)[in1][0]) + getPoint((*ga)[in2][1])
	p2 := 2*getPoint((*ga)[in1][1]) + getPoint((*ga)[in2][0])
	p3 := 2*getPoint((*ga)[in1][1]) + getPoint((*ga)[in2][1])

	truthTable := make([][]byte, 4)
	truthTable[p0] = v0
	truthTable[p1] = v1
	truthTable[p2] = v2
	truthTable[p3] = v3

	var flatTable []byte
	for i := 0; i < 4; i++ {
		flatTable = append(flatTable, truthTable[i]...)
	}

	return flatTable
}

func garbleXor(g Gate, R []byte, ga *[][][]byte) {
	in1 := g.InputWires[0]
	in2 := g.InputWires[1]
	out := g.OutputWire

	out1 := u.XorBytes((*ga)[in1][0], (*ga)[in2][0])
	out2 := u.XorBytes(u.XorBytes((*ga)[in1][1], (*ga)[in2][1]), R)
	(*ga)[out] = [][]byte{out1, out2}
}

func garbleInv(g Gate, ga *[][][]byte) {
	in1 := g.InputWires[0]
	out := g.OutputWire

	(*ga)[out] = [][]byte{(*ga)[in1][1], (*ga)[in1][0]}
}
