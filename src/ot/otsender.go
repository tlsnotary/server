package ot

import (
	"bytes"
	"log"
	u "notary/utils"

	"github.com/bwesterb/go-ristretto"
)

// OTSender implements the sender of the Oblivious Transfer acc.to.
// the KOS15 protocol
type OTSender struct {
	extraOT   int
	otCount   int
	TotalOT   int
	s         []byte
	sBits     []int
	decrKeys  [][]byte
	rQ0       []byte
	rQ1       []byte
	sentSoFar int
	hisCommit []byte
	seedShare []byte
}

func (o *OTSender) Init(otCount int) {
	o.otCount = otCount
	o.extraOT = 256
	o.TotalOT = (otCount+7)/8*8 + o.extraOT
}

func (o *OTSender) SetupStep1(A_, hisCommit []byte) ([]byte, []byte) {
	var tmp [32]byte
	copy(tmp[:], A_)
	A := new(ristretto.Point)
	ok := A.SetBytes(&tmp)
	if !ok {
		panic("could not set A")
	}
	o.hisCommit = hisCommit
	o.seedShare = u.GetRandom(16)
	// compute Bs and decryption keys of the base OT for each bit in S
	o.s = u.GetRandom(16)
	o.sBits = u.Reverse(u.BytesToBits(o.s))
	allBs := make([][]byte, len(o.sBits))
	o.decrKeys = make([][]byte, len(o.sBits))
	for i, bit := range o.sBits {
		b := new(ristretto.Scalar).Rand()
		B := new(ristretto.Point).ScalarMultBase(b)
		if bit == 1 {
			tmp2 := new(ristretto.Point).Add(A, B)
			B = tmp2
		}
		k := u.Generichash(16, new(ristretto.Point).ScalarMult(A, b).Bytes())
		o.decrKeys[i] = k
		allBs[i] = B.Bytes()
	}
	return u.Concat(allBs...), o.seedShare
}

func (o *OTSender) SetupStep2(encryptedColumnsBlob, receiverSeedShare, x, t []byte) {
	if len(receiverSeedShare) != 16 {
		panic("len(receiverSeedShare) != 16")
	}
	if len(encryptedColumnsBlob)%256 != 0 {
		panic("len(encryptedColumnsBlob) % 256 != 0")
	}
	encryptedColumns := make([][]byte, 256)
	columnSize := len(encryptedColumnsBlob) / 256
	for i := 0; i < 256; i++ {
		encryptedColumns[i] = encryptedColumnsBlob[i*columnSize : (i+1)*columnSize]
	}
	// Decrypt only those columns which correspond to S's bit
	columns := make([][]byte, 128)
	for i := 0; i < 128; i++ {
		col0 := encryptedColumns[i*2]
		col1 := encryptedColumns[i*2+1]
		if o.sBits[i] == 0 {
			columns[i] = u.AESCTRdecrypt(o.decrKeys[i], col0)
		} else {
			columns[i] = u.AESCTRdecrypt(o.decrKeys[i], col1)
		}
	}
	Q0 := transposeMatrix(columns)

	// KOS15: Alice multiplies every 128-bit row of matrix Q1 with the corresponding random
	// value in expandedSeed and XORs the products
	if !bytes.Equal(u.Sha256(receiverSeedShare), o.hisCommit) {
		panic("Bad seed commit")
	}
	seed := u.XorBytes(receiverSeedShare, o.seedShare)
	expandedSeed := expandSeed(seed, o.TotalOT)
	q := make([]byte, 32) // set q to 0
	for i := 0; i < len(Q0); i++ {
		rand := expandedSeed[i*16 : (i+1)*16]
		q = u.XorBytes(q, clmul128(Q0[i], rand))
	}
	// Alice checks that t = q xor x * S
	log.Println("done")
	if !bytes.Equal(t, u.XorBytes(q, clmul128(x, o.s))) {
		panic("KOS15 consistency check failed")
	}
	// Alice xors each row of Q0 with S to get Q1
	Q1 := make([][]byte, len(Q0))
	for i := 0; i < len(Q0); i++ {
		Q1[i] = u.XorBytes(Q0[i], o.s)
	}

	// we need to break correlations between Q0 and Q1
	// The last extraOTs were sacrificed as part of the KOS15 protocol
	// and so we don't need them anymore
	o.rQ0 = breakCorrelation(Q0[0 : len(Q0)-o.extraOT])
	o.rQ1 = breakCorrelation(Q1[0 : len(Q1)-o.extraOT])
	// now we have instances of Random OT where depending on r's bit,
	// each row in RT0 equals to a row either in RQ0 or RQ1

	// when processing OT request, we will use Beaver Derandomization to convert
	// randomOT into standardOT
}

// ProcessRequest processes a request for OT from the OT receiver.
// otRequest contains bits which need to be flipped acc.to the Beaver derandomiation
// method. The Sender has two 16-byte messages for 1-of-2 OT and
// two random masks (from the KOS15 protocol) r0 and r1.
// If the bit to flip is 0, the Sender sends (m0 xor r0) and (m1 xor r1).
// If the bit to flip is 1, the Sender sends (m0 xor r1) and (m1 xor r0).
// Returns an OT response.
func (o *OTSender) ProcessRequest(otRequest, messages []byte) []byte {
	dropCount := int(otRequest[0])
	bitsToFlipWithRem := u.BytesToBits(otRequest[1:])
	bitsToFlip := bitsToFlipWithRem[:len(bitsToFlipWithRem)-dropCount]
	if o.sentSoFar+len(bitsToFlip) > o.otCount {
		panic("o.sentSoFar + len(bitsToFlip) > o.otCount")
	}
	if len(bitsToFlip)*32 != len(messages) {
		panic("len(bitsToFlip)*32 != len(messages)")
	}
	var encodedToSend []byte
	for i := 0; i < len(bitsToFlip); i++ {
		m0 := messages[i*32 : i*32+16]
		m1 := messages[i*32+16 : i*32+32]
		r0 := o.rQ0[(o.sentSoFar+i)*16 : (o.sentSoFar+i)*16+16]
		r1 := o.rQ1[(o.sentSoFar+i)*16 : (o.sentSoFar+i)*16+16]
		if bitsToFlip[i] == 0 {
			encodedToSend = append(encodedToSend, u.XorBytes(m0, r0)...)
			encodedToSend = append(encodedToSend, u.XorBytes(m1, r1)...)
		} else {
			encodedToSend = append(encodedToSend, u.XorBytes(m0, r1)...)
			encodedToSend = append(encodedToSend, u.XorBytes(m1, r0)...)
		}
	}
	o.sentSoFar += len(bitsToFlip)
	return encodedToSend
}
