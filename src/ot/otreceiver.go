package ot

import (
	u "notary/utils"

	"github.com/bwesterb/go-ristretto"
)

type OTReceiver struct {
	extraOT               int
	otCount               int
	totalOT               int
	seedShare             []byte
	rBits                 []int
	T0                    [][]byte
	T1                    [][]byte
	a                     *ristretto.Scalar
	A                     *ristretto.Point
	RT0                   []byte
	receivedSoFar         int
	expectingResponseSize int
}

func (o *OTReceiver) Init(otCount int) {
	o.otCount = otCount
	o.extraOT = 256
	o.totalOT = (otCount+7)/8*8 + o.extraOT
}

func (o *OTReceiver) SetupStep1() ([]byte, []byte) {
	o.seedShare = u.GetRandom(16)
	seedCommit := u.Sha256(o.seedShare)
	r := u.GetRandom(o.totalOT / 8)
	R := extend_r(r)
	o.rBits = u.Reverse(u.BytesToBits(r))
	o.T0, o.T1 = secretShareMatrix(R)
	o.a = new(ristretto.Scalar).Rand()
	o.A = new(ristretto.Point).ScalarMultBase(o.a)
	return o.A.Bytes(), seedCommit
}

func (o *OTReceiver) SetupStep2(allBsBlob, senderSeedShare []byte) ([]byte, []byte, []byte, []byte) {
	// compute key_0 and key_1 for each B of the base OT
	if (len(allBsBlob) != 128*32) || (len(senderSeedShare) != 16) {
		panic("len(allBsBlob) != 128*32")
	}
	encrKeys := make([][][]byte, 128)
	for i := 0; i < 128; i++ {
		B_ := allBsBlob[i*32 : (i+1)*32]
		var tmp [32]byte
		copy(tmp[:], B_)
		B := new(ristretto.Point)
		B.SetBytes(&tmp)
		k0 := u.Generichash(16, new(ristretto.Point).ScalarMult(B, o.a).Bytes())
		sub := new(ristretto.Point).Sub(B, o.A)
		k1 := u.Generichash(16, new(ristretto.Point).ScalarMult(sub, o.a).Bytes())
		encrKeys[i] = [][]byte{k0, k1}
	}
	// Use the i-th k0 to encrypt the i-th column in T0, likewise
	// use the i-th k1 to encrypt the i-th column in T1
	T0columns := transposeMatrix(o.T0)
	T1columns := transposeMatrix(o.T1)
	encryptedColumns := make([][]byte, 256)
	for i := 0; i < 128; i++ {
		encryptedColumns[i*2] = u.AESCTRencrypt(encrKeys[i][0], T0columns[i])
		encryptedColumns[i*2+1] = u.AESCTRencrypt(encrKeys[i][1], T1columns[i])
	}

	// KOS15 kicks in at this point to check if Receiver sent the correct columnsArray
	// combine seed shares and expand the seed
	seed := u.XorBytes(o.seedShare, senderSeedShare)
	expandedSeed := expandSeed(seed, o.totalOT)
	// Bob multiplies every 128-bit row of matrix T1 with the corresponding random
	// value in expandedSeed and XORs the products.
	// Bob multiplies every bit of r with the corresponding random
	// value in expandedSeed and XORs the products.
	// Bob sends seed,x,t to Alice
	x := make([]byte, 16)
	t := make([]byte, 32)
	for i := 0; i < len(o.T0); i++ {
		rand := expandedSeed[i*16 : (i+1)*16]
		if o.rBits[i] == 1 {
			x = u.XorBytes(x, rand)
		}
		t = u.XorBytes(t, clmul128(o.T0[i], rand))
	}
	// we need to break correlations between Q0 and Q1
	// The last extraOTs were sacrificed as part of the KOS15 protocol
	// and so we don't need them anymore
	o.RT0 = breakCorrelation(o.T0[0 : len(o.T0)-o.extraOT])
	// also drop the unneeded bytes and bits of r
	o.rBits = o.rBits[0 : len(o.rBits)-o.extraOT]

	// now we have instances of Random OT where depending on r's bit,
	// each row in RT0 equals to a row either in RQ0 or RQ1
	// use Beaver Derandomization [Beaver91] to convert randomOT into standardOT
	return u.Concat(encryptedColumns...), o.seedShare, x, t
}

// CreateRequest creates a request for OT for the choice bits.
func (o *OTReceiver) CreateRequest(choiceBits []int) []byte {
	if o.receivedSoFar+len(choiceBits) > o.otCount {
		panic("o.receivedSoFar + len(bitsArr) > o.otCount")
	}
	if o.expectingResponseSize != 0 {
		panic("The previous request must be processed before requesting more OTs.")
	}
	// for Beaver Derandomization, tell the Sender which masks to flip: 0 means
	// no flip needed, 1 means a flip is needed
	// pad the bitcount to a multiple of 8
	dropCount := 0
	if len(choiceBits)%8 > 0 {
		dropCount = 8 - len(choiceBits)%8
	}
	bitsToFlip := make([]int, len(choiceBits)+dropCount)
	for i := 0; i < len(choiceBits); i++ {
		bitsToFlip[i] = choiceBits[i] ^ o.rBits[o.receivedSoFar+i]
	}
	for i := 0; i < dropCount; i++ {
		bitsToFlip[len(choiceBits)+i] = 0
	}
	o.expectingResponseSize = len(choiceBits)
	// prefix with the amount of bits that Sender needs to drop
	// in cases when bitsArr.length is not a multiple of 8
	return u.Concat([]byte{byte(dropCount)}, u.BitsToBytes(bitsToFlip))
}

// ParseResponse parses (i.e. decodes) the OT response from the OT sender and
// returns the plaintext result of OT.
// For every choice bit, it unmasks one of the two 16-byte messages.
func (o *OTReceiver) ParseResponse(choiceBits []int, encodedOT []byte) []byte {
	if (o.expectingResponseSize != len(choiceBits)) ||
		(o.expectingResponseSize*32 != len(encodedOT)) {
		panic("o.expectingResponseSize issue")
	}
	decodedArr := make([][]byte, len(choiceBits))
	for i := 0; i < len(choiceBits); i++ {
		mask := o.RT0[(o.receivedSoFar+i)*16 : (o.receivedSoFar+i)*16+16]
		m0 := encodedOT[i*32 : i*32+16]
		m1 := encodedOT[i*32+16 : i*32+32]
		if choiceBits[i] == 0 {
			decodedArr[i] = u.XorBytes(m0, mask)
		} else {
			decodedArr[i] = u.XorBytes(m1, mask)
		}
	}
	o.receivedSoFar += len(choiceBits)
	o.expectingResponseSize = 0
	return u.Concat(decodedArr...)
}
