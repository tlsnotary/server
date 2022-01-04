// Methods used by both OTSender and OTReceiver

package ot

import (
	"encoding/binary"
	"math/big"
	u "notary/utils"

	"golang.org/x/crypto/salsa20/salsa"
)

// extend r (Uint8Array) into a matrix of 128 columns where depending on r's bit, each row
// is either all 0s or all 1s
func extend_r(r []byte) [][]byte {
	// 128 bits all set to 1
	all_1 := []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	// 128 bits all set to 0
	all_0 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var matrix [][]byte
	bits := u.Reverse(u.BytesToBits(r))
	for _, bit := range bits {
		if bit == 0 {
			matrix = append(matrix, all_0)
		} else {
			matrix = append(matrix, all_1)
		}
	}
	return matrix
}

// given a matrix, output 2 xor shares of it
func secretShareMatrix(matrix [][]byte) ([][]byte, [][]byte) {
	var T0 [][]byte
	var T1 [][]byte
	for _, row := range matrix {
		rand := u.GetRandom(16)
		T0 = append(T0, rand)
		T1 = append(T1, u.XorBytes(row, rand))
	}
	return T0, T1
}

// transpose a matrix of bits. matrix is an array of rows (each row is a Uin8Array)
func transposeMatrix(matrix [][]byte) [][]byte {
	colCount := len(matrix[0]) * 8
	rowCount := len(matrix)
	if colCount != 128 && rowCount != 128 {
		panic("colCount != 128 && rowCount != 128")
	}
	newRows := make([][]byte, colCount)
	for j := 0; j < colCount; j++ {
		// in which byte of the column is j located
		byteNo := j >> 3 //Math.floor(j / 8);
		// what is the index of j inside the byte
		bitIdx := j % 8
		newRowBits := make([]int, rowCount)
		for i := 0; i < rowCount; i++ {
			newRowBits[i] = int((matrix[i][byteNo] >> (7 - bitIdx)) & 1)
		}
		newRows[j] = u.BitsToBytes(u.Reverse(newRowBits))
	}
	return newRows
}

// pseudorandomly expands a 16-byte seed into a bytestring of bytesize "count"*16
// to benefit from AES-NI, we use browser WebCrypto's AES-CTR: with seed as the key
// we encrypt an all-zero bytestring.
func expandSeed(seed []byte, count int) []byte {
	if len(seed) != 16 {
		panic("len(seed) != 16")
	}
	zeroBytes := make([]byte, count*16)
	return u.AESCTRencrypt(seed, zeroBytes)
}

// encrypt each 16-byte chunk of msg with a fixed-key Salsa20
func fixedKeyCipher(msg []byte) []byte {
	if len(msg)%16 != 0 {
		panic("len(msg) % 16 != 0")
	}
	fixedKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	chunkCount := len(msg) / 16
	var allOut []byte
	for i := 0; i < chunkCount; i++ {
		out := make([]byte, 16) // zero bytes
		var msgArray [16]byte
		copy(msgArray[:], msg[i*16:(i+1)*16])
		// will run Salsa20(fixedKey, msgArray), then xor the result with the 2nd arg
		// and output the result into the 1st arg
		salsa.XORKeyStream(out, out, &msgArray, &fixedKey)
		allOut = append(allOut, out...)
	}
	return allOut
}

// to break the correlation, KOS15 needs a hash function which has tweakable correlation
// robustness (tcr). GKWY20 shows (Section 7.4) how to achieve tcr using a fixed-key cipher C
// instead of a hash, i.e. instead of Hash(x, i) we can do C(C(x) xor i) xor C(x)
func breakCorrelation(rows [][]byte) []byte {
	if len(rows[0]) != 16 {
		panic("len(rows[0]) != 16")
	}
	AESx := fixedKeyCipher(u.Concat(rows...))
	var indexes []byte
	for i := 0; i < len(rows); i++ {
		intBytes := make([]byte, 16)
		binary.BigEndian.PutUint64(intBytes[8:16], uint64(i))
		indexes = append(indexes, intBytes...)
	}
	return u.XorBytes(fixedKeyCipher(u.XorBytes(AESx, indexes)), AESx)
}

func BreakCorrelation(rows [][]byte) []byte {
	return breakCorrelation(rows)
}

// carry-less multiplication (i.e. multiplication in galois field) without reduction.
// Let a's right-most bit have index 0. Then for every bit set in a, b is left-shifted
// by the set bit's index value. All the left-shifted values are then XORed.

// this is a port of the unoptimized JS version (clmul128_unoptimized).
// TODO: There may be golang optimizations to make this significantly faster
func clmul128(a, b []byte) []byte {
	if len(a) != 16 || len(b) != 16 {
		panic("a or b are not 16 bytes")
	}
	aBits := u.BytesToBits(a) // is it faster if turned to bits rather than shift each time?
	b_bi := new(big.Int).SetBytes(b)
	res := big.NewInt(0)
	for i := 0; i < 128; i++ {
		if aBits[i] == 1 { // a's bit is set
			res.Xor(res, new(big.Int).Lsh(b_bi, uint(i)))
		}
	}
	return u.To32Bytes(res)
}

func Clmul128(a, b []byte) []byte {
	return clmul128(a, b)
}
