package ghash

import (
	"log"
	"math/big"
	u "notary/utils"
)

// Protocol to compute AES-GCM's GHASH function in 2PC using Oblivious Transfer
// https://tlsnotary.org/how_it_works#section4
// (4. Computing MAC of the request using Oblivious Transfer.)

// GHASH implement the 2PC protocol to compute GHASH using OT
type GHASH struct {
	// P (p stands for Powers) contains notary's share for each power of H.
	// These are powers used to compute MACs/tags on client's requests.
	P [][]byte
	// maxPowerNeeded is the max power of H that client needs. This equals the
	// amount of AES blocks + 2
	maxPowerNeeded int
	// if we compute all sequential shares of powers from 1 up to and including
	// maxOddPowerNeeded, we can start computing the MAC using the Block
	// Aggregation method.
	maxOddPowerNeeded int
	// maxHTable and strategies are initialized in Init(). See comments there.
	maxHTable []int
	strategy1 [][]int
	strategy2 [][]int
}

func (g *GHASH) Init() {
	g.P = make([][]byte, 1027) //starting with 1, 1026 is the max that we'll ever need

	// maxHTable's <value> shows how many GHASH blocks can be processed
	// with Block Aggregation if we have all the sequential shares
	// starting with 1 up to and including <key>.
	// e.g. {5:29} means that if we have shares of H^1,H^2,H^3,H^4,H^5,
	// then we can process 29 GHASH blocks.
	// max TLS record size of 16KB requires 1026 GHASH blocks
	g.maxHTable = []int{
		0: 0, 3: 19, 5: 29, 7: 71, 9: 89, 11: 107, 13: 125, 15: 271, 17: 305, 19: 339, 21: 373,
		23: 407, 25: 441, 27: 475, 29: 509, 31: 1023, 33: 1025, 35: 1027}

	// shows what shares of powers we will be multiplying to obtain other odd shares of powers
	// max sequential odd power that we can obtain during the first round of communication is 19
	// note that we multiply N_x*C_y and C_y*N_x to get cross-terms. These are not yet shares of powers
	// we must add N_x*N_y and C_x*C_y to respective cross-terms in order to get shares of powers
	g.strategy1 = [][]int{
		5:  {4, 1},
		7:  {4, 3},
		9:  {8, 1},
		11: {8, 3},
		13: {12, 1},
		15: {12, 3},
		17: {16, 1},
		19: {16, 3}}
	g.strategy2 = [][]int{
		21: {17, 4},
		23: {17, 6},
		25: {17, 8},
		27: {19, 8},
		29: {17, 12},
		31: {19, 12},
		33: {17, 16},
		35: {19, 16}}
}

// countPowersToBeMultiplied computes how many consequtive odd powers we need.
// Returns how many block multiplications are needed to obtain those odd powers.
func (g *GHASH) CountPowersToBeMultiplied() int {
	totalBlockMult := 0
	for k, v := range g.strategy1 {
		if v == nil {
			continue
		}
		if k > g.maxOddPowerNeeded {
			break
		}
		totalBlockMult += 2
	}
	log.Println("totalBlockMult", totalBlockMult)
	return totalBlockMult
}

// StepCommon is common to Step1 and Step2, they only differ in the strategy
// used. Notary returns masked xTable for shares of powers based on the strategy
func (g *GHASH) stepCommon(strategy *[][]int) []byte {
	var allEntries []byte
	for k, v := range *strategy {
		if v == nil {
			continue
		}
		if k > g.maxOddPowerNeeded {
			break
		}
		entries1, maskSum1 := GetMaskedXTable(g.P[v[1]])
		entries2, maskSum2 := GetMaskedXTable(g.P[v[0]])
		allEntries = append(allEntries, entries1...)
		allEntries = append(allEntries, entries2...)

		// get notary's N_x*N_y and then get the final share of power
		NxNy := BlockMult(g.P[v[0]], g.P[v[1]])
		g.P[k] = u.XorBytes(u.XorBytes(maskSum1, maskSum2), NxNy)
	}
	FreeSquare(&g.P, g.maxPowerNeeded)
	return allEntries
}

func (g *GHASH) Step1() []byte {
	//perform free squaring on powers 2,3 which we have from client finished
	FreeSquare(&g.P, g.maxPowerNeeded)
	return g.stepCommon(&g.strategy1)
}

func (g *GHASH) Step2() []byte {
	return g.stepCommon(&g.strategy2)
}

// in Step3 we multiply GHASH block by those shares of powers which we have.
// For those which we don't have, we perform Block Aggregation.
// Returns 1) Notary's share of GHASH output 2) masked xTables 3) count of block
// multiplications which we performed during Block Aggregation.
func (g *GHASH) Step3(ghashInputs [][]byte) ([]byte, []byte, int) {
	u.Assert(len(ghashInputs) == g.maxPowerNeeded)
	res := make([]byte, 16)

	// compute direct powers
	// L is the total count of GHASH blocks. n is the index of the input block
	// starting from 0. We multiply GHASH input block X[n] by power H^(L-n).
	for i := 1; i < len(g.P); i++ {
		if i > g.maxPowerNeeded {
			break
		}
		if g.P[i] == nil {
			continue
		}
		x := ghashInputs[len(ghashInputs)-i]
		h := g.P[i]
		res = u.XorBytes(res, BlockMult(h, x))
	}

	// Block Aggregation

	// aggregated <key> -> small power, <value> -> aggregated value for that small power
	aggregated := make([][]byte, 36) //starting with 1, 35 is the max that we'll ever need
	for i := 1; i < len(g.P); i++ {
		if i > g.maxPowerNeeded {
			break
		}
		if g.P[i] != nil {
			continue
		}
		// found a hole in our sparse array, need block aggregation
		// a is the smaller power
		a, b := FindSum(&g.P, i)
		x := ghashInputs[len(ghashInputs)-i]
		// locally compute a*b*x
		res = u.XorBytes(res, BlockMult(BlockMult(g.P[a], g.P[b]), x))
		if aggregated[a] == nil {
			aggregated[a] = make([]byte, 16) //set to zero
		}
		aggregated[a] = u.XorBytes(aggregated[a], BlockMult(g.P[b], x))
	}
	ghashOutputShare := res

	// arrange masked Xtable entries for each entry in aggregated:
	// first the Xtable for share of the small power,
	// then the Xtable for the aggregated value.
	var allEntries []byte
	maskSum := make([]byte, 16) //starting with zeroed mask
	for i := 0; i < len(aggregated); i++ {
		if aggregated[i] == nil {
			continue
		}
		entries1, maskSum1 := GetMaskedXTable(g.P[i])
		entries2, maskSum2 := GetMaskedXTable(aggregated[i])
		allEntries = append(allEntries, entries1...)
		allEntries = append(allEntries, entries2...)
		maskSum = u.XorBytes(maskSum, u.XorBytes(maskSum1, maskSum2))
	}
	ghashOutputShare = u.XorBytes(ghashOutputShare, maskSum)

	nonNilItemsCount := 0
	for i := 0; i < len(aggregated); i++ {
		if aggregated[i] != nil {
			nonNilItemsCount += 1
		}
	}

	return ghashOutputShare, allEntries, nonNilItemsCount * 2
}

func (g *GHASH) GetMaxPowerNeeded() int {
	return g.maxPowerNeeded
}

func (g *GHASH) GetMaxOddPowerNeeded() int {
	return g.maxOddPowerNeeded
}

// set max power of H that is needed and calculate max odd power needed based
// on g.maxHTable
func (g *GHASH) SetMaxPowerNeeded(max int) {
	g.maxPowerNeeded = max
	for k, v := range g.maxHTable {
		if v >= g.maxPowerNeeded {
			g.maxOddPowerNeeded = k
			log.Println("maxPowerNeeded", g.maxPowerNeeded)
			log.Println("maxOddPowerNeeded", g.maxOddPowerNeeded)
			break
		}
	}
}

// FreeSquare locally squares all powers found in powersOfH up to and including
// maxPowerNeeded. Modifies powersOfH in place.
func FreeSquare(powersOfH *[][]byte, maxPowerNeeded int) {
	for i := 0; i < len(*powersOfH); i++ {
		if (*powersOfH)[i] == nil || i%2 == 0 {
			continue
		}
		if i > maxPowerNeeded {
			return
		}
		power := i
		for power < maxPowerNeeded {
			power = power * 2
			if (*powersOfH)[power] != nil {
				continue
			}
			prevPower := (*powersOfH)[power/2]
			(*powersOfH)[power] = BlockMult(prevPower, prevPower)
		}
	}
}

// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial
func BlockMult(x_, y_ []byte) []byte {
	x := new(big.Int).SetBytes(x_)
	y := new(big.Int).SetBytes(y_)
	res := big.NewInt(0)
	_1 := big.NewInt(1)
	R, ok := new(big.Int).SetString("E1000000000000000000000000000000", 16)
	if !ok {
		panic("SetString")
	}
	for i := 127; i >= 0; i-- {
		tmp1 := new(big.Int).Rsh(y, uint(i))
		tmp2 := new(big.Int).And(tmp1, _1)
		res.Xor(res, new(big.Int).Mul(x, tmp2))
		tmp3 := new(big.Int).And(x, _1)
		tmp4 := new(big.Int).Mul(tmp3, R)
		tmp5 := new(big.Int).Rsh(x, 1)
		x = new(big.Int).Xor(tmp5, tmp4)
	}
	return u.To16Bytes(res)
}

// return a table of byte values of x after each of the 128 rounds of BlockMult
func GetXTable(xBytes []byte) [][]byte {
	x := new(big.Int).SetBytes(xBytes)
	_1 := big.NewInt(1)
	R, ok := new(big.Int).SetString("E1000000000000000000000000000000", 16)
	if !ok {
		panic("SetString")
	}
	xTable := make([][]byte, 128)
	for i := 0; i < 128; i++ {
		xTable[i] = u.To16Bytes(x)
		tmp3 := new(big.Int).And(x, _1)
		tmp4 := new(big.Int).Mul(tmp3, R)
		tmp5 := new(big.Int).Rsh(x, 1)
		x = new(big.Int).Xor(tmp5, tmp4)
	}
	return xTable
}

// FindSum decomposes a sum into non-zero summands. The first summand is repeatedly
// incremented until a suitable second summand is found. Both summands must be
// in the array.
func FindSum(array *[][]byte, sum int) (int, int) {
	for i := 0; i < len(*array); i++ {
		if (*array)[i] == nil {
			continue
		}
		for j := 0; j < len(*array); j++ {
			if (*array)[j] == nil {
				continue
			}
			if i+j == sum {
				return i, j
			}
		}
	}
	// this should never happen because we always call
	// findSum() knowing that the sum can be found
	panic("sum not found")
}

// getMaskedXTable returns a masked xTable from which OT response will
// be constructed and the XOR-sum of all masks. A masked xTable replaces
// each entry of xTable with 2 16-byte values: 1) a mask and 2) the xTable
// entry masked with the mask.
func GetMaskedXTable(powerShare []byte) ([]byte, []byte) {
	xTable := GetXTable(powerShare)

	// maskSum is the xor sum of all masks
	maskSum := make([]byte, 16)

	var allMessages []byte
	for i := 0; i < 128; i++ {
		mask := u.GetRandom(16)
		maskSum = u.XorBytes(maskSum, mask)
		m0 := mask
		m1 := u.XorBytes(xTable[i], mask)
		allMessages = append(allMessages, m0...)
		allMessages = append(allMessages, m1...)
	}

	return allMessages, maskSum
}
