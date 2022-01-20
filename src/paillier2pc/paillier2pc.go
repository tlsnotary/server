package paillier2pc

import (
	ec "crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	u "notary/utils"

	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

// Protocol to compute EC point addition in Paillier as described here:
// https://tlsnotary.org/how_it_works#section1
// The code uses the same notation as in the link above. The code must be read
// alongside the writeup.

// Paillier2PC implements the notary's side of computing an EC point
// addition in 2PC
type Paillier2PC struct {
	p256 ec.Curve
	// d_n is notary's share of the EC private key
	d_n *big.Int
	// Q_nx, Q_ny are notary's shares of the EC public key
	Q_nx, Q_ny *big.Int
	// paillierPrivKey is used to decrypt 2PC messages from client
	// it also contains a public key used to encrypt 2PC message to the client
	paillierPrivKey *paillier.PrivateKey
	// constant numbers
	Zero, One, Two, Three *big.Int
	// P is curve P-256's Field prime
	P *big.Int
}

func (p *Paillier2PC) Init() {
	p.Zero = big.NewInt(0)
	p.One = big.NewInt(1)
	p.Two = big.NewInt(2)
	p.Three = big.NewInt(3)
	p.p256 = ec.P256()
	p.P = p.p256.Params().P
	// we need an int in range [1, N-1]
	nMinusOne := sub(p.p256.Params().N, p.One)
	randInt, err := rand.Int(rand.Reader, nMinusOne) //returns range [0, max)
	if err != nil {
		panic("crypto random error")
	}
	// N picks a random private key share d_n
	p.d_n = add(randInt, p.One)
	// and computes a public key share Q_n = d_n * G
	p.Q_nx, p.Q_ny = p.p256.ScalarBaseMult(p.d_n.Bytes())
	for {
		// double-check that n has 1536 bits
		p.paillierPrivKey, _ = paillier.GenerateKey(rand.Reader, 1536)
		if len(p.paillierPrivKey.PublicKey.N.Bytes()) == 192 {
			break
		}
		log.Println("n is not 1536 bits")
	}
}

func (p *Paillier2PC) Step1(payload []byte) ([]byte, []byte) {
	type Step1 struct {
		Q_bx string
		Q_by string
	}
	var step1 Step1
	json.Unmarshal([]byte(string(payload)), &step1)

	// C passes Q_b to N
	serverX := h2bi(step1.Q_bx)
	serverY := h2bi(step1.Q_by)
	serverPubkey := u.Concat([]byte{0x04}, u.To32Bytes(serverX), u.To32Bytes(serverY))
	// N computes an EC point (x_q, y_q) = d_n * Q_b
	x_q, y_q := p.p256.ScalarMult(serverX, serverY, p.d_n.Bytes())
	// 1.2.1
	Ex_q := p.encrypt(x_q.Bytes())
	// Enx_q is encrypted negative x_q which N sends in 1.3.1
	// (but we send it right now to make code easier)
	nx_q := sub(p.P, x_q)
	Enx_q := p.encrypt(nx_q.Bytes())
	// 1.1.1
	y_q2 := exp(y_q, p.Two, p.P)
	// n2y_q is -2*y_q mod p == p - 2*yq
	n2y_q := mod(sub(p.P, mul(y_q, p.Two)), p.P)
	Ey_q2 := p.encrypt(y_q2.Bytes())
	En2y_q := p.encrypt(n2y_q.Bytes())

	json := `{"Ex_q":"` + hex.EncodeToString(Ex_q) + `",
				 "Enx_q":"` + hex.EncodeToString(Enx_q) + `",
				 "Ey_q2":"` + hex.EncodeToString(Ey_q2) + `",
				 "Pn2yq":"` + hex.EncodeToString(En2y_q) + `",
				 "n":"` + hex.EncodeToString(p.paillierPrivKey.PublicKey.N.Bytes()) + `",
				 "g":"` + hex.EncodeToString(p.paillierPrivKey.PublicKey.G.Bytes()) + `",
				 "Q_nx":"` + hex.EncodeToString(p.Q_nx.Bytes()) + `",
				 "Q_ny":"` + hex.EncodeToString(p.Q_ny.Bytes()) + `"}`

	return serverPubkey, []byte(json)
}

func (p *Paillier2PC) Step2(payload []byte) []byte {
	type Step2 struct {
		E125    string
		N_bmodp string
	}
	var step2 Step2
	json.Unmarshal([]byte(string(payload)), &step2)
	// 1.2.7
	// E125 is the value which C computes in step 1.2.5
	D125_bytes := p.decrypt(h2bi(step2.E125).Bytes())
	D125 := new(big.Int).SetBytes(D125_bytes)
	// 1.2.9
	bM_b := mod(sub(D125, h2bi(step2.N_bmodp)), p.P)
	// 1.2.10
	powMinus3 := sub(p.P, p.Three)
	bM_b_raised := exp(bM_b, powMinus3, p.P)
	E1210 := p.encrypt(bM_b_raised.Bytes())
	json := `{"E1210":"` + hex.EncodeToString(E1210) + `"}`
	return []byte(json)
}

func (p *Paillier2PC) Step3(payload []byte) []byte {
	type Step3 struct {
		E1213   string
		N_Bmodp string
		E114    string
		N_Amodp string
	}
	var step3 Step3
	json.Unmarshal([]byte(string(payload)), &step3)
	// E114 is the value which C computed in Step 1.1.4
	E114, _ := new(big.Int).SetString(step3.E114, 16)
	N_Amodp, _ := new(big.Int).SetString(step3.N_Amodp, 16)
	// 1.2.15
	// E1213 is the value which C computed in Step 1.2.13
	D1213 := new(big.Int).SetBytes(p.decrypt(h2bi(step3.E1213).Bytes()))
	// 1.2.17
	BM_B := mod(sub(D1213, h2bi(step3.N_Bmodp)), p.P)
	// 1.1.6
	D114 := new(big.Int).SetBytes(p.decrypt(E114.Bytes()))
	// 1.1.8
	AM_A := mod(sub(D114, N_Amodp), p.P)
	// 1.3.1 (Nota that E(-x_q) has already been sent)
	E131 := p.encrypt(mod(mul(BM_B, AM_A), p.P).Bytes())
	json := `{"E131":"` + hex.EncodeToString(E131) + `"}`
	return []byte(json)
}

// final step
func (p *Paillier2PC) Step4(payload []byte) []byte {
	type Step4 struct {
		E135 string
	}
	var step4 Step4
	json.Unmarshal([]byte(string(payload)), &step4)
	D135 := new(big.Int).SetBytes(p.decrypt(h2bi(step4.E135).Bytes()))
	notaryPMSShare := u.To32Bytes(mod(D135, p.P))
	return notaryPMSShare
}

func (p *Paillier2PC) encrypt(payload []byte) []byte {
	res, err := paillier.Encrypt(&p.paillierPrivKey.PublicKey, payload)
	if err != nil {
		panic(err)
	}
	return res
}

func (p *Paillier2PC) decrypt(payload []byte) []byte {
	res, err := paillier.Decrypt(p.paillierPrivKey, payload)
	if err != nil {
		panic(err)
	}
	return res
}

// wrappers for big.Int methods which are less clunky than the stock ones
func mul(a, b *big.Int) *big.Int {
	res := new(big.Int)
	res.Mul(a, b)
	return res
}

func mod(a, b *big.Int) *big.Int {
	res := new(big.Int)
	res.Mod(a, b)
	return res
}

func sub(a, b *big.Int) *big.Int {
	res := new(big.Int)
	res.Sub(a, b)
	return res
}

func add(a, b *big.Int) *big.Int {
	res := new(big.Int)
	res.Add(a, b)
	return res
}

func exp(a, b, c *big.Int) *big.Int {
	res := new(big.Int)
	res.Exp(a, b, c)
	return res
}

// h2bi converts a hex string into big.Int
func h2bi(a string) *big.Int {
	res, ok := new(big.Int).SetString(a, 16)
	if !ok {
		panic("in h2bi")
	}
	return res
}
