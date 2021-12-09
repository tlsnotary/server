package session

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math"
	"math/big"
	"notary/evaluator"
	"notary/garbled_pool"
	"notary/garbler"
	u "notary/utils"
	"os"
	"path/filepath"

	ec "crypto/elliptic"
	"time"

	"github.com/bwesterb/go-ristretto"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

type Session struct {
	e                       *evaluator.Evaluator
	g                       *garbler.Garbler
	p256                    ec.Curve
	qPriv, qPrivGX, qPrivGY *big.Int
	paillierPrivKey         *paillier.PrivateKey
	ghashOutputShare        []byte            //notary's share of gcm's ghash output
	powersOfH               [][]byte          // contains notary's share for each power of H
	clientOTForPowers       [][]byte          // contains idxArrays of each client share of H
	notaryOTArray           []evaluator.OTmap //
	notaryBitArray          []int             //bits for c6 OT
	maxPowerNeeded          int
	maxOddPowerNeeded       int
	// serverPubkey is EC pubkey used during 3-party ECDH secret negotiation.
	// This pubkey will be included in notary's signature
	serverPubkey []byte
	// notaryPMSShare is notary's additive share of TLS pre-master secret. It is the result of
	// computing point addition jointly with the client using our Paillier-based protocol.
	notaryPMSShare []byte
	// ghashInputsBlob contains a blob of inputs for the ghash function. It will
	// be included into the notary's final signature.
	ghashInputsBlob []byte
	// cwkShare is notary's xor share of client_write_key
	cwkShare []byte
	// civShare is notary's xor share of client_write_iv
	civShare []byte
	// swkShare is notary's xor share of server_write_key
	swkShare []byte
	// sivShare is notary's xor share of server_write_iv
	sivShare []byte
	// notaryKey is a symmetric key used to encrypt messages TO the client
	notaryKey []byte
	// clientKey is a symmetric key used to decrypt messages FROM the client
	clientKey []byte
	// signingKey is used to sign the notarization session
	signingKey *ecdsa.PrivateKey
	// ghashOTNeeded is the count of OT bits which the client tells the notary
	// to prepare for 2PC of ghash for the client request
	ghashOTNeeded int
	// blobSizeSent is how many bytes of blob has been sent so far
	blobSizeSent int
	// gp is class GarbledPool from which we request garbled Blobs
	gp *garbled_pool.GarbledPool
	// storageKey is AES-GCM key used to store blobs on disk
	storageKey []byte
	// StorageDir is where the blobs are stored on disk
	StorageDir string
	// storedFromClientSoFar is how many bytes if client's blob we've stored so far
	storedFromClientSoFar int
	// msgsSeen contains a list of all messages seen from the client
	msgsSeen []int
}

// getSymmetricKeys computes a shared ECDH secret between the other party's
// pubkey and my privkey. Outputs 2 16-byte secrets.
func (s *Session) getSymmetricKeys(pk []byte, myPrivKey *ecdsa.PrivateKey) (ck, nk []byte) {
	hisPubKey := ecdsa.PublicKey{
		elliptic.P256(),
		new(big.Int).SetBytes(pk[0:32]),
		new(big.Int).SetBytes(pk[32:64]),
	}
	secret, _ := hisPubKey.Curve.ScalarMult(hisPubKey.X, hisPubKey.Y, myPrivKey.D.Bytes())
	secretBytes := u.To32Bytes(secret)
	return secretBytes[0:16], secretBytes[16:32]
}

func (s *Session) decryptFromClient(ctWithNonce []byte) []byte {
	return u.AESGCMdecrypt(s.clientKey, ctWithNonce)
}

func (s *Session) encryptToClient(plaintext []byte) []byte {
	return u.AESGCMencrypt(s.notaryKey, plaintext)
}

// sequenceCheck makes sure messages are received in the correct order
func (s *Session) sequenceCheck(seqNo int) {
	if u.Contains(seqNo, s.msgsSeen) {
		// get/setBlobChunk may be sent many times but not after step1
		if (seqNo == 3 || seqNo == 4) && !u.Contains(7, s.msgsSeen) {
			return
		} else {
			panic("message sent twice")
		}
	}
	if !u.Contains(seqNo-1, s.msgsSeen) {
		if seqNo == 1 || (seqNo == 36 && u.Contains(32, s.msgsSeen)) {
			// steps 33,34 and 35 are optional and can be skipped
		} else {
			panic("previous message not seen")
		}
	}
	s.msgsSeen = append(s.msgsSeen, seqNo)
}

func (s *Session) PreInit(body, blob []byte, signingKey ecdsa.PrivateKey) []byte {
	s.sequenceCheck(1)
	s.g = new(garbler.Garbler)
	s.e = new(evaluator.Evaluator)
	s.signingKey = &signingKey
	// the first 64 bytes are client pubkey for ECDH
	o := 0
	s.clientKey, s.notaryKey = s.getSymmetricKeys(body[o:o+64], &signingKey)
	o += 64
	c5count := int(new(big.Int).SetBytes(body[o : o+2]).Uint64())
	o += 2
	c6count := int(new(big.Int).SetBytes(body[o : o+2]).Uint64())
	o += 2
	otNeeded := int(new(big.Int).SetBytes(body[o : o+2]).Uint64())
	o += 2
	if c5count > 300 || c6count > 1 || otNeeded > 20000 {
		panic("can't process a huge request")
	}
	s.g.C5Count = c5count
	s.g.C6Count = c6count
	s.ghashOTNeeded = otNeeded
	log.Println("s.g.C5Count", s.g.C5Count)
	A := body[o : o+32]
	o += 32
	s.e.SetA(A)
	s.g.PrepareA()
	return u.Concat(blob, s.encryptToClient(s.g.Ot_GetA()))
}

func (s *Session) Init(gp *garbled_pool.GarbledPool) []byte {
	s.sequenceCheck(2)
	g := s.g
	e := s.e
	s.gp = gp
	s.ghashOutputShare = make([]byte, 16)
	s.powersOfH = make([][]byte, 1027)       //starting with 1, 1026 is the max that we'll ever need
	s.clientOTForPowers = make([][]byte, 36) //starting with 1, 35 is the max that we'll ever need
	s.storageKey = u.GetRandom(16)
	curDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	s.StorageDir = filepath.Join(filepath.Dir(curDir), u.RandString())
	err = os.Mkdir(s.StorageDir, 0755)
	if err != nil {
		panic(err)
	}
	s.storedFromClientSoFar = 0

	blobs := s.gp.GetBlobs(s.g.C5Count)
	ilBlobs := make([]garbler.Labels, len(blobs))
	for i := 1; i < len(ilBlobs); i++ {
		ilBlobs[i] = blobs[i].Il
	}
	g.Init(ilBlobs, s.gp.Circuits)
	e.Init(g)
	s.swkShare = g.Cs[3].Masks[1]
	s.cwkShare = g.Cs[3].Masks[2]
	s.sivShare = g.Cs[3].Masks[3]
	s.civShare = g.Cs[3].Masks[4]

	g.One = big.NewInt(1)
	g.Zero = big.NewInt(0)

	s.p256 = ec.P256()
	// we need an int in range [1, N-1]
	nMinusOne := new(big.Int).Sub(s.p256.Params().N, g.One)
	randInt, err := rand.Int(rand.Reader, nMinusOne) //returns range [0, max)
	if err != nil {
		panic("crypto random error")
	}
	s.qPriv = new(big.Int).Add(randInt, g.One)
	s.qPrivGX, s.qPrivGY = s.p256.ScalarBaseMult(s.qPriv.Bytes())
	s.paillierPrivKey, _ = paillier.GenerateKey(rand.Reader, 1536)

	// for each circuit send truth table and output labels
	var blobForClient []byte
	for i := 1; i < len(g.Cs); i++ {
		blobForClient = append(blobForClient, blobs[i].Tt...)
		blobForClient = append(blobForClient, blobs[i].Ol...)
	}

	log.Println("finished Init")
	blobTotalSize := make([]byte, 4)
	binary.BigEndian.PutUint32(blobTotalSize, uint32(len(blobForClient)))
	s.storeBlobForClient(blobForClient)
	s.blobSizeSent = 0
	return s.encryptToClient(blobTotalSize)
}

func (s *Session) storeBlobForClient(blob []byte) {
	// we split up the blob into 1MB chunks and encrypt each chunk
	// all encrypted chunks + nonces+MACs are stored in one blob
	path := filepath.Join(s.StorageDir, "blobForClient")
	oneMB := 1024 * 1024
	chunkCount := int(math.Ceil(float64(len(blob)) / float64(oneMB)))
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	processedSoFar := 0
	for i := 0; i < chunkCount; i++ {
		size := oneMB
		if i == chunkCount-1 {
			size = len(blob) - oneMB*i
		}
		enc := u.AESGCMencrypt(s.storageKey, blob[oneMB*i:oneMB*i+size])
		// each chunk we wrote had a 12-byte nonce and 16-byte MAC
		_, err := file.WriteAt(enc, int64((oneMB+12+16)*i))
		if err != nil {
			panic(err)
		}
		processedSoFar += size
	}
	err = file.Close()
	if err != nil {
		panic(err)
	}
}

func (s *Session) retrieveChunksForClient(from, to int) []byte {
	return s.retrieveChunks(from, to, "blobForClient")
}

func (s *Session) retrieveChunksForNotary(from, to int) []byte {
	return s.retrieveChunks(from, to, "blobForNotary")
}

// returns complete decrypted chunks which fall in the (from,to] range
func (s *Session) retrieveChunks(from, to int, blobFile string) []byte {
	log.Println("from to", from, to)
	path := filepath.Join(s.StorageDir, blobFile)
	oneMB := 1024 * 1024
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	fromChunk := int(math.Floor(float64(from) / float64(oneMB)))
	toChunk := int(math.Floor(float64(to-1) / float64(oneMB)))
	totalChunks := toChunk - fromChunk + 1
	start := fromChunk * (oneMB + 12 + 16)
	pt := make([]byte, totalChunks*oneMB)
	processedSoFar := 0
	ptBytesCount := 0
	for i := 0; i < totalChunks; i++ {
		buffer := make([]byte, oneMB+12+16)
		n, err := file.ReadAt(buffer, int64(start+processedSoFar))
		if err != nil && err != io.EOF {
			panic(err)
		}
		dec := u.AESGCMdecrypt(s.storageKey, buffer[0:n])
		copy(pt[ptBytesCount:ptBytesCount+len(dec)], dec)
		processedSoFar += n
		ptBytesCount += len(dec)
	}
	err = file.Close()
	if err != nil {
		panic(err)
	}
	return pt[0:ptBytesCount]
}

func (s *Session) GetBlobChunk(encrypted []byte) []byte {
	s.sequenceCheck(3)
	body := s.decryptFromClient(encrypted)
	chunkSize := int(new(big.Int).SetBytes(body).Uint64())
	log.Println("chunk size", chunkSize)
	chunkToSend := s.retrieveChunksForClient(s.blobSizeSent, s.blobSizeSent+chunkSize)
	s.blobSizeSent += len(chunkToSend)
	return s.encryptToClient(chunkToSend)
}

// store a 1MB chunk to disk
func (s *Session) storeChunkForNotary(blob []byte) {
	path := filepath.Join(s.StorageDir, "blobForNotary")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := f.Write(u.AESGCMencrypt(s.storageKey, blob)); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

// returns ot blob and ol blob from the [off:off+len] range from the blob encrypted on disk
func (s *Session) RetrieveBlobsForNotary(off, ttSize, olSize int) ([]byte, []byte) {
	oneMB := 1024 * 1024
	endOff := off + ttSize + olSize
	// chunks contains full 1MB chunks, we need to trim it to
	// include only our range
	chunks := s.retrieveChunksForNotary(off, endOff)
	trimStart := off % oneMB
	chunkCount := int(math.Ceil(float64(len(chunks)) / float64(oneMB)))
	lastChuckSize := len(chunks) - ((chunkCount - 1) * oneMB)
	trimEnd := lastChuckSize - (endOff % oneMB)
	trimmed := chunks[trimStart : len(chunks)-trimEnd]
	return trimmed[:ttSize], trimmed[ttSize:]
}

func (s *Session) SetBlobChunk(encrypted []byte) []byte {
	s.sequenceCheck(4)
	blobChunk := s.decryptFromClient(encrypted)
	if bytes.Equal(blobChunk, []byte("magic: no more data")) {
		// client signals that no more data will be sent
		return nil
	} else {
		if s.storedFromClientSoFar > 1024*1024*350 {
			panic("trying to store more than 350MB of data")
		}
		s.storeChunkForNotary(blobChunk)
		s.storedFromClientSoFar += len(blobChunk)
	}
	log.Println("got blob chunk of size", len(blobChunk))
	return nil
}

// OT_AllB receives a blob of B values for 1-of-2 Oblivious Transfer from Client.
// For fixed inputs, immediately computes the two encrypted messages E(M_0) and E(M_1)
// and sends them to Client.
// For non-fixed inputs (those inputs which are not known at this stage), computes
// the encryption keys and stores them to be used later when inputs will become known
// and OT can be completed.
func (s *Session) OT_AllB(encrypted []byte) []byte {
	s.sequenceCheck(5)
	body := s.decryptFromClient(encrypted)
	e := s.e
	g := s.g
	// how many time each circuit is garbled/evaluated
	repeatCount := []int{0, 1, 1, 1, 1, g.C5Count, g.C6Count}
	fixedCount := 0
	nonFixedCount := 0
	for i := 1; i < len(g.Cs); i++ {
		fixedCount += g.Cs[i].ClientFixedInputSize * repeatCount[i]
		log.Println("fixed count in NasG ", g.Cs[i].ClientFixedInputSize*repeatCount[i])
		nonFixedCount += g.Cs[i].ClientNonFixedInputSize
	}
	nonFixedCount += (256 + 256) // for powers of H OT for ClFin and ServFin
	nonFixedCount += s.ghashOTNeeded

	log.Println("NoOfc5Circuits", g.C5Count)
	log.Println("fixedCount", fixedCount)
	log.Println("nonFixedCount", nonFixedCount)

	OT0PoolSize := int(math.Ceil(float64(nonFixedCount/2) * 1.2))
	OT1PoolSize := int(math.Ceil(float64(nonFixedCount/2) * 1.2))

	expectedLen := (OT0PoolSize + OT1PoolSize + fixedCount) * 32
	if len(body) != expectedLen {
		log.Println("body len was", len(body), " expected ", expectedLen)
		panic("len(body) != expectedLen")
	}

	fixedBlob := body[0 : fixedCount*32]
	nonFixedPoolBlob := body[fixedCount*32:]
	g.AllNonFixedOT = nil

	start := time.Now()
	var encLabels []byte
	fixedBlobIdx := 0
	for j := 1; j < len(g.Cs); j++ {
		c := &g.Cs[j]
		if c.ClientFixedInputSize*repeatCount[j]*32 != len(c.Il.ClientFixed) {
			log.Println(c.ClientFixedInputSize * repeatCount[j] * 32)
			log.Println(len(c.Il.ClientFixed))
			panic("c.ClientFixedInputSize*repeatCount[j]*32 != c.Il.ClientFixed")
		}
		for i := 0; i < c.ClientFixedInputSize*repeatCount[j]; i++ {
			m0 := c.Il.ClientFixed[i*32 : i*32+16]
			m1 := c.Il.ClientFixed[i*32+16 : i*32+32]
			var buf [32]byte
			copy(buf[:], fixedBlob[fixedBlobIdx*32:fixedBlobIdx*32+32])
			B := new(ristretto.Point)
			B.SetBytes(&buf)
			k0 := u.Generichash(16, new(ristretto.Point).ScalarMult(B, g.Ot_a).Bytes())
			k1 := u.Generichash(16, new(ristretto.Point).ScalarMult(new(ristretto.Point).Sub(B, g.A), g.Ot_a).Bytes())
			e0 := u.Encrypt_generic(m0, k0, 0)
			e1 := u.Encrypt_generic(m1, k1, 0)
			encLabels = append(encLabels, e0...)
			encLabels = append(encLabels, e1...)
			fixedBlobIdx++
		}
	}

	// for the non-fixed OT will compute k0,k1
	for i := 0; i < len(nonFixedPoolBlob)/32; i++ {
		var buf [32]byte
		copy(buf[:], nonFixedPoolBlob[i*32:i*32+32])
		B := new(ristretto.Point)
		B.SetBytes(&buf)
		k0 := u.Generichash(16, new(ristretto.Point).ScalarMult(B, g.Ot_a).Bytes())
		k1 := u.Generichash(16, new(ristretto.Point).ScalarMult(new(ristretto.Point).Sub(B, g.A), g.Ot_a).Bytes())
		g.AllNonFixedOT = append(g.AllNonFixedOT, [][]byte{k0, k1})
	}
	log.Println("time taken for OT", time.Since(start))

	e.SetFixedInputs()
	evalOT := e.PreComputeOT()
	log.Println("size of evalOT", len(evalOT))

	return s.encryptToClient((u.Concat(encLabels, evalOT)))
}

func (s *Session) OT_encLabelsForEval(encrypted []byte) []byte {
	s.sequenceCheck(6)
	body := s.decryptFromClient(encrypted)
	s.e.ProcessEncryptedLabels(body)
	return nil
}

func (s *Session) Step1(encrypted []byte) []byte {
	s.sequenceCheck(7)
	body := s.decryptFromClient(encrypted)
	// we get server ec pubkey, multiply it by qPriv to get
	// our additive share of pms

	type Step1 struct {
		ServerX string
		ServerY string
		Share1X string
		Share1Y string
	}
	var step1 Step1
	p256 := s.p256

	json.Unmarshal([]byte(string(body)), &step1)

	serverX := new(big.Int)
	serverX.SetString(step1.ServerX, 16)
	xBytes := make([]byte, 32)
	serverX.FillBytes(xBytes)
	serverY := new(big.Int)
	serverY.SetString(step1.ServerY, 16)
	yBytes := make([]byte, 32)
	serverY.FillBytes(yBytes)
	s.serverPubkey = u.Concat([]byte{0x04}, xBytes, yBytes)

	// share1X and Y are here for debug purposes
	// they should not be revealed by the client
	share1X := new(big.Int)
	share1X.SetString(step1.Share1X, 16)
	share1Y := new(big.Int)
	share1Y.SetString(step1.Share1Y, 16)
	shareX, shareY := p256.ScalarMult(serverX, serverY, s.qPriv.Bytes())

	Pxq, _ := paillier.Encrypt(&s.paillierPrivKey.PublicKey, shareX.Bytes())
	// negative xq mod p == p - xq
	nxq := new(big.Int).Sub(p256.Params().P, shareX)
	Pnxq, _ := paillier.Encrypt(&s.paillierPrivKey.PublicKey, nxq.Bytes())
	//yq**2 mod p
	two := big.NewInt(2)
	yq2 := new(big.Int).Exp(shareY, two, p256.Params().P)
	// -2*yq mod p == p - 2*yq
	n2yq := new(big.Int).Mod(
		new(big.Int).Sub(p256.Params().P, new(big.Int).Mul(shareY, two)),
		p256.Params().P)
	Pyq2, _ := paillier.Encrypt(&s.paillierPrivKey.PublicKey, yq2.Bytes())
	Pn2yq, _ := paillier.Encrypt(&s.paillierPrivKey.PublicKey, n2yq.Bytes())

	var json = `{"Pxq":"` + hex.EncodeToString(Pxq) + `",
				 "Pnxq":"` + hex.EncodeToString(Pnxq) + `",
				 "Pyq2":"` + hex.EncodeToString(Pyq2) + `",
				 "Pn2yq":"` + hex.EncodeToString(Pn2yq) + `",
				 "n":"` + hex.EncodeToString(s.paillierPrivKey.PublicKey.N.Bytes()) + `",
				 "g":"` + hex.EncodeToString(s.paillierPrivKey.PublicKey.G.Bytes()) + `",
				 "qPrivGX":"` + hex.EncodeToString(s.qPrivGX.Bytes()) + `",
				 "qPrivGY":"` + hex.EncodeToString(s.qPrivGY.Bytes()) + `"}`

	return s.encryptToClient([]byte(json))
}

func (s *Session) Step2(encrypted []byte) []byte {
	s.sequenceCheck(8)
	body := s.decryptFromClient(encrypted)
	type Step2 struct {
		PABC  string
		Cmodp string
	}
	var step2 Step2
	json.Unmarshal([]byte(string(body)), &step2)

	PABC, err := hex.DecodeString(step2.PABC)
	if err != nil {
		panic(err)
	}
	Cmodp_bytes, err := hex.DecodeString(step2.Cmodp)
	if err != nil {
		panic(err)
	}

	DABC_bytes, _ := paillier.Decrypt(s.paillierPrivKey, PABC)
	DABC := new(big.Int).SetBytes(DABC_bytes)
	Cmodp := new(big.Int).SetBytes(Cmodp_bytes)
	AB := new(big.Int).Mod(new(big.Int).Sub(DABC, Cmodp), s.p256.Params().P)
	three := big.NewInt(3)
	pow := new(big.Int).Sub(s.p256.Params().P, three)
	ABraised := new(big.Int).Exp(AB, pow, s.p256.Params().P)
	PABraised, _ := paillier.Encrypt(&s.paillierPrivKey.PublicKey, ABraised.Bytes())

	var json = `{"PABraised":"` + hex.EncodeToString(PABraised) + `"}`
	return s.encryptToClient([]byte(json))
}

func (s *Session) Step3(encrypted []byte) []byte {
	s.sequenceCheck(9)
	body := s.decryptFromClient(encrypted)
	type Step3 struct {
		B      string
		A2modp string
		D      string
		C2modp string
	}
	var step3 Step3
	json.Unmarshal([]byte(string(body)), &step3)

	b, err := hex.DecodeString(step3.B)
	if err != nil {
		panic(err)
	}
	a2modp_bytes, err := hex.DecodeString(step3.A2modp)
	if err != nil {
		panic(err)
	}
	d, err := hex.DecodeString(step3.D)
	if err != nil {
		panic(err)
	}
	c2modp_bytes, err := hex.DecodeString(step3.C2modp)
	if err != nil {
		panic(err)
	}

	decrB_bytes, _ := paillier.Decrypt(s.paillierPrivKey, b)
	decrB := new(big.Int).SetBytes(decrB_bytes)
	a2modp := new(big.Int).SetBytes(a2modp_bytes)
	termBa1 := new(big.Int).Mod(
		new(big.Int).Sub(decrB, a2modp),
		s.p256.Params().P)
	decrD_bytes, _ := paillier.Decrypt(s.paillierPrivKey, d)
	decrD := new(big.Int).SetBytes(decrD_bytes)
	c2modp := new(big.Int).SetBytes(c2modp_bytes)
	termAc2 := new(big.Int).Mod(
		new(big.Int).Sub(decrD, c2modp),
		s.p256.Params().P)
	termABmasked := new(big.Int).Mod(
		new(big.Int).Mul(termBa1, termAc2),
		s.p256.Params().P)
	PtermABmasked, _ := paillier.Encrypt(&s.paillierPrivKey.PublicKey, termABmasked.Bytes())

	var json = `{"PtermABmasked":"` + hex.EncodeToString(PtermABmasked) + `"}`
	return s.encryptToClient([]byte(json))
}

func (s *Session) Step4(encrypted []byte) []byte {
	s.sequenceCheck(10)
	body := s.decryptFromClient(encrypted)
	type Step4 struct {
		Px2unreduced string
	}
	var step4 Step4
	json.Unmarshal([]byte(string(body)), &step4)

	Px2unreduced, err := hex.DecodeString(step4.Px2unreduced)
	if err != nil {
		panic(err)
	}

	decr_bytes, _ := paillier.Decrypt(s.paillierPrivKey, Px2unreduced)
	decr := new(big.Int).SetBytes(decr_bytes)
	s.notaryPMSShare = make([]byte, 32)
	new(big.Int).Mod(decr, s.p256.Params().P).FillBytes(s.notaryPMSShare)

	var json = `{"x2":"` + hex.EncodeToString(s.notaryPMSShare) + `",
				"qPriv":"` + hex.EncodeToString(s.qPriv.Bytes()) + `"}`

	return s.encryptToClient([]byte(json))
}

// c_step1 is common for all c circuits
func (s *Session) c_step1(body []byte, cNo int) []byte {
	offset := 0
	if cNo > 1 {
		hisCommit := body[:32]
		offset += 32
		if !bytes.Equal(hisCommit, s.e.CommitHash[cNo-1]) {
			panic("commit hash doesn't match")
		}
	}
	idxBlob := body[offset:]

	encLabels := s.g.C_getEncNonFixedLabels(cNo, idxBlob)
	inputLabels := s.g.C_getInputLabels(cNo)
	indexes := s.e.GetNonFixedIndexes(cNo)
	log.Println(len(inputLabels), len(encLabels), len(indexes))

	var salt []byte = nil
	if cNo > 1 {
		salt = append(salt, s.e.Salt[cNo-1]...)
	}
	return u.Concat(
		salt,
		inputLabels,
		encLabels,
		indexes)
}

func (s *Session) C1_step1(encrypted []byte) []byte {
	s.sequenceCheck(11)
	body := s.decryptFromClient(encrypted)
	s.g.Cs[1].Input = u.Concat(s.g.Cs[1].Masks[1], s.notaryPMSShare)
	out := s.c_step1(body, 1)
	return s.encryptToClient(out)
}

func (s *Session) C1_step2(encrypted []byte) []byte {
	s.sequenceCheck(12)
	body := s.decryptFromClient(encrypted)
	off, ttLen, olLen := s.e.GetCircuitBlobOffset(1)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(off, ttLen, olLen)
	hash := s.e.Evaluate(1, body, ttBlob, olBlob)
	s.g.Cs[1].PmsOuterHash = u.XorBytes(s.g.Cs[1].Output[32:64], s.g.Cs[1].Masks[1])
	return s.encryptToClient(hash)
}

// receive inner hash for a1
func (s *Session) C1_step3(encrypted []byte) []byte {
	s.sequenceCheck(13)
	body := s.decryptFromClient(encrypted)
	a1 := u.FinishHash(s.g.Cs[1].PmsOuterHash, body)
	return s.encryptToClient(a1)
}

// receive inner hash for a2
func (s *Session) C1_step4(encrypted []byte) []byte {
	s.sequenceCheck(14)
	body := s.decryptFromClient(encrypted)
	a2 := u.FinishHash(s.g.Cs[1].PmsOuterHash, body)
	return s.encryptToClient(a2)
}

// receive inner hash for p2
func (s *Session) C1_step5(encrypted []byte) []byte {
	s.sequenceCheck(15)
	body := s.decryptFromClient(encrypted)
	p2 := u.FinishHash(s.g.Cs[1].PmsOuterHash, body)
	return s.encryptToClient(p2)
}

func (s *Session) C2_step1(encrypted []byte) []byte {
	s.sequenceCheck(16)
	body := s.decryptFromClient(encrypted)
	s.g.Cs[2].Input = u.Concat(s.g.Cs[2].Masks[1], s.g.Cs[1].PmsOuterHash)
	out := s.c_step1(body, 2)
	return s.encryptToClient(out)
}

func (s *Session) C2_step2(encrypted []byte) []byte {
	s.sequenceCheck(17)
	body := s.decryptFromClient(encrypted)
	off, ttLen, olLen := s.e.GetCircuitBlobOffset(2)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(off, ttLen, olLen)
	hash := s.e.Evaluate(2, body, ttBlob, olBlob)
	s.g.Cs[2].MsOuterHash = u.XorBytes(s.g.Cs[2].Output[32:64], s.g.Cs[2].Masks[1])
	return s.encryptToClient(hash)
}

// receive inner hash for a1_2
func (s *Session) C2_step3(encrypted []byte) []byte {
	s.sequenceCheck(18)
	body := s.decryptFromClient(encrypted)
	a1inner_2 := body[:32]
	a1inner_vd := body[32:64]
	a1_2 := u.FinishHash(s.g.Cs[2].MsOuterHash, a1inner_2)
	a1_vd := u.FinishHash(s.g.Cs[2].MsOuterHash, a1inner_vd)
	return s.encryptToClient(u.Concat(a1_2, a1_vd))
}

// receive inner hash for a2_2
func (s *Session) C2_step4(encrypted []byte) []byte {
	s.sequenceCheck(19)
	body := s.decryptFromClient(encrypted)
	a2inner_2 := body[:32]
	p1inner_vd := body[32:64]
	a2_2 := u.FinishHash(s.g.Cs[2].MsOuterHash, a2inner_2)
	s.g.P1_vd = u.FinishHash(s.g.Cs[2].MsOuterHash, p1inner_vd)[:12]
	return s.encryptToClient(u.Concat(a2_2, s.g.P1_vd))
}

func (s *Session) C3_step1(encrypted []byte) []byte {
	s.sequenceCheck(20)
	body := s.decryptFromClient(encrypted)
	g := s.g
	g.Cs[3].Input = u.Concat(
		g.Cs[3].Masks[6],
		g.Cs[3].Masks[5],
		g.Cs[3].Masks[4],
		g.Cs[3].Masks[3],
		g.Cs[3].Masks[2],
		g.Cs[3].Masks[1],
		g.Cs[2].MsOuterHash)
	out := s.c_step1(body, 3)
	return s.encryptToClient(out)
}

func (s *Session) C3_step2(encrypted []byte) []byte {
	s.sequenceCheck(21)
	body := s.decryptFromClient(encrypted)
	g := s.g
	off, ttLen, olLen := s.e.GetCircuitBlobOffset(3)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(off, ttLen, olLen)
	commit := s.e.Evaluate(3, body, ttBlob, olBlob)

	// h1MaskedTwice := g.Cs[3].Output[44:60]
	// civMaskedTwice := g.Cs[3].Output[60:64]
	// sivMaskedTwice := g.Cs[3].Output[64:68]
	cwkMaskedTwice := g.Cs[3].Output[68:84]
	swkMaskedTwice := g.Cs[3].Output[84:100]

	g.CwkMaskedByClient = u.XorBytes(cwkMaskedTwice, g.Cs[3].Masks[2])
	g.SwkMaskedByClient = u.XorBytes(swkMaskedTwice, g.Cs[3].Masks[1])

	return s.encryptToClient(commit)
}

func (s *Session) C3_step3(encrypted []byte) []byte {
	s.sequenceCheck(22)
	body := s.decryptFromClient(encrypted)
	g := s.g
	if len(body) != 16+2*128+2*128 {
		panic("wrong len in c3_step4")
	}

	s.powersOfH[1] = g.Cs[3].Masks[5]
	h1share := new(big.Int).SetBytes(s.powersOfH[1])
	h2share := u.BlockMult(h1share, h1share)
	s.powersOfH[2] = u.To16Bytes(h2share)
	H1H2 := u.To16Bytes(u.BlockMult(h1share, h2share))
	h1table := u.GetXTable(s.powersOfH[1])
	h2table := u.GetXTable(s.powersOfH[2])

	o := 0
	encCF := body[o : o+16]
	o += 16
	idxArray1 := body[o : o+256]
	o += 256
	idxArray2 := body[o : o+256]
	o += 256

	masksSum := make([]byte, 16) //notary's H3 share includes the sum of all masks
	var encEntries1 []byte
	for i := 0; i < 128; i++ {
		idx := int(binary.BigEndian.Uint16(idxArray2[i*2 : i*2+2]))
		k0 := g.AllNonFixedOT[idx][0]
		k1 := g.AllNonFixedOT[idx][1]
		mask := u.GetRandom(16)
		masksSum = u.XorBytes(masksSum, mask)
		m0 := mask
		m1 := u.XorBytes(h1table[i], mask)
		e0 := u.Encrypt_generic(m0, k0, 0)
		e1 := u.Encrypt_generic(m1, k1, 0)
		encEntries1 = append(encEntries1, e0...)
		encEntries1 = append(encEntries1, e1...)
	}
	var encEntries2 []byte
	for i := 0; i < 128; i++ {
		idx := int(binary.BigEndian.Uint16(idxArray1[i*2 : i*2+2]))
		k0 := g.AllNonFixedOT[idx][0]
		k1 := g.AllNonFixedOT[idx][1]
		mask := u.GetRandom(16)
		masksSum = u.XorBytes(masksSum, mask)
		m0 := mask
		m1 := u.XorBytes(h2table[i], mask)
		e0 := u.Encrypt_generic(m0, k0, 0)
		e1 := u.Encrypt_generic(m1, k1, 0)
		encEntries2 = append(encEntries2, e0...)
		encEntries2 = append(encEntries2, e1...)
	}
	H3share := u.XorBytes(masksSum, H1H2)
	s.powersOfH[3] = H3share

	aad := []byte{0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0}

	//lenA (before padding) == 13*8 == 104, lenC == 16*8 == 128
	lenAlenC := []byte{0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128}

	gctrShare := g.Cs[3].Masks[6]

	s1 := u.To16Bytes(u.BlockMult(new(big.Int).SetBytes(aad), new(big.Int).SetBytes(H3share)))
	s2 := u.To16Bytes(u.BlockMult(new(big.Int).SetBytes(encCF), h2share))
	s3 := u.To16Bytes(u.BlockMult(new(big.Int).SetBytes(lenAlenC), h1share))
	S := u.XorBytes(u.XorBytes(s1, s2), s3)
	tagShare := u.XorBytes(S, gctrShare)
	return s.encryptToClient(u.Concat(
		tagShare,
		encEntries1,
		encEntries2))
}

func (s *Session) C4_pre1(encrypted []byte) []byte {
	s.sequenceCheck(23)
	body := s.decryptFromClient(encrypted)
	a1inner := body[:]
	a1 := u.FinishHash(s.g.Cs[2].MsOuterHash, a1inner)
	return s.encryptToClient(a1)
}

func (s *Session) C4_step1(encrypted []byte) []byte {
	s.sequenceCheck(24)
	body := s.decryptFromClient(encrypted)
	g := s.g
	g.Cs[4].Input = u.Concat(
		g.Cs[4].Masks[2],
		g.Cs[4].Masks[1],
		g.Cs[3].Masks[3],
		g.Cs[3].Masks[1],
		g.Cs[2].MsOuterHash)

	if len(g.Cs[4].Input) != 84 {
		panic("len(g.Cs[4].input) != 84")
	}
	out := s.c_step1(body, 4)
	return s.encryptToClient(out)
}

func (s *Session) C4_step2(encrypted []byte) []byte {
	s.sequenceCheck(25)
	body := s.decryptFromClient(encrypted)
	off, ttLen, olLen := s.e.GetCircuitBlobOffset(4)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(off, ttLen, olLen)
	hash := s.e.Evaluate(4, body, ttBlob, olBlob)
	return s.encryptToClient(hash)
}

func (s *Session) C4_step3(encrypted []byte) []byte {
	s.sequenceCheck(26)
	body := s.decryptFromClient(encrypted)
	g := s.g
	if len(body) != 16+2*128+2*128 {
		panic("wrong len in c3_step4")
	}

	h1share := new(big.Int).SetBytes(g.Cs[4].Masks[1])
	h2share := u.BlockMult(h1share, h1share)
	H1H2 := u.To16Bytes(u.BlockMult(h1share, h2share))
	h1table := u.GetXTable(u.To16Bytes(h1share))
	h2table := u.GetXTable(u.To16Bytes(h2share))

	o := 0
	encSF := body[o : o+16]
	o += 16
	idxArray1 := body[o : o+256]
	o += 256
	idxArray2 := body[o : o+256]
	o += 256

	masksSum := make([]byte, 16) //notary's H3 share includes the sum of all masks
	var encEntries1 []byte
	for i := 0; i < 128; i++ {
		idx := int(binary.BigEndian.Uint16(idxArray2[i*2 : i*2+2]))
		k0 := g.AllNonFixedOT[idx][0]
		k1 := g.AllNonFixedOT[idx][1]
		mask := u.GetRandom(16)
		masksSum = u.XorBytes(masksSum, mask)
		m0 := mask
		m1 := u.XorBytes(h1table[i], mask)
		e0 := u.Encrypt_generic(m0, k0, 0)
		e1 := u.Encrypt_generic(m1, k1, 0)
		encEntries1 = append(encEntries1, e0...)
		encEntries1 = append(encEntries1, e1...)
	}
	var encEntries2 []byte
	for i := 0; i < 128; i++ {
		idx := int(binary.BigEndian.Uint16(idxArray1[i*2 : i*2+2]))
		k0 := g.AllNonFixedOT[idx][0]
		k1 := g.AllNonFixedOT[idx][1]
		mask := u.GetRandom(16)
		masksSum = u.XorBytes(masksSum, mask)
		m0 := mask
		m1 := u.XorBytes(h2table[i], mask)
		e0 := u.Encrypt_generic(m0, k0, 0)
		e1 := u.Encrypt_generic(m1, k1, 0)
		encEntries2 = append(encEntries2, e0...)
		encEntries2 = append(encEntries2, e1...)
	}
	H3share := u.XorBytes(masksSum, H1H2)

	aad := []byte{0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0}
	//lenA (before padding) == 13*8 == 104, lenC == 16*8 == 128
	lenAlenC := []byte{0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128}

	gctrShare := g.Cs[4].Masks[2]

	s1 := u.To16Bytes(u.BlockMult(new(big.Int).SetBytes(aad), new(big.Int).SetBytes(H3share)))
	s2 := u.To16Bytes(u.BlockMult(new(big.Int).SetBytes(encSF), h2share))
	s3 := u.To16Bytes(u.BlockMult(new(big.Int).SetBytes(lenAlenC), h1share))
	S := u.XorBytes(u.XorBytes(s1, s2), s3)
	tagShare := u.XorBytes(S, gctrShare)

	return s.encryptToClient(u.Concat(
		tagShare,
		encEntries1,
		encEntries2))
}

func (s *Session) C5_step1(encrypted []byte) []byte {
	s.sequenceCheck(27)
	body := s.decryptFromClient(encrypted)
	g := s.g
	g.Cs[5].Input = u.Concat(
		g.Cs[3].Masks[4],
		g.Cs[3].Masks[2])
	out := s.c_step1(body, 5)
	return s.encryptToClient(out)
}

func (s *Session) C5_step2(encrypted []byte) []byte {
	s.sequenceCheck(28)
	body := s.decryptFromClient(encrypted)
	off, ttLen, olLen := s.e.GetCircuitBlobOffset(5)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(off, ttLen, olLen)
	hash := s.e.Evaluate(5, body, ttBlob, olBlob)
	return s.encryptToClient(hash)
}

func (s *Session) C6_step1(encrypted []byte) []byte {
	s.sequenceCheck(29)
	body := s.decryptFromClient(encrypted)
	g := s.g
	g.Cs[6].Input = nil
	for i := g.C6Count; i > 0; i-- {
		g.Cs[6].Input = append(g.Cs[6].Input, g.Cs[6].Masks[i]...)
	}
	g.Cs[6].Input = append(g.Cs[6].Input, g.Cs[3].Masks[4]...)
	g.Cs[6].Input = append(g.Cs[6].Input, g.Cs[3].Masks[2]...)
	out := s.c_step1(body, 6)
	return s.encryptToClient(out)
}

func (s *Session) C6_step2(encrypted []byte) []byte {
	s.sequenceCheck(30)
	body := s.decryptFromClient(encrypted)
	off, ttLen, olLen := s.e.GetCircuitBlobOffset(6)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(off, ttLen, olLen)
	hash := s.e.Evaluate(6, body, ttBlob, olBlob)
	return s.encryptToClient(hash)
}

func (s *Session) CheckC6Commit(encrypted []byte) []byte {
	s.sequenceCheck(31)
	body := s.decryptFromClient(encrypted)
	hisCommit := body
	if !bytes.Equal(hisCommit, s.e.CommitHash[6]) {
		panic("commit hash doesn't match")
	}
	return s.encryptToClient(s.e.Salt[6])
}

func (s *Session) Ghash_step1(encrypted []byte) []byte {
	s.sequenceCheck(32)
	body := s.decryptFromClient(encrypted)

	g := s.g
	s.ghashOutputShare = u.XorBytes(s.ghashOutputShare, g.Cs[6].Masks[1])

	if len(body) == 2 {
		// The Client's max odd power needed is 3, he doesn't need any OT
		s.maxPowerNeeded = int(binary.BigEndian.Uint16(body))
		//perform free squaring on powers 2,3 which we have from client finished
		u.FreeSquare(&s.powersOfH, s.maxPowerNeeded)
		return nil
	}
	maxHTable := []int{
		0: 0, 3: 19, 5: 29, 7: 71, 9: 89, 11: 107, 13: 125, 15: 271, 17: 305, 19: 339, 21: 373,
		23: 407, 25: 441, 27: 475, 29: 509, 31: 1023, 33: 1025, 35: 1027}

	uniquePowers := []int{1, 3, 4, 8, 12, 16}

	if len(body) != len(uniquePowers)*256+2 {
		panic("len(body) != 6*256+2")
	}
	o := 0
	idxArray := body[o : o+len(uniquePowers)*256]
	o += len(uniquePowers) * 256
	mpnBytes := body[o : o+2]

	s.maxPowerNeeded = int(binary.BigEndian.Uint16(mpnBytes))
	for k, v := range maxHTable {
		if v >= s.maxPowerNeeded {
			s.maxOddPowerNeeded = k
			log.Println("s.maxPowerNeeded", s.maxPowerNeeded)
			log.Println("s.maxOddPowerNeeded", s.maxOddPowerNeeded)
			break
		}
	}

	o = 0
	for i := 0; i < len(uniquePowers); i++ {
		s.clientOTForPowers[uniquePowers[i]] = idxArray[o : o+256]
		o += 256
	}

	// shows what shares of powers we will be multiplying to obtain other odd shares of powers
	// max sequential odd power that we can obtain on first round is 19
	// note that we multiply N_x*C_y and C_y*N_x to get cross-terms. These are not yet shares of powers
	// we must add N_x*N_y and C_x*C_y to respective cross-terms in order to get shares of powers
	strategies := [][]int{
		5:  {4, 1},
		7:  {4, 3},
		9:  {8, 1},
		11: {8, 3},
		13: {12, 1},
		15: {12, 3},
		17: {16, 1},
		19: {16, 3}}

	//perform free squaring on powers 2,3 which we have from client finished
	u.FreeSquare(&s.powersOfH, s.maxPowerNeeded)

	var encEntries []byte
	for k, v := range strategies {
		if v == nil {
			continue
		}
		maskSum := make([]byte, 16) //starting with zeroed mask
		for j := 0; j < 2; j++ {
			var x, y int
			if j == 0 { // on 1st round, 1st factor is notary's
				x = v[0]
				y = v[1]
			} else { // on 2nd round, 2nd factor is notary's
				x = v[1]
				y = v[0]
			}
			xTable := u.GetXTable(s.powersOfH[x])
			idxArray := s.clientOTForPowers[y]
			for i := 0; i < 128; i++ {
				idx := int(binary.BigEndian.Uint16(idxArray[i*2 : i*2+2]))
				k0 := g.AllNonFixedOT[idx][0]
				k1 := g.AllNonFixedOT[idx][1]
				mask := u.GetRandom(16)
				maskSum = u.XorBytes(maskSum, mask)
				m0 := mask
				m1 := u.XorBytes(xTable[i], mask)
				e0 := u.Encrypt_generic(m0, k0, 0)
				e1 := u.Encrypt_generic(m1, k1, 0)
				encEntries = append(encEntries, e0...)
				encEntries = append(encEntries, e1...)
			}
		}
		// get notary's N_x*N_y and then get the final share of power
		v0 := new(big.Int).SetBytes(s.powersOfH[v[0]])
		v1 := new(big.Int).SetBytes(s.powersOfH[v[1]])
		NxNy := u.To16Bytes(u.BlockMult(v0, v1))
		s.powersOfH[k] = u.XorBytes(maskSum, NxNy)
	}
	u.FreeSquare(&s.powersOfH, s.maxPowerNeeded)
	return s.encryptToClient(encEntries)
}

func (s *Session) Ghash_step2(encrypted []byte) []byte {
	s.sequenceCheck(33)
	body := s.decryptFromClient(encrypted)
	allUniquePowers := []int{2, 5, 6, 7, 9, 10, 11, 13, 14, 15, 17, 18, 19}
	var uniquePowers []int
	// keep only those powers which we actually need
	for _, v := range allUniquePowers {
		if v <= s.maxOddPowerNeeded {
			uniquePowers = append(uniquePowers, v)
		}
	}

	if len(body) != len(uniquePowers)*256 {
		log.Println(uniquePowers)
		panic("len(body) != len(uniquePowers)*256")
	}
	// we already have shares for all these uniquePowers
	// now we only save their idxArrays
	o := 0
	for i := 0; i < len(uniquePowers); i++ {
		s.clientOTForPowers[uniquePowers[i]] = body[o : o+256]
		o += 256
	}
	return nil
}

func (s *Session) Ghash_step3(encrypted []byte) []byte {
	s.sequenceCheck(34)
	body := s.decryptFromClient(encrypted)
	g := s.g
	if len(body) != 2*256 {
		panic("len(body) != 2*256")
	}

	uniquePowers := []int{17, 19}
	o := 0
	for i := 0; i < len(uniquePowers); i++ {
		s.clientOTForPowers[uniquePowers[i]] = body[o : o+256]
		o += 256
	}

	// shows what shares of powers we will be multiplying to obtain other odd shares of powers
	// max sequential odd power that we can obtain on first round is 19
	// note that we multiply N_x*C_y and C_y*N_x to get cross-terms. These are not yet shares of powers
	// we must add N_x*N_y and C_x*C_y to respective cross-terms in order to get shares of powers
	strategies2 := map[int][]int{
		21: {17, 4},
		23: {17, 6},
		25: {17, 8},
		27: {19, 8},
		29: {17, 12},
		31: {19, 12},
		33: {17, 16},
		35: {19, 16}}

	var encEntries []byte
	for k, v := range strategies2 {
		maskSum := make([]byte, 16) //starting with zeroed mask
		for j := 0; j < 2; j++ {
			var x, y int
			if j == 0 { // on 1st round, 1st factor is notary's
				x = v[0]
				y = v[1]
			} else { // on 2nd round, 2nd factor is notary's
				x = v[1]
				y = v[0]
			}
			xTable := u.GetXTable(s.powersOfH[x])
			idxArray := s.clientOTForPowers[y]
			for i := 0; i < 128; i++ {
				idx := int(binary.BigEndian.Uint16(idxArray[i*2 : i*2+2]))
				k0 := g.AllNonFixedOT[idx][0]
				k1 := g.AllNonFixedOT[idx][1]
				mask := u.GetRandom(16)
				maskSum = u.XorBytes(maskSum, mask)
				m0 := mask
				m1 := u.XorBytes(xTable[i], mask)
				e0 := u.Encrypt_generic(m0, k0, 0)
				e1 := u.Encrypt_generic(m1, k1, 0)
				encEntries = append(encEntries, e0...)
				encEntries = append(encEntries, e1...)
			}
		}
		// get notary's N_x*N_y and then get the final share of power
		v0 := new(big.Int).SetBytes(s.powersOfH[v[0]])
		v1 := new(big.Int).SetBytes(s.powersOfH[v[1]])
		NxNy := u.To16Bytes(u.BlockMult(v0, v1))
		s.powersOfH[k] = u.XorBytes(maskSum, NxNy)
	}
	u.FreeSquare(&s.powersOfH, s.maxPowerNeeded)
	return s.encryptToClient(encEntries)
}

func (s *Session) Ghash_step4(encrypted []byte) []byte {
	s.sequenceCheck(35)
	body := s.decryptFromClient(encrypted)
	uniquePowers := []int{20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35}
	if len(body) != len(uniquePowers)*256 {
		panic("len(body) != len(uniquePowers)*256")
	}
	// we already have shares for all these uniquePowers
	// now we only save their idxArrays
	o := 0
	for i := 0; i < len(uniquePowers); i++ {
		s.clientOTForPowers[uniquePowers[i]] = body[o : o+256]
		o += 256
	}
	return nil
}

func (s *Session) Ghash_step5(encrypted []byte) []byte {
	s.sequenceCheck(36)
	body := s.decryptFromClient(encrypted)
	o := 0
	s.ghashInputsBlob = body[o : o+s.maxPowerNeeded*16]
	o += s.maxPowerNeeded * 16
	hisIdxArray := body[o:]
	ghashInputs := make([][]byte, s.maxPowerNeeded)
	for i := 0; i < s.maxPowerNeeded; i++ {
		ghashInputs[i] = s.ghashInputsBlob[i*16 : i*16+16]
	}

	res := make([]byte, 16)
	// compute direct powers
	for i := 1; i < len(s.powersOfH); i++ {
		if i > s.maxPowerNeeded {
			break
		}
		if s.powersOfH[i] == nil {
			continue
		}
		x := new(big.Int).SetBytes(ghashInputs[len(ghashInputs)-i])
		h := new(big.Int).SetBytes(s.powersOfH[i])
		res = u.XorBytes(res, u.To16Bytes(u.BlockMult(h, x)))
	}

	// compute indirect powers, i.e. find powers for X*H
	sumForPowers := make([][]byte, 36) //starting with 1, 35 is the max that we'll ever need
	for i := 1; i < len(s.powersOfH); i++ {
		if i > s.maxPowerNeeded {
			break
		}
		if s.powersOfH[i] != nil {
			continue
		}
		// found a hole in our sparse array, we need X*H for this missing power
		// a is the smaller power
		a, b := u.FindSum(&s.powersOfH, i)
		x := new(big.Int).SetBytes(ghashInputs[len(ghashInputs)-i])
		h_small := new(big.Int).SetBytes(s.powersOfH[a])
		h_big := new(big.Int).SetBytes(s.powersOfH[b])
		res = u.XorBytes(res, u.To16Bytes(u.BlockMult(u.BlockMult(h_small, h_big), x)))
		hx := u.To16Bytes(u.BlockMult(h_big, x))
		if sumForPowers[a] != nil {
			sumForPowers[a] = u.XorBytes(sumForPowers[a], hx)
		} else {
			sumForPowers[a] = hx
		}
	}
	s.ghashOutputShare = u.XorBytes(s.ghashOutputShare, res)

	nonNilItemsCount := 0
	for i := 0; i < len(sumForPowers); i++ {
		if sumForPowers[i] != nil {
			nonNilItemsCount += 1
		}
	}
	if nonNilItemsCount*2*128 != len(hisIdxArray) {
		log.Println("nonNilItemsCount", nonNilItemsCount)
		panic("nonNilItemsCount*2*128 != len(hisIdxArray)")
	}

	idxOff := 0
	maskSum := make([]byte, 16) //starting with zeroed mask
	var encEntries []byte
	for i := 0; i < len(sumForPowers); i++ {
		if sumForPowers[i] == nil {
			continue
		}
		idxArray := hisIdxArray[idxOff : idxOff+256]
		idxOff += 256
		xTable := u.GetXTable(s.powersOfH[i])
		for i := 0; i < 128; i++ {
			idx := int(binary.BigEndian.Uint16(idxArray[i*2 : i*2+2]))
			k0 := s.g.AllNonFixedOT[idx][0]
			k1 := s.g.AllNonFixedOT[idx][1]
			mask := u.GetRandom(16)
			maskSum = u.XorBytes(maskSum, mask)
			m0 := mask
			m1 := u.XorBytes(xTable[i], mask)
			e0 := u.Encrypt_generic(m0, k0, 0)
			e1 := u.Encrypt_generic(m1, k1, 0)
			encEntries = append(encEntries, e0...)
			encEntries = append(encEntries, e1...)
		}
	}
	s.ghashOutputShare = u.XorBytes(s.ghashOutputShare, maskSum)

	// send OT for all sums in sumForPowers in ascending order
	var allBits []int
	for i := 0; i < len(sumForPowers); i++ {
		if sumForPowers[i] == nil {
			continue
		}
		bits := u.Reverse(u.BytesToBits(sumForPowers[i]))
		allBits = append(allBits, bits...)
	}

	idxArray, otArray := s.e.DoGetNonFixedIndexes(allBits)
	s.notaryBitArray = allBits
	s.notaryOTArray = otArray
	return s.encryptToClient(u.Concat(
		encEntries,
		idxArray))
}

func (s *Session) Ghash_step6(encrypted []byte) []byte {
	s.sequenceCheck(37)
	body := s.decryptFromClient(encrypted)
	//expect encEntries for each of the notaryOTArray bit
	if len(s.notaryOTArray)*32 != len(body) {
		panic("len(s.notaryOTArray)*32 != len(body)")
	}
	encEntries := body[:]
	for i := 0; i < len(s.notaryOTArray); i++ {
		bit := s.notaryBitArray[i]
		e := encEntries[i*32+16*bit : i*32+16*bit+16]
		k := s.notaryOTArray[i].K
		maskedEntry := u.Decrypt_generic(e, k, 0)
		s.ghashOutputShare = u.XorBytes(s.ghashOutputShare, maskedEntry)
	}
	return s.encryptToClient(s.ghashOutputShare)
}

func (s *Session) CommitHash(encrypted []byte) []byte {
	s.sequenceCheck(38)
	body := s.decryptFromClient(encrypted)
	hisCommitHash := body[0:32]
	hisKeyShareHash := body[32:64]
	hisPMSShareHash := body[64:96]
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix()))
	signature := u.ECDSASign(s.signingKey,
		hisCommitHash,
		hisKeyShareHash,
		hisPMSShareHash,
		s.ghashInputsBlob,
		s.serverPubkey,
		s.notaryPMSShare,
		s.cwkShare,
		s.civShare,
		s.swkShare,
		s.sivShare,
		timeBytes)

	return s.encryptToClient(u.Concat(
		signature,
		s.notaryPMSShare,
		s.cwkShare,
		s.civShare,
		s.swkShare,
		s.sivShare,
		timeBytes))
}
