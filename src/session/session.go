package session

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"io"
	"log"
	"math"
	"math/big"
	"notary/evaluator"
	"notary/garbled_pool"
	"notary/garbler"
	"notary/ot"
	"notary/paillier2pc"
	u "notary/utils"

	"os"
	"path/filepath"

	"time"
)

type Session struct {
	e                 *evaluator.Evaluator
	g                 *garbler.Garbler
	p2pc              *paillier2pc.Paillier2PC
	ghashOutputShare  []byte   //notary's share of gcm's ghash output
	powersOfH         [][]byte // contains notary's share for each power of H
	maxPowerNeeded    int
	maxOddPowerNeeded int
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
	otS      *ot.OTSender
	otR      *ot.OTReceiver
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

// sequenceCheck makes sure messages are received in the correct order and
// (where applicable) received only once. This is crucial for the security
// of the TLSNotary protocol.
func (s *Session) sequenceCheck(seqNo int) {
	if u.Contains(seqNo, s.msgsSeen) {
		// get/setBlobChunk may be sent many times but not after step1
		if (seqNo == 3 || seqNo == 4) && !u.Contains(5, s.msgsSeen) {
			return
		} else {
			panic("message sent twice")
		}
	}
	if !u.Contains(seqNo-1, s.msgsSeen) {
		// it is acceptable if the preceding message was not found if:
		// 1) the msg is the very first msg "init1"
		// 2) the msg is getBlobChunk (no 3) and the client hasn't yet
		// sent "init2" (no2)
		// 3) the msg is no 32 and no 31 which is optional was skipped
		if seqNo == 1 || seqNo == 3 || (seqNo == 32 && u.Contains(30, s.msgsSeen)) {
		} else {
			panic("previous message not seen")
		}
	}
	s.msgsSeen = append(s.msgsSeen, seqNo)
}

func (s *Session) Init1(body, blob []byte, signingKey ecdsa.PrivateKey,
	gp *garbled_pool.GarbledPool) []byte {
	s.sequenceCheck(1)
	s.g = new(garbler.Garbler)
	s.e = new(evaluator.Evaluator)
	s.otS = new(ot.OTSender)
	s.otR = new(ot.OTReceiver)
	s.p2pc = new(paillier2pc.Paillier2PC)
	s.signingKey = &signingKey
	// the first 64 bytes are client pubkey for ECDH
	o := 0
	s.clientKey, s.notaryKey = s.getSymmetricKeys(body[o:o+64], &signingKey)
	o += 64
	c5count := int(new(big.Int).SetBytes(body[o : o+2]).Uint64())
	o += 2
	c6count := int(new(big.Int).SetBytes(body[o : o+2]).Uint64())
	o += 2
	otCountForSend := int(new(big.Int).SetBytes(body[o : o+4]).Uint64())
	o += 4
	otCountForRecv := int(new(big.Int).SetBytes(body[o : o+4]).Uint64())
	o += 4
	if c5count > 300 || c6count > 1 || otCountForSend > 2000000 ||
		otCountForRecv > 2000000 {
		panic("can't process a huge request")
	}
	s.g.C5Count = c5count
	s.g.C6Count = c6count
	log.Println("s.g.C5Count", s.g.C5Count)
	s.otS.Init(otCountForSend)
	s.otR.Init(otCountForRecv)

	receiverA := body[o : o+32]
	o += 32
	receiverSeedCommit := body[o : o+32]
	o += 32
	if len(body) != o {
		panic("len(body) != o")
	}
	allBs, senderSeedShare := s.otS.SetupStep1(receiverA, receiverSeedCommit)
	A, seedCommit := s.otR.SetupStep1()

	g := s.g
	e := s.e
	s.gp = gp
	s.ghashOutputShare = make([]byte, 16)
	s.powersOfH = make([][]byte, 1027) //starting with 1, 1026 is the max that we'll ever need
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
	ilBlobs := make([][]byte, len(blobs))
	for i := 1; i < len(ilBlobs); i++ {
		ilBlobs[i] = blobs[i].Il
	}
	g.Init(ilBlobs, s.gp.Circuits)
	e.Init(g)
	s.swkShare = g.Cs[3].Masks[1]
	s.cwkShare = g.Cs[3].Masks[2]
	s.sivShare = g.Cs[3].Masks[3]
	s.civShare = g.Cs[3].Masks[4]

	s.p2pc.Init()
	g.One = big.NewInt(1)
	g.Zero = big.NewInt(0)

	// for each circuit send truth table and output labels
	var blobForClient []byte
	for i := 1; i < len(g.Cs); i++ {
		blobForClient = append(blobForClient, blobs[i].Tt...)
		blobForClient = append(blobForClient, blobs[i].Ol...)
	}

	blobTotalSize := make([]byte, 4)
	binary.BigEndian.PutUint32(blobTotalSize, uint32(len(blobForClient)))
	s.storeBlobForClient(blobForClient)
	s.blobSizeSent = 0
	return u.Concat(blob, s.encryptToClient(u.Concat(A, seedCommit, allBs,
		senderSeedShare, blobTotalSize)))
}

func (s *Session) Init2(encrypted []byte) []byte {
	s.sequenceCheck(2)
	body := s.decryptFromClient(encrypted)
	o := 0
	hisReceiverEncryptedColumns := body[o : o+256*s.otS.TotalOT/8]
	o += 256 * s.otS.TotalOT / 8
	hisReceiverSeedShare := body[o : o+16]
	o += 16
	hisReceiverX := body[o : o+16]
	o += 16
	hisReceiverT := body[o : o+32]
	o += 32
	hisSenderallBs := body[o : o+128*32]
	o += 128 * 32
	hisSenderSeedShare := body[o : o+16]
	o += 16
	if len(body) != o {
		panic("len(body) != o")
	}
	s.otS.SetupStep2(hisReceiverEncryptedColumns, hisReceiverSeedShare,
		hisReceiverX, hisReceiverT)
	encryptedColumns, receiverSeedShare, x, t := s.otR.SetupStep2(hisSenderallBs, hisSenderSeedShare)
	log.Println("finished Init")
	return s.encryptToClient(u.Concat(encryptedColumns, receiverSeedShare, x, t))
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

// returns truth tables blob and output labels blob from the blob encrypted on disk
// The encrypted blob is the one we received earlier from the client
func (s *Session) RetrieveBlobsForNotary(cNo int) ([]byte, []byte) {
	off, ttSize, olSize := s.getCircuitBlobOffset(cNo)
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

// GetCircuitBlobOffset finds the offset and size of the tt+ol blob for circuit cNo
// in the blob of all circuits
func (s *Session) getCircuitBlobOffset(cNo int) (int, int, int) {
	offset := 0
	var ttLen, olLen int
	for i := 1; i < len(s.g.Cs); i++ {
		ttLen = s.g.Cs[i].Circuit.AndGateCount * 48
		olLen = s.g.Cs[i].Circuit.OutputSize * 32
		if i == 5 {
			ttLen = s.g.C5Count * ttLen
			olLen = s.g.C5Count * olLen
		}
		if i == 6 {
			ttLen = s.g.C6Count * ttLen
			olLen = s.g.C6Count * olLen
		}
		if i == cNo {
			break
		}
		offset += ttLen
		offset += olLen
	}
	return offset, ttLen, olLen
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

func (s *Session) Step1(encrypted []byte) []byte {
	s.sequenceCheck(5)
	body := s.decryptFromClient(encrypted)
	var resp []byte
	s.serverPubkey, resp = s.p2pc.Step1(body)
	return s.encryptToClient(resp)
}

func (s *Session) Step2(encrypted []byte) []byte {
	s.sequenceCheck(6)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.p2pc.Step2(body))
}

func (s *Session) Step3(encrypted []byte) []byte {
	s.sequenceCheck(7)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.p2pc.Step3(body))
}

func (s *Session) Step4(encrypted []byte) []byte {
	s.sequenceCheck(8)
	body := s.decryptFromClient(encrypted)
	s.notaryPMSShare = s.p2pc.Step4(body)
	return nil
}

// c_step1 is common for all c circuits
func (s *Session) c_step1(cNo int, body []byte) []byte {
	o := 0
	if cNo > 1 {
		hisCommit := body[:32]
		o += 32
		if !bytes.Equal(hisCommit, s.e.CommitHash[cNo-1]) {
			panic("output hashes don't match")
		}
	}
	hisBitsToFlip := body[o:]
	senderMsg := s.GetClientLabels(cNo)
	maskedToSend := s.otS.GetMaskedOT(hisBitsToFlip, senderMsg)
	inputLabels := s.GetNotaryLabels(cNo)
	myBitsToFlip := s.otR.RequestMaskedOT(s.g.Cs[cNo].InputBits)

	var salt []byte = nil
	if cNo > 1 {
		salt = s.e.Salt[cNo-1]
	}
	return u.Concat(
		salt,
		inputLabels,
		maskedToSend,
		myBitsToFlip)
}

// Client's inputs always come after the Notary's inputs in the circuit
func (s *Session) GetClientLabels(cNo int) []byte {
	// exeCount is how many executions of this circuit we need
	exeCount := []int{0, 1, 1, 1, 1, s.g.C5Count, s.g.C6Count}[cNo]
	c := &s.g.Cs[cNo]
	// chunkSize is the bytesize of input labels for one circuit execution
	chunkSize := (c.NotaryInputSize + c.ClientInputSize) * 32
	if chunkSize*exeCount != len(c.Il) {
		panic("(chunkSize * exeCount != len(c.Il))")
	}
	var allIl []byte
	for i := 0; i < exeCount; i++ {
		allIl = append(allIl, c.Il[i*chunkSize+c.NotaryInputSize*32:(i+1)*chunkSize]...)
	}
	return allIl
}

//  C_getInputLabels returns notary's input labels for the circuit
func (s *Session) GetNotaryLabels(cNo int) []byte {
	// exeCount is how many executions of this circuit we need
	exeCount := []int{0, 1, 1, 1, 1, s.g.C5Count, s.g.C6Count}[cNo]
	c := &s.g.Cs[cNo]
	// chunkSize is the bytesize of input labels for one circuit execution
	chunkSize := (c.NotaryInputSize + c.ClientInputSize) * 32
	if chunkSize*exeCount != len(c.Il) {
		panic("(chunkSize * exeCount != len(c.Il))")
	}
	var inputLabelBlob []byte
	for i := 0; i < exeCount; i++ {
		inputLabelBlob = append(inputLabelBlob,
			c.Il[i*chunkSize:i*chunkSize+c.NotaryInputSize*32]...)
	}
	if len(inputLabelBlob) != len(c.InputBits)*32 {
		panic("len(inputLabelBlob) != len(c.InputBits)*32")
	}

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

// given a slice of circuit inputs in the same order as expected by the c*.casm file,
// convert each input into a bit array with the least bit of each input at index[0]
func (s *Session) setCircuitInputs(cNo int, inputs ...[]byte) {
	for _, v := range inputs {
		s.g.Cs[cNo].InputBits = append(s.g.Cs[cNo].InputBits, u.BytesToBits(v)...)
	}
}

// c_step2 is common for all c circuits
func (s *Session) c_step2(cNo int, body []byte) ([]byte, []byte) {
	// exeCount is how many executions of this circuit we need
	exeCount := []int{0, 1, 1, 1, 1, s.g.C5Count, 1, s.g.C6Count}[cNo]
	notaryMaskedLabels := body[:s.g.Cs[cNo].NotaryInputSize*32*exeCount]
	clientLabels := body[s.g.Cs[cNo].NotaryInputSize*32*exeCount:]
	notaryLabels := s.otR.UnmaskOT(s.g.Cs[cNo].InputBits, notaryMaskedLabels)
	return notaryLabels, clientLabels
}

func (s *Session) C1_step1(encrypted []byte) []byte {
	s.sequenceCheck(9)
	body := s.decryptFromClient(encrypted)
	s.setCircuitInputs(1, s.notaryPMSShare, s.g.Cs[1].Masks[1])
	out := s.c_step1(1, body)
	return s.encryptToClient(out)
}

func (s *Session) C1_step2(encrypted []byte) []byte {
	s.sequenceCheck(10)
	body := s.decryptFromClient(encrypted)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(1)
	notaryLabels, clientLabels := s.c_step2(1, body)
	hash := s.e.Evaluate(1, notaryLabels, clientLabels, ttBlob, olBlob)
	// unmask the output
	s.g.Cs[1].PmsOuterHash = u.XorBytes(s.g.Cs[1].Output[32:64], s.g.Cs[1].Masks[1])
	return s.encryptToClient(hash)
}

// receive inner hash for a1
func (s *Session) C1_step3(encrypted []byte) []byte {
	s.sequenceCheck(11)
	body := s.decryptFromClient(encrypted)
	a1 := u.FinishHash(s.g.Cs[1].PmsOuterHash, body)
	return s.encryptToClient(a1)
}

// receive inner hash for a2
func (s *Session) C1_step4(encrypted []byte) []byte {
	s.sequenceCheck(12)
	body := s.decryptFromClient(encrypted)
	a2 := u.FinishHash(s.g.Cs[1].PmsOuterHash, body)
	return s.encryptToClient(a2)
}

// receive inner hash for p2
func (s *Session) C1_step5(encrypted []byte) []byte {
	s.sequenceCheck(13)
	body := s.decryptFromClient(encrypted)
	p2 := u.FinishHash(s.g.Cs[1].PmsOuterHash, body)
	return s.encryptToClient(p2)
}

func (s *Session) C2_step1(encrypted []byte) []byte {
	s.sequenceCheck(14)
	body := s.decryptFromClient(encrypted)
	s.setCircuitInputs(2, s.g.Cs[1].PmsOuterHash, s.g.Cs[2].Masks[1])
	out := s.c_step1(2, body)
	return s.encryptToClient(out)
}

func (s *Session) C2_step2(encrypted []byte) []byte {
	s.sequenceCheck(15)
	body := s.decryptFromClient(encrypted)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(2)
	notaryLabels, clientLabels := s.c_step2(2, body)
	hash := s.e.Evaluate(2, notaryLabels, clientLabels, ttBlob, olBlob)
	// TODO MsOuterHash must not belong to CData but to Session, since
	// it is part of the session
	s.g.Cs[2].MsOuterHash = u.XorBytes(s.g.Cs[2].Output[32:64], s.g.Cs[2].Masks[1])
	return s.encryptToClient(hash)
}

// receive inner hash for a1_2
func (s *Session) C2_step3(encrypted []byte) []byte {
	s.sequenceCheck(16)
	body := s.decryptFromClient(encrypted)
	a1inner_2 := body[:32]
	a1inner_vd := body[32:64]
	a1_2 := u.FinishHash(s.g.Cs[2].MsOuterHash, a1inner_2)
	a1_vd := u.FinishHash(s.g.Cs[2].MsOuterHash, a1inner_vd)
	return s.encryptToClient(u.Concat(a1_2, a1_vd))
}

// receive inner hash for a2_2
func (s *Session) C2_step4(encrypted []byte) []byte {
	s.sequenceCheck(17)
	body := s.decryptFromClient(encrypted)
	a2inner_2 := body[:32]
	p1inner_vd := body[32:64]
	a2_2 := u.FinishHash(s.g.Cs[2].MsOuterHash, a2inner_2)
	s.g.P1_vd = u.FinishHash(s.g.Cs[2].MsOuterHash, p1inner_vd)[:12]
	return s.encryptToClient(u.Concat(a2_2, s.g.P1_vd))
}

func (s *Session) C3_step1(encrypted []byte) []byte {
	s.sequenceCheck(18)
	body := s.decryptFromClient(encrypted)
	g := s.g
	s.setCircuitInputs(3,
		g.Cs[2].MsOuterHash,
		g.Cs[3].Masks[1],
		g.Cs[3].Masks[2],
		g.Cs[3].Masks[3],
		g.Cs[3].Masks[4],
		g.Cs[3].Masks[5],
		g.Cs[3].Masks[6])

	out := s.c_step1(3, body)
	return s.encryptToClient(out)
}

func (s *Session) C3_step2(encrypted []byte) []byte {
	s.sequenceCheck(19)
	body := s.decryptFromClient(encrypted)
	g := s.g
	ttBlob, olBlob := s.RetrieveBlobsForNotary(3)
	notaryLabels, clientLabels := s.c_step2(3, body)
	commit := s.e.Evaluate(3, notaryLabels, clientLabels, ttBlob, olBlob)
	// we unmask only those outputs which are relevant to the notary
	// the commented outputs below are not relevant, they are here
	// for reference
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
	s.sequenceCheck(20)
	body := s.decryptFromClient(encrypted)
	g := s.g
	if len(body) != 16+33 {
		panic("wrong len in c3_step3")
	}

	o := 0
	encCF := body[o : o+16]
	o += 16
	hisBitsToFlip := body[o : o+33]
	o += 33

	s.powersOfH[1] = g.Cs[3].Masks[5]
	s.powersOfH[2] = u.BlockMult(s.powersOfH[1], s.powersOfH[1])
	H1H2 := u.BlockMult(s.powersOfH[1], s.powersOfH[2])
	h1table := u.GetXTable(s.powersOfH[1])
	h2table := u.GetXTable(s.powersOfH[2])
	// maskSum is the xor sum of all masks
	maskSum := make([]byte, 16)

	var allMessages1 []byte
	for i := 0; i < 128; i++ {
		mask := u.GetRandom(16)
		maskSum = u.XorBytes(maskSum, mask)
		m0 := mask
		m1 := u.XorBytes(h1table[i], mask)
		allMessages1 = append(allMessages1, m0...)
		allMessages1 = append(allMessages1, m1...)
	}

	var allMessages2 []byte
	for i := 0; i < 128; i++ {
		mask := u.GetRandom(16)
		maskSum = u.XorBytes(maskSum, mask)
		m0 := mask
		m1 := u.XorBytes(h2table[i], mask)
		allMessages2 = append(allMessages2, m0...)
		allMessages2 = append(allMessages2, m1...)
	}

	// hisBitsToFlip contain a concatenation of client's H1 share bits and H2 share bits
	// (bits that need to be flipped). Client's H1 is mapped to notary's H2 and client's
	// H2 is mapped to notary's H1
	maskedOT := s.otS.GetMaskedOT(hisBitsToFlip, u.Concat(allMessages2, allMessages1))

	s.powersOfH[3] = u.XorBytes(maskSum, H1H2)

	aad := []byte{0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0}

	//lenA (before padding) == 13*8 == 104, lenC == 16*8 == 128
	lenAlenC := []byte{0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128}

	gctrShare := g.Cs[3].Masks[6]

	s1 := u.BlockMult(aad, s.powersOfH[3])
	s2 := u.BlockMult(encCF, s.powersOfH[2])
	s3 := u.BlockMult(lenAlenC, s.powersOfH[1])
	tagShare := u.XorBytes(u.XorBytes(u.XorBytes(s1, s2), s3), gctrShare)
	return s.encryptToClient(u.Concat(
		tagShare,
		maskedOT))
}

func (s *Session) C4_pre1(encrypted []byte) []byte {
	s.sequenceCheck(21)
	body := s.decryptFromClient(encrypted)
	a1inner := body[:]
	a1 := u.FinishHash(s.g.Cs[2].MsOuterHash, a1inner)
	return s.encryptToClient(a1)
}

func (s *Session) C4_step1(encrypted []byte) []byte {
	s.sequenceCheck(22)
	body := s.decryptFromClient(encrypted)
	g := s.g
	s.setCircuitInputs(4,
		g.Cs[2].MsOuterHash,
		g.Cs[3].Masks[1],
		g.Cs[3].Masks[3],
		g.Cs[4].Masks[1],
		g.Cs[4].Masks[2])

	if len(g.Cs[4].InputBits)/8 != 84 {
		panic("len(g.Cs[4].input) != 84")
	}
	out := s.c_step1(4, body)
	return s.encryptToClient(out)
}

func (s *Session) C4_step2(encrypted []byte) []byte {
	s.sequenceCheck(23)
	body := s.decryptFromClient(encrypted)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(4)
	notaryLabels, clientLabels := s.c_step2(4, body)
	hash := s.e.Evaluate(4, notaryLabels, clientLabels, ttBlob, olBlob)
	return s.encryptToClient(hash)
}

func (s *Session) C4_step3(encrypted []byte) []byte {
	s.sequenceCheck(24)
	body := s.decryptFromClient(encrypted)
	g := s.g
	if len(body) != 16+33 {
		panic("wrong len in c3_step4")
	}

	o := 0
	encSF := body[o : o+16]
	o += 16
	hisBitsToFlip := body[o : o+33]
	o += 33

	h1share := g.Cs[4].Masks[1]
	h2share := u.BlockMult(h1share, h1share)
	H1H2 := u.BlockMult(h1share, h2share)
	h1table := u.GetXTable(h1share)
	h2table := u.GetXTable(h2share)

	maskSum := make([]byte, 16) //notary's H3 share includes the sum of all masks

	var allMessages1 []byte
	for i := 0; i < 128; i++ {
		mask := u.GetRandom(16)
		maskSum = u.XorBytes(maskSum, mask)
		m0 := mask
		m1 := u.XorBytes(h1table[i], mask)
		allMessages1 = append(allMessages1, m0...)
		allMessages1 = append(allMessages1, m1...)
	}

	var allMessages2 []byte
	for i := 0; i < 128; i++ {
		mask := u.GetRandom(16)
		maskSum = u.XorBytes(maskSum, mask)
		m0 := mask
		m1 := u.XorBytes(h2table[i], mask)
		allMessages2 = append(allMessages2, m0...)
		allMessages2 = append(allMessages2, m1...)
	}
	// hisBitsToFlip contain a concatenation of client's H1 share bits and H2 share bits
	// (bits that need to be flipped). Client's H1 is mapped to notary's H2 and client's
	// H2 is mapped to notary's H1
	maskedOT := s.otS.GetMaskedOT(hisBitsToFlip, u.Concat(allMessages2, allMessages1))

	H3share := u.XorBytes(maskSum, H1H2)

	aad := []byte{0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0}
	//lenA (before padding) == 13*8 == 104, lenC == 16*8 == 128
	lenAlenC := []byte{0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128}

	gctrShare := g.Cs[4].Masks[2]

	s1 := u.BlockMult(aad, H3share)
	s2 := u.BlockMult(encSF, h2share)
	s3 := u.BlockMult(lenAlenC, h1share)
	tagShare := u.XorBytes(u.XorBytes(u.XorBytes(s1, s2), s3), gctrShare)

	return s.encryptToClient(u.Concat(
		tagShare,
		maskedOT))
}

func (s *Session) C5_step1(encrypted []byte) []byte {
	s.sequenceCheck(25)
	body := s.decryptFromClient(encrypted)
	g := s.g
	var allInputs [][]byte
	for i := 0; i < s.g.C5Count; i++ {
		allInputs = append(allInputs, g.Cs[3].Masks[2])
		allInputs = append(allInputs, g.Cs[3].Masks[4])
	}
	s.setCircuitInputs(5, allInputs...)
	out := s.c_step1(5, body)
	return s.encryptToClient(out)
}

func (s *Session) C5_step2(encrypted []byte) []byte {
	s.sequenceCheck(26)
	body := s.decryptFromClient(encrypted)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(5)
	notaryLabels, clientLabels := s.c_step2(5, body)
	hash := s.e.Evaluate(5, notaryLabels, clientLabels, ttBlob, olBlob)
	return s.encryptToClient(hash)
}

func (s *Session) C6_step1(encrypted []byte) []byte {
	s.sequenceCheck(27)
	body := s.decryptFromClient(encrypted)
	g := s.g
	var allInputs [][]byte
	for i := 0; i < s.g.C6Count; i++ {
		allInputs = append(allInputs, g.Cs[3].Masks[2])
		allInputs = append(allInputs, g.Cs[3].Masks[4])
		allInputs = append(allInputs, g.Cs[6].Masks[i+1])
	}
	s.setCircuitInputs(6, allInputs...)
	out := s.c_step1(6, body)
	return s.encryptToClient(out)
}

func (s *Session) C6_step2(encrypted []byte) []byte {
	s.sequenceCheck(28)
	body := s.decryptFromClient(encrypted)
	ttBlob, olBlob := s.RetrieveBlobsForNotary(6)
	notaryLabels, clientLabels := s.c_step2(6, body)
	hash := s.e.Evaluate(6, notaryLabels, clientLabels, ttBlob, olBlob)
	return s.encryptToClient(hash)
}

func (s *Session) CheckC6Commit(encrypted []byte) []byte {
	s.sequenceCheck(29)
	body := s.decryptFromClient(encrypted)
	hisCommit := body
	if !bytes.Equal(hisCommit, s.e.CommitHash[6]) {
		panic("commit hash doesn't match")
	}
	return s.encryptToClient(s.e.Salt[6])
}

func (s *Session) Ghash_step1(encrypted []byte) []byte {
	s.sequenceCheck(30)
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

	o := 0
	mpnBytes := body[o : o+2]
	o += 2

	s.maxPowerNeeded = int(binary.BigEndian.Uint16(mpnBytes))
	for k, v := range maxHTable {
		if v >= s.maxPowerNeeded {
			s.maxOddPowerNeeded = k
			log.Println("s.maxPowerNeeded", s.maxPowerNeeded)
			log.Println("s.maxOddPowerNeeded", s.maxOddPowerNeeded)
			break
		}
	}

	totalPowers := 0
	for k, v := range strategies {
		if v == nil {
			continue
		}
		if k > s.maxOddPowerNeeded {
			break
		}
		totalPowers += 2
	}
	log.Println("totalPowers", totalPowers)

	// client requests OT for each pair of powers in each item of the strategies,
	hisBitsToFlip := body[o : o+totalPowers*16+1]
	o += totalPowers*16 + 1

	if len(body) != o {
		panic("len(body) != o")
	}

	//perform free squaring on powers 2,3 which we have from client finished
	u.FreeSquare(&s.powersOfH, s.maxPowerNeeded)

	var allEntries [][]byte
	for k, v := range strategies {
		if v == nil {
			continue
		}
		if k > s.maxOddPowerNeeded {
			break
		}
		maskSum := make([]byte, 16) //starting with zeroed mask
		var twoXTables [][]byte
		twoXTables = append(twoXTables, u.GetXTable(s.powersOfH[v[1]])...)
		twoXTables = append(twoXTables, u.GetXTable(s.powersOfH[v[0]])...)
		for i := 0; i < 256; i++ {
			mask := u.GetRandom(16)
			maskSum = u.XorBytes(maskSum, mask)
			m0 := mask
			m1 := u.XorBytes(twoXTables[i], mask)
			allEntries = append(allEntries, m0)
			allEntries = append(allEntries, m1)
		}
		// get notary's N_x*N_y and then get the final share of power
		NxNy := u.BlockMult(s.powersOfH[v[0]], s.powersOfH[v[1]])
		s.powersOfH[k] = u.XorBytes(maskSum, NxNy)
	}
	u.FreeSquare(&s.powersOfH, s.maxPowerNeeded)
	maskedOT := s.otS.GetMaskedOT(hisBitsToFlip, u.Concat(allEntries...))
	return s.encryptToClient(maskedOT)
}

func (s *Session) Ghash_step2(encrypted []byte) []byte {
	s.sequenceCheck(31)
	body := s.decryptFromClient(encrypted)
	if len(body) != 16*16+1 {
		panic("16*16+1")
	}
	o := 0
	hisBitsToFlip := body[:o+16*16+1]

	// shows what shares of powers we will be multiplying to obtain other odd shares of powers
	// max sequential odd power that we can obtain on first round is 19
	// note that we multiply N_x*C_y and C_y*N_x to get cross-terms. These are not yet shares of powers
	// we must add N_x*N_y and C_x*C_y to respective cross-terms in order to get shares of powers
	strategies2 := [][]int{
		21: {17, 4},
		23: {17, 6},
		25: {17, 8},
		27: {19, 8},
		29: {17, 12},
		31: {19, 12},
		33: {17, 16},
		35: {19, 16}}

	var allEntries [][]byte
	for k, v := range strategies2 {
		if v == nil {
			continue
		}
		maskSum := make([]byte, 16) //starting with zeroed mask
		var twoXTables [][]byte
		twoXTables = append(twoXTables, u.GetXTable(s.powersOfH[v[1]])...)
		twoXTables = append(twoXTables, u.GetXTable(s.powersOfH[v[0]])...)
		for i := 0; i < 256; i++ {
			mask := u.GetRandom(16)
			maskSum = u.XorBytes(maskSum, mask)
			m0 := mask
			m1 := u.XorBytes(twoXTables[i], mask)
			allEntries = append(allEntries, m0)
			allEntries = append(allEntries, m1)
		}
		// get notary's N_x*N_y and then get the final share of power
		NxNy := u.BlockMult(s.powersOfH[v[0]], s.powersOfH[v[1]])
		s.powersOfH[k] = u.XorBytes(maskSum, NxNy)
	}
	u.FreeSquare(&s.powersOfH, s.maxPowerNeeded)
	maskedOT := s.otS.GetMaskedOT(hisBitsToFlip, u.Concat(allEntries...))
	return s.encryptToClient(maskedOT)
}

func (s *Session) Ghash_step3(encrypted []byte) []byte {
	s.sequenceCheck(32)
	body := s.decryptFromClient(encrypted)
	o := 0
	s.ghashInputsBlob = body[o : o+s.maxPowerNeeded*16]
	o += s.maxPowerNeeded * 16
	hisBitsToFlip := body[o:]

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
		x := ghashInputs[len(ghashInputs)-i]
		h := s.powersOfH[i]
		res = u.XorBytes(res, u.BlockMult(h, x))
	}

	// compute indirect powers, i.e. find powers for X*H
	aggregated := make([][]byte, 36) //starting with 1, 35 is the max that we'll ever need
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
		x := ghashInputs[len(ghashInputs)-i]
		res = u.XorBytes(res, u.BlockMult(u.BlockMult(
			s.powersOfH[a], s.powersOfH[b]), x))
		if aggregated[a] == nil {
			aggregated[a] = make([]byte, 16) //set to zero
		}
		aggregated[a] = u.XorBytes(aggregated[a], u.BlockMult(s.powersOfH[b], x))
	}
	s.ghashOutputShare = u.XorBytes(s.ghashOutputShare, res)

	nonNilItemsCount := 0
	for i := 0; i < len(aggregated); i++ {
		if aggregated[i] != nil {
			nonNilItemsCount += 1
		}
	}

	// client sent us bits for every small power and for every corresponding
	// aggregated value
	if nonNilItemsCount*2*16+1 != len(hisBitsToFlip) {
		log.Println("nonNilItemsCount", nonNilItemsCount, len(hisBitsToFlip))
		panic("nonNilItemsCount*2*16 != len(hisBitsToFlip)")
	}

	// arrange masked Xtable entries in this way:
	// for each entry in sumForPowers,
	// first the Xtables for the small power times x,
	// then the Xtable for each aggregated value times x
	var allEntries [][]byte
	maskSum := make([]byte, 16) //starting with zeroed mask
	for i := 0; i < len(aggregated); i++ {
		if aggregated[i] == nil {
			continue
		}
		var twoXTables [][]byte
		twoXTables = append(twoXTables, u.GetXTable(s.powersOfH[i])...)
		twoXTables = append(twoXTables, u.GetXTable(aggregated[i])...)
		for j := 0; j < 256; j++ {
			mask := u.GetRandom(16)
			maskSum = u.XorBytes(maskSum, mask)
			m0 := mask
			m1 := u.XorBytes(twoXTables[j], mask)
			allEntries = append(allEntries, m0)
			allEntries = append(allEntries, m1)
		}
	}
	maskedOT := s.otS.GetMaskedOT(hisBitsToFlip, u.Concat(allEntries...))
	s.ghashOutputShare = u.XorBytes(s.ghashOutputShare, maskSum)
	return s.encryptToClient(u.Concat(
		maskedOT,
		s.ghashOutputShare))
}

func (s *Session) CommitHash(encrypted []byte) []byte {
	s.sequenceCheck(33)
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
