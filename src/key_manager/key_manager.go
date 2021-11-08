package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"log"
	u "notary/utils"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type KeyManager struct {
	sync.Mutex
	// Blob contains validFrom|validUntil|pubkey|signature
	// the client will verify the signature (made with the masterKey)
	Blob []byte
	// PrivKey is the ephemeral key used to sign a session. Also used
	// in ECDH with the the client to derive symmetric keys to encrypt the communication
	PrivKey *ecdsa.PrivateKey
	// masterKey is used to sign ephemeral keys
	masterKey *ecdsa.PrivateKey
	// MasterPubKeyPEM is masterKey public key in PEM format
	MasterPubKeyPEM []byte
	// validMins is how many minutes an ephemeral key is valid for signing
	validMins int
}

func (k *KeyManager) Init() {
	k.generateMasterKey()
	go k.rotateEphemeralKeys()
}

func (k *KeyManager) generateMasterKey() {
	// masterKey is only used to sign ephemeral keys
	var err error
	k.masterKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln("Could not create keys:", err)
	}
	k.MasterPubKeyPEM = u.ECDSAPubkeyToPEM(&k.masterKey.PublicKey)
	curDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filepath.Join(curDir, "public.key"), k.MasterPubKeyPEM, 0644)
	if err != nil {
		panic(err)
	}
}

// generate a new ephemeral key after a certain interval
// sign it with the master key
func (k *KeyManager) rotateEphemeralKeys() {
	k.validMins = 20
	nextKeyRotationTime := time.Unix(0, 0)
	for {
		time.Sleep(time.Second * 1)
		now := time.Now()
		if nextKeyRotationTime.Sub(now) > time.Minute*2 {
			continue
		}
		// to protect against side-channel attacks, we don't want the attacker to know when
		// exactly next key change happens; picking a random interval
		randInt := u.RandInt(k.validMins/2*60, k.validMins*60)
		nextKeyRotationTime = now.Add(time.Second * time.Duration(randInt))

		// else change the ephemeral key
		log.Println("changing ephemeral key")
		validFrom := make([]byte, 4)
		binary.BigEndian.PutUint32(validFrom, uint32(now.Unix()))
		validUntil := make([]byte, 4)
		untilTime := now.Add(time.Second * time.Duration(k.validMins*60))
		binary.BigEndian.PutUint32(validUntil, uint32(untilTime.Unix()))
		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalln("Could not create keys:", err)
		}
		pubkey := u.Concat([]byte{0x04}, u.To32Bytes(newKey.PublicKey.X), u.To32Bytes(newKey.PublicKey.Y))
		signature := u.ECDSASign(k.masterKey, validFrom, validUntil, pubkey)
		blob := u.Concat(validFrom, validUntil, pubkey, signature)
		k.Lock()
		k.Blob = blob
		k.PrivKey = newKey
		k.Unlock()
	}
}
