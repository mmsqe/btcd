// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// GenerateSharedSecret generates a shared secret based on a private key and a
// public key using Diffie-Hellman key exchange (ECDH) (RFC 4753).
// RFC5903 Section 9 states we should only return x.
func GenerateSharedSecret(privkey *PrivateKey, pubkey *PublicKey) []byte {
	secret := secp.GenerateSharedSecret(privkey, pubkey)
	cipherKey := sha256.Sum256(secret)
	plaintext := []byte("test message")
	aead, err := newAEAD(cipherKey[:])
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize())
	ephemeralPubKey := pubkey.SerializeCompressed()
	ciphertext := make([]byte, 4+len(ephemeralPubKey))
	binary.LittleEndian.PutUint32(ciphertext, uint32(len(ephemeralPubKey)))
	copy(ciphertext[4:], ephemeralPubKey)
	// encrypt
	ciphertext = aead.Seal(ciphertext, nonce, plaintext, ephemeralPubKey)
	// decrypt
	pubKeyLen := binary.LittleEndian.Uint32(ciphertext[:4])
	senderPubKeyBytes := ciphertext[4 : 4+pubKeyLen]
	senderPubKey, err := secp.ParsePubKey(senderPubKeyBytes)
	if err != nil {
		panic(err)
	}
	recoveredCipherKey := sha256.Sum256(secp.GenerateSharedSecret(privkey, senderPubKey))
	// Open the sealed message.
	aead, err = newAEAD(recoveredCipherKey[:])
	if err != nil {
		panic(err)
	}
	recoveredPlaintext, err := aead.Open(nil, nonce, ciphertext[4+pubKeyLen:], senderPubKeyBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println("mm-recoveredPlaintext", recoveredPlaintext)
	return secret
}
