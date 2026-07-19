package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {
	// Setup AEAD
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)

	nonce := make([]byte, 12)
	
	// Sender side:
	// out initially has outer_header (16 bytes) + inner_packet (say, 50 bytes)
	outerHeader := []byte("1234567890123456") // 16 bytes
	innerPacket := []byte("this is some inner packet that is already encrypted")
	
	out := append([]byte(nil), outerHeader...)
	out = append(out, innerPacket...)
	
	// ad = out
	// plaintext = nil
	// Seal appends the 16-byte tag to out
	ciphertext := aead.Seal(out, nonce, nil, out)
	fmt.Printf("Sender wire packet length: %d\n", len(ciphertext))

	// Receiver side:
	// Received packet is 'ciphertext'
	receivedOuterHeader := ciphertext[:16]
	receivedInnerAndTag := ciphertext[16:]
	
	// Receiver tries to decrypt:
	// pt, err := Decrypt(out, receivedOuterHeader, receivedInnerAndTag)
	pt, err := aead.Open(nil, nonce, receivedInnerAndTag, receivedOuterHeader)
	if err != nil {
		fmt.Printf("Receiver decryption failed: %v\n", err)
	} else {
		fmt.Printf("Receiver decryption succeeded! pt len: %d\n", len(pt))
	}
}
