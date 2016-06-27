// Copyright 2015 Apcera Inc. All rights reserved.

package sec

import (
	"encoding/base64"
	"errors"
	"strings"
	"sync"

	"github.com/apcera/gossl"
)

// encryptBytes encrypts the plaintext with AES GCM encryption.
func encryptBytes(
	keyBitSize, hashBitSize int,
	plainText, iv, aad []byte,
	receiverPubKey, senderPrivKey *gossl.ECKey,
	senderID, receiverID string,
) (cipherText, tag []byte, err error) {

	sharedSecret, err := gossl.ECDHComputeKey(keyBitSize, hashBitSize,
		receiverPubKey, senderPrivKey, []byte(senderID), []byte(receiverID))
	if err != nil {
		return nil, nil, err
	}

	return gossl.AESgcmEncrypt(sharedSecret, iv, aad, plainText)
}

// decryptBytes decrypts ciphertext encrypted by AES GCM.
func decryptBytes(
	keyBitSize, hashBitSize int,
	cipherText, iv, aad, tag []byte,
	receiverPrivKey, senderPubKey *gossl.ECKey,
	senderID, receiverID string,
) ([]byte, error) {

	sharedSecret, err := gossl.ECDHComputeKey(keyBitSize, hashBitSize,
		senderPubKey, receiverPrivKey, []byte(senderID), []byte(receiverID))
	if err != nil {
		return nil, err
	}

	return gossl.AESgcmDecrypt(sharedSecret, iv, aad, cipherText, tag)
}

// signBytes generates a signature for a payload using the specified
// private key.
func signBytes(
	hashBitSize int,
	payload []byte,
	senderPrivateKey *gossl.ECKey,
) ([]byte, error) {

	digest := make([]byte, hashBitSize/8)
	if err := gossl.SHA(payload, digest); err != nil {
		return nil, err
	}

	return senderPrivateKey.Sign(digest)
}

// verifyBytes verifies the payload signature using the specified
// public key.
func verifyBytes(
	digestBitSize int,
	payload []byte, sig []byte,
	senderPubKey *gossl.ECKey,
) error {

	digest := make([]byte, digestBitSize/8)
	if err := gossl.SHA(payload, digest); err != nil {
		return err
	}

	sigValid, err := senderPubKey.Verify(digest, sig)
	if err != nil {
		return err
	}

	if !sigValid {
		return errors.New("invalid signature")
	}

	return nil
}

// TODO(oleg): add LRU to key cache once we have key rotation.

// kmu is a mutex that must be used for any operations with 'keys'
// map.
var kmu sync.Mutex

// keys contains cached gossl.ECKey objects. gossl.ECKey requires
// being freed explicitly, so it's hard to share between goroutines
// (e.g. if one goroutine frees the key, another one will panic on any
// operation with this key). There are several ways to alleviate that:
// pass keys as byte slices and inflate them as needed is one of them,
// but this results in a severe performance penalty: SetupSign() makes
// signing operations about 50 times faster, but it has to be called
// on every new gossl.ECKey object used for signing; inflating the key
// invalidates this optimization. Since we only have one keypair per
// component, it seems fine to keep a single copy of every gossl.ECKey
// object per byte slice key representation. This way callers can
// always work with byte slices and avoid any explicit freeing, while
// internally this package can maintain a cache of preconditioned
// keys.
var keys = map[string]*gossl.ECKey{}

// ecPrivKey returns gossl.ECKey with private key bytes set to
// keyBytes. If the key with the same bytes has been seen before, it's
// retrieved from the key cache. This is done so that we can call
// SetupSign on a key without making a caller work with gossl.ECKey
// objects that are notoriously hard to use b/c of explicit
// Free(). Caller is not responsible for freeing the key.
func ecPrivKey(keySize int, keyBytes []byte) (*gossl.ECKey, error) {
	kmu.Lock()
	defer kmu.Unlock()

	if key, ok := keys[string(keyBytes)]; ok {
		return key, nil
	}

	key, err := gossl.NewECKey(keySize)
	if err != nil {
		return nil, err
	}

	if err := key.SetPrivKey(keyBytes); err != nil {
		key.Free()
		return nil, err
	}

	if err := key.SetupSign(); err != nil {
		key.Free()
		return nil, err
	}

	keys[string(keyBytes)] = key

	return key, nil
}

// ecPubKey returns gossl.ECKey with public key bytes set to
// keyBytes. Caller is NOT responsible for freeing the key.
func ecPubKey(keySize int, keyBytes []byte) (*gossl.ECKey, error) {
	kmu.Lock()
	defer kmu.Unlock()

	if key, ok := keys[string(keyBytes)]; ok {
		return key, nil
	}

	key, err := gossl.NewECKey(keySize)
	if err != nil {
		return nil, err
	}

	if err := key.SetPubKey(keyBytes); err != nil {
		key.Free()
		return nil, err
	}

	keys[string(keyBytes)] = key

	return key, nil
}

// base64Decode decodes a base64-encoded value, adding any missing
// padding before decoding if necessary.
func base64Decode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(pad(s))
}

// base64Encode encodes a value with base64 URL encoding. Any padding
// bytes are trimmed.
func base64Encode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// pad adds any missing base64 padding to the value.
func pad(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}
