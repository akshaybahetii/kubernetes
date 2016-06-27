// Copyright 2015 Apcera Inc. All rights reserved.

package sec

import (
	"testing"

	"github.com/apcera/gossl"
)

func prepareKeys(tb testing.TB, size int) (pub, priv []byte) {
	key, err := gossl.NewECKey(size)
	if err != nil {
		tb.Fatalf("Error on NewECKey for original keypair: %s", err)
	}
	defer key.Free()
	if err := key.Generate(); err != nil {
		tb.Fatalf("Error on key.Generate: %s", err)
	}

	pubBytes, err := key.PubKey()
	if err != nil {
		tb.Fatalf("Error on key.PubKey: %s", err)
	}

	privBytes, err := key.PrivKey()
	if err != nil {
		tb.Fatalf("Error on key.PrivKey: %s", err)
	}

	return pubBytes, privBytes
}
