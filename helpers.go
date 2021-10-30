package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

func genPrivkey() device.NoisePrivateKey {
	var key device.NoisePrivateKey
	_, err := rand.Read(key[:])
	if err != nil {
		panic(fmt.Sprintf("could not generate random key"))
	}
	return key
}

func devconfig(dev *device.Device) map[string]string {
	var buf bytes.Buffer
	err := dev.IpcGetOperation(&buf)
	if err != nil {
		return nil
	}
	conf := make(map[string]string)
	for _, line := range bytes.Split(buf.Bytes(), []byte{'\n'}) {
		vars := bytes.SplitN(line, []byte{'='}, 2)
		if len(vars) == 2 {
			conf[string(vars[0])] = string(vars[1])
		}
	}
	return conf
}

// copied from wireguard-go
func pubkey(sk *device.NoisePrivateKey) (pk device.NoisePublicKey) {
	apk := (*[device.NoisePublicKeySize]byte)(&pk)
	ask := (*[device.NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}
