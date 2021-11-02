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

func toHumanBits(number uint64) string {
	number *= 8
	table := []string{"bit", "kbit", "mbit", "gbit", "tbit", "pbit", "ebit"}
	fnumber := float64(number)
	for i, suffix := range table {
		if fnumber < 1024 || i == len(table)-1 {
			return fmt.Sprintf("%.2f %s", fnumber, suffix)
		}
		fnumber /= 1024
	}
	return fmt.Sprintf("%d bit", number)
}

func toHumanBytes(number uint64) string {
	table := []string{"B", "K", "M", "G", "T", "P", "E"}
	fnumber := float64(number)
	for i, suffix := range table {
		if fnumber < 1024 || i == len(table)-1 {
			return fmt.Sprintf("%.2f%s", fnumber, suffix)
		}
		fnumber /= 1024
	}
	return fmt.Sprintf("%dB", number)
}
