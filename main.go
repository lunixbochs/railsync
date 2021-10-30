package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// copied from wireguard-go
func pubkey(sk *device.NoisePrivateKey) (pk device.NoisePublicKey) {
	apk := (*[device.NoisePublicKeySize]byte)(&pk)
	ask := (*[device.NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

type LoopTun struct {
	In  <-chan []byte
	Out chan<- []byte

	in  chan []byte
	out chan []byte

	mtu    int
	events chan tun.Event
}

func (tun *LoopTun) Name() (string, error) { return "loop", nil }
func (tun *LoopTun) File() *os.File        { return nil }
func (tun *LoopTun) Flush() error          { return nil }
func (tun *LoopTun) MTU() (int, error)     { return tun.mtu, nil }

func (tun *LoopTun) Events() chan tun.Event {
	return tun.events
}

func (tun *LoopTun) Close() error {
	close(tun.events)
	close(tun.in)
	return nil
}

func (tun *LoopTun) Read(buf []byte, offset int) (int, error) {
	if packet, ok := <-tun.out; ok {
		dst := buf[offset:]
		copy(dst, packet)
		return len(packet), nil
	}
	return 0, os.ErrClosed
}

func (tun *LoopTun) Write(buf []byte, offset int) (int, error) {
	packet := make([]byte, len(buf)-offset)
	tun.in <- packet
	return len(packet), nil
}

func NewLoopTun(mtu int, queuesize int) *LoopTun {
	in := make(chan []byte, queuesize)
	out := make(chan []byte, queuesize)
	dev := &LoopTun{
		In:  in,
		Out: out,
		in:  in,
		out: out,

		mtu:    mtu,
		events: make(chan tun.Event, 10),
	}
	dev.events <- tun.EventUp
	return dev
}

func keypair() (key1, key2 device.NoisePrivateKey) {
	_, err := rand.Read(key1[:])
	if err != nil {
		panic(fmt.Sprintf("could not generate random key"))
	}
	_, err = rand.Read(key2[:])
	if err != nil {
		panic(fmt.Sprintf("could not generate random key"))
	}
	return
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

func main() {
	key1, key2 := keypair()
	pubkey1, pubkey2 := pubkey(&key1), pubkey(&key2)
	localhost := net.ParseIP("127.0.0.1")

	pingPacket := tuntest.Ping(localhost, localhost)
	tun1 := NewLoopTun(1420, 1024)
	tun2 := NewLoopTun(1420, 1024)

	dev1 := device.NewDevice(tun1, conn.NewDefaultBind(), device.NewLogger(9999, "dev1 "))
	dev1.IpcSet("private_key=" + hex.EncodeToString(key1[:]))
	dev1.Up()

	dev2 := device.NewDevice(tun2, conn.NewDefaultBind(), device.NewLogger(9999, "dev2 "))
	dev2.IpcSet("private_key=" + hex.EncodeToString(key2[:]))
	dev2.Up()

	port1 := devconfig(dev1)["listen_port"]
	port2 := devconfig(dev2)["listen_port"]

	dev1.IpcSet(fmt.Sprintf(`public_key=%s
endpoint=127.0.0.1:%s
allowed_ip=0.0.0.0/0`, hex.EncodeToString(pubkey2[:]), port2))
	dev2.IpcSet(fmt.Sprintf(`public_key=%s
endpoint=127.0.0.1:%s
allowed_ip=0.0.0.0/0`, hex.EncodeToString(pubkey1[:]), port1))

	go func() {
		for packet := range tun2.In {
			fmt.Println("recv", len(packet))
		}
	}()

	for {
		fmt.Println("send", len(pingPacket))
		tun1.Out <- pingPacket
		time.Sleep(1 * time.Second)
	}

	time.Sleep(1000 * time.Second)
}
