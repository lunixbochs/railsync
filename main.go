package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func main() {
	key1, key2 := genPrivkey(), genPrivkey()
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
