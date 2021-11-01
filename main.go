package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type Pipe struct {
	privkey device.NoisePrivateKey
	pubkey  device.NoisePublicKey
	port    uint16
	In      <-chan []byte
	Out     chan<- []byte
	*device.Device
}

func NewPipe(mtu int, queuesize int) (*Pipe, error) {
	tun := NewLoopTun(mtu, queuesize)
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(0, ""))
	privkey := genPrivkey()
	pubkey := pubkey(&privkey)
	dev.IpcSet("private_key=" + hex.EncodeToString(privkey[:]))
	dev.Up()

	config := devconfig(dev)
	var port int
	if portstr, ok := config["listen_port"]; !ok {
		return nil, errors.New("device has no listen_port")
	} else if porti, err := strconv.Atoi(portstr); err != nil {
		return nil, errors.Wrap(err, "listen_port invalid")
	} else {
		port = porti
	}

	pipe := &Pipe{
		privkey: privkey,
		pubkey:  pubkey,
		port:    uint16(port),
		In:      tun.In,
		Out:     tun.Out,
		Device:  dev,
	}
	return pipe, nil
}

func (p *Pipe) Port() uint16 {
	return p.port
}

func (p *Pipe) Pubkey() device.NoisePublicKey {
	return p.pubkey
}

func (p *Pipe) Connect(host string, port uint16, pubkey device.NoisePublicKey) error {
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("invalid IP")
	}
	p.Device.IpcSet(fmt.Sprintf(`public_key=%s
endpoint=%s:%d
allowed_ip=0.0.0.0/0`, hex.EncodeToString(pubkey[:]), ip, port))
	return nil
}

func main() {
	pipe1, err := NewPipe(1420, 1024)
	if err != nil {
		panic(err)
	}

	pipe2, err := NewPipe(1420, 1024)
	if err != nil {
		panic(err)
	}

	pipe1.Connect("127.0.0.1", pipe2.Port(), pipe2.Pubkey())
	pipe2.Connect("127.0.0.1", pipe1.Port(), pipe1.Pubkey())

	localhost := net.ParseIP("127.0.0.1")
	pingPacket := tuntest.Ping(localhost, localhost)

	go func() {
		for packet := range pipe2.In {
			fmt.Println("recv", len(packet))
		}
	}()

	for {
		fmt.Println("send", len(pingPacket))
		pipe1.Out <- pingPacket
		time.Sleep(1 * time.Second)
	}

	time.Sleep(1000 * time.Second)
}
