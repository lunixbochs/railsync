package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	"github.com/pkg/errors"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

type Pipe struct {
	privkey device.NoisePrivateKey
	pubkey  device.NoisePublicKey
	port    uint16
	MTU     int
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
		MTU:     mtu - ipv4.HeaderLen,
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

func (p *Pipe) PubkeyHex() string {
	return hex.EncodeToString(p.pubkey[:])
}

func (p *Pipe) Connect(host string, port uint16, pubkey device.NoisePublicKey) error {
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("invalid IP")
	}
	p.Device.IpcSet(fmt.Sprintf(`public_key=%s
endpoint=%s:%d
allowed_ip=169.254.0.0/16`, hex.EncodeToString(pubkey[:]), ip, port))
	return nil
}
