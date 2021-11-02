package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

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

func selftest() {
	pipe1, err := NewPipe(1420, 1)
	if err != nil {
		panic(err)
	}
	pipe2, err := NewPipe(1420, 1)
	if err != nil {
		panic(err)
	}
	pipe1.Connect("127.0.0.1", pipe2.Port(), pipe2.Pubkey())
	pipe2.Connect("127.0.0.1", pipe1.Port(), pipe1.Pubkey())

	go func() {
		start := time.Now()
		lastPrint := start
		seen := make(map[uint64]bool)
		dropped := uint64(0)
		minNonce := uint64(0)
		maxNonce := uint64(0)
		totalPackets := uint64(0)
		totalBytes := uint64(0)
		for packet := range pipe2.In {
			nonce := binary.BigEndian.Uint64(packet[:8])
			seen[nonce] = true
			if nonce > maxNonce {
				maxNonce = nonce
			}
			totalPackets += 1
			totalBytes += uint64(len(packet))
			if totalPackets%128 == 0 && time.Since(lastPrint).Seconds() >= 1.0 {
				lastPrint = time.Now()
				elapsed := lastPrint.Sub(start).Seconds()

				for i := minNonce; i < maxNonce; i++ {
					if !seen[i] {
						dropped++
					}
				}
				dropPercent := float64(dropped) / float64(maxNonce) * 100
				transferred := float64(totalBytes) / 1024 / 1024 / 1024
				rate := (transferred / elapsed) * 8
				fmt.Printf("[recv] elapsed=%.2fs  packets=%d  data=%.2f GB  rate=%.3f gbit/s  dropped=%d (%.2f%%)\n", elapsed, totalPackets, transferred, rate, dropped, dropPercent)
				minNonce = maxNonce
				seen = make(map[uint64]bool)
			}
		}
	}()

	start := time.Now()
	lastPrint := start
	nonce := uint64(0)
	totalBytes := uint64(0)
	for {
		packet := make([]byte, pipe1.MTU)
		binary.BigEndian.PutUint64(packet[:8], nonce)
		pipe1.Out <- packet
		nonce += 1
		totalBytes += uint64(len(packet))
		if nonce%128 == 0 && time.Since(lastPrint).Seconds() >= 1.0 {
			lastPrint = time.Now()
			elapsed := lastPrint.Sub(start).Seconds()
			transferred := float64(totalBytes) / 1024 / 1024 / 1024
			rate := (transferred / elapsed) * 8
			fmt.Printf("[send] elapsed=%.2fs  packets=%d  data=%.2f GB  rate=%.3f gbit/s\n", elapsed, nonce, transferred, rate)
		}
	}
}

func main() {
	selftest()
}
