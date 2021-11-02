package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/device"
)

func sendtest(pipe *Pipe) {
	start := time.Now()
	lastPrint := start
	nonce := uint64(0)
	totalBytes := uint64(0)
	for {
		packet := make([]byte, pipe.MTU)
		binary.BigEndian.PutUint64(packet[:8], nonce)
		pipe.Out <- packet
		nonce += 1
		totalBytes += uint64(len(packet))
		if nonce%128 == 0 && time.Since(lastPrint).Seconds() >= 1.0 {
			lastPrint = time.Now()
			elapsed := lastPrint.Sub(start).Seconds()
			humanTransfer := toHumanBytes(totalBytes)
			humanRate := toHumanBits(uint64(float64(totalBytes) / elapsed))
			fmt.Fprintf(os.Stderr, "[send] elapsed=%.2fs  packets=%d  data=%s  rate=%s/s\n", elapsed, nonce, humanTransfer, humanRate)
		}
		time.Sleep(1 * time.Microsecond)
	}
}

func recvtest(pipe *Pipe) {
	start := time.Now()
	lastPrint := start
	seen := make(map[uint64]bool)
	dropped := uint64(0)
	minNonce := uint64(0)
	maxNonce := uint64(0)
	totalPackets := uint64(0)
	totalBytes := uint64(0)
	for packet := range pipe.In {
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
			humanTransfer := toHumanBytes(totalBytes)
			humanRate := toHumanBits(uint64(float64(totalBytes) / elapsed))
			fmt.Fprintf(os.Stderr, "[recv] elapsed=%.2fs  packets=%d  data=%s  rate=%s/s  dropped=%d (%.2f%%)\n", elapsed, totalPackets, humanTransfer, humanRate, dropped, dropPercent)
			minNonce = maxNonce
			seen = make(map[uint64]bool)
		}
	}
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

	go recvtest(pipe2)
	sendtest(pipe1)
}

func getSshIP(host string) ([]net.IP, error) {
	cmd := exec.Command("ssh", "-G", host)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("hostname ")) {
			hostname := string(bytes.TrimSpace(line[len("hostname "):]))
			return net.LookupIP(hostname)
		}
	}
	return nil, errors.New("no SSH hostname found")
}

func getHostIP(host string) ([]net.IP, error) {
	if ips, err := getSshIP(host); err == nil {
		return ips, nil
	}
	return net.LookupIP(host)
}

func parseHandshake(line string) (port uint16, pubkey device.NoisePublicKey, err error) {
	line = strings.TrimSpace(line)
	components := strings.SplitN(line, " ", 2)
	portStr, pubkeyHex := components[0], components[1]
	err = pubkey.FromHex(pubkeyHex)
	if err != nil {
		return
	}
	portInt, err := strconv.Atoi(portStr)
	port = uint16(portInt)
	return
}

func main() {
	host := os.Args[1]
	if host == "--server" {
		pipe, err := NewPipe(1420, 1)
		if err != nil {
			panic(err)
		}

		fmt.Println(pipe.Port(), pipe.PubkeyHex())
		reader := bufio.NewReader(os.Stdin)
		line, _, err := reader.ReadLine()
		if err != nil {
			panic(err)
		}
		port, pubkey, err := parseHandshake(string(line))
		if err != nil {
			panic(err)
		}
		pipe.Connect("0.0.0.0", port, pubkey)
		recvtest(pipe)
	} else {
		pipe, err := NewPipe(1420, 1)
		if err != nil {
			panic(err)
		}

		ips, err := getHostIP(host)
		if err != nil {
			panic(err)
		}
		if len(ips) == 0 {
			panic("no IP found for host")
		}
		ip := ips[0]

		cmd := exec.Command("ssh", host, "railsync/railsync", "--server")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			panic(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			panic(err)
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			panic(err)
		}
		go io.Copy(os.Stderr, stderr)

		if err := cmd.Start(); err != nil {
			panic(err)
		}

		reader := bufio.NewReader(stdout)
		line, _, err := reader.ReadLine()
		if err != nil {
			panic(err)
		}
		port, pubkey, err := parseHandshake(string(line))
		if err != nil {
			panic(err)
		}
		stdin.Write([]byte(fmt.Sprintf("%d %s\n", pipe.Port(), pipe.PubkeyHex())))
		pipe.Connect(ip.String(), port, pubkey)
		sendtest(pipe)
	}
}
