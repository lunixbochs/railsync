package main

import (
	"encoding/binary"
	"fmt"
	"time"
)

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
