package main

import (
	"encoding/binary"
	"os"

	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

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
		header := buf[offset : offset+ipv4.HeaderLen]
		body := buf[offset+ipv4.HeaderLen:]
		lengthField := header[device.IPv4offsetTotalLength : device.IPv4offsetTotalLength+2]
		// write fake ipv4 header
		header[0] = 4 << 4
		binary.BigEndian.PutUint16(lengthField, uint16(ipv4.HeaderLen+len(packet)))
		copy(header[device.IPv4offsetSrc:], []byte{169, 254, 0, 1})
		copy(header[device.IPv4offsetDst:], []byte{169, 254, 0, 1})
		copy(body, packet)
		return ipv4.HeaderLen + len(packet), nil
	}
	return 0, os.ErrClosed
}

func (tun *LoopTun) Write(buf []byte, offset int) (int, error) {
	// ignore ipv4 header
	offset += ipv4.HeaderLen
	packet := make([]byte, len(buf)-offset)
	copy(packet, buf[offset:])
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
