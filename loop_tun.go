package main

import (
	"os"

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
