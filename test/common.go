package main

import (
	"fmt"
	"github.com/jclab-joseph/miracl-go/core"
)

var (
	rng = core.NewRAND()
)

func init() {
	var raw [100]byte
	for i := 0; i < 100; i++ {
		raw[i] = byte(i + 1)
	}
	rng.Seed(100, raw[:])
}

func printBinary(array []byte) {
	for i := 0; i < len(array); i++ {
		fmt.Printf("%02x", array[i])
	}
	fmt.Printf("\n")
}
