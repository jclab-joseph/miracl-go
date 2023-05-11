/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Test driver and function exerciser for Boneh-Lynn-Shacham BLS Signature API Functions */

/* To reverse the groups G1 and G2, edit BLS*.go
Swap G1 <-> G2
Swap ECP <-> ECPn
Disable G2 precomputation
Switch G1/G2 parameter order in pairing function calls
Swap G1S and G2S in this program
See CPP library version for example
*/

package main

import (
	"fmt"
	"github.com/jclab-joseph/miracl-go/core/BLS12381"
	"github.com/stretchr/testify/assert"
	"testing"
)

import "github.com/jclab-joseph/miracl-go/core/BN254"
import "github.com/jclab-joseph/miracl-go/core/BLS12383"
import "github.com/jclab-joseph/miracl-go/core/BLS24479"
import "github.com/jclab-joseph/miracl-go/core/BLS48556"

func Test_bls_BN254_SignVerify(t *testing.T) {

	const BGS = BN254.BGS
	const BFS = BN254.BFS
	const G1S = BFS + 1   /* Group 1 Size */
	const G2S = 2*BFS + 1 /* Group 2 Size */

	var S [BGS]byte
	var W [G2S]byte
	var SIG [G1S]byte
	var IKM [32]byte

	for i := 0; i < len(IKM); i++ {
		//IKM[i] = byte(i+1)
		IKM[i] = byte(rng.GetByte())
	}

	fmt.Printf("\nTesting Boneh-Lynn-Shacham BLS signature code\n")
	mess := "This is a test message"

	res := BN254.Init()
	assert.Equal(t, 0, res)

	res = BN254.KeyPairGenerate(IKM[:], S[:], W[:])
	assert.Equal(t, 0, res)

	fmt.Printf("Private key : 0x")
	printBinary(S[:])
	fmt.Printf("Public  key : 0x")
	printBinary(W[:])

	BN254.Core_Sign(SIG[:], []byte(mess), S[:])
	fmt.Printf("Signature : 0x")
	printBinary(SIG[:])

	res = BN254.Core_Verify(SIG[:], []byte(mess), W[:])
	assert.Equal(t, 0, res)
}

func Test_bls_BLS12381_SignVerify(t *testing.T) {

	const BGS = BLS12381.BGS
	const BFS = BLS12381.BFS
	const G1S = BFS + 1   /* Group 1 Size */
	const G2S = 2*BFS + 1 /* Group 2 Size */

	var S [BGS]byte
	var W [G2S]byte
	var SIG [G1S]byte
	var IKM [32]byte

	for i := 0; i < len(IKM); i++ {
		//IKM[i] = byte(i+1)
		IKM[i] = byte(rng.GetByte())
	}

	fmt.Printf("\nTesting Boneh-Lynn-Shacham BLS signature code\n")
	mess := "This is a test message"

	res := BLS12381.Init()
	if res != 0 {
		fmt.Printf("Failed to Initialize\n")
		return
	}

	res = BLS12381.KeyPairGenerate(IKM[:], S[:], W[:])
	assert.Equal(t, 0, res)

	fmt.Printf("Private key : 0x")
	printBinary(S[:])
	fmt.Printf("Public  key : 0x")
	printBinary(W[:])

	BLS12381.Core_Sign(SIG[:], []byte(mess), S[:])
	fmt.Printf("Signature : 0x")
	printBinary(SIG[:])

	res = BLS12381.Core_Verify(SIG[:], []byte(mess), W[:])
	assert.Equal(t, 0, res)
}

func Test_bls_BLS12383_SignVerify(t *testing.T) {

	const BGS = BLS12383.BGS
	const BFS = BLS12383.BFS
	const G1S = BFS + 1   /* Group 1 Size */
	const G2S = 2*BFS + 1 /* Group 2 Size */

	var S [BGS]byte
	var W [G2S]byte
	var SIG [G1S]byte
	var IKM [32]byte

	for i := 0; i < len(IKM); i++ {
		//IKM[i] = byte(i+1)
		IKM[i] = byte(rng.GetByte())
	}

	fmt.Printf("\nTesting Boneh-Lynn-Shacham BLS signature code\n")
	mess := "This is a test message"

	res := BLS12383.Init()
	if res != 0 {
		fmt.Printf("Failed to Initialize\n")
		return
	}

	res = BLS12383.KeyPairGenerate(IKM[:], S[:], W[:])
	assert.Equal(t, 0, res)

	fmt.Printf("Private key : 0x")
	printBinary(S[:])
	fmt.Printf("Public  key : 0x")
	printBinary(W[:])

	BLS12383.Core_Sign(SIG[:], []byte(mess), S[:])
	fmt.Printf("Signature : 0x")
	printBinary(SIG[:])

	res = BLS12383.Core_Verify(SIG[:], []byte(mess), W[:])
	assert.Equal(t, 0, res)
}

func Test_bls_BLS24479_SignVerify(t *testing.T) {

	const BGS = BLS24479.BGS
	const BFS = BLS24479.BFS
	const G1S = BFS + 1   /* Group 1 Size */
	const G2S = 4*BFS + 1 /* Group 2 Size */

	var S [BGS]byte
	var W [G2S]byte
	var SIG [G1S]byte
	var IKM [48]byte

	for i := 0; i < len(IKM); i++ {
		//IKM[i] = byte(i+1)
		IKM[i] = byte(rng.GetByte())
	}

	fmt.Printf("\nTesting Boneh-Lynn-Shacham BLS signature code\n")
	mess := "This is a test message"

	res := BLS24479.Init()
	assert.Equal(t, 0, res)

	res = BLS24479.KeyPairGenerate(IKM[:], S[:], W[:])
	assert.Equal(t, 0, res)

	fmt.Printf("Private key : 0x")
	printBinary(S[:])
	fmt.Printf("Public  key : 0x")
	printBinary(W[:])

	BLS24479.Core_Sign(SIG[:], []byte(mess), S[:])
	fmt.Printf("Signature : 0x")
	printBinary(SIG[:])

	res = BLS24479.Core_Verify(SIG[:], []byte(mess), W[:])
	assert.Equal(t, 0, res)
}

func Test_bls_BLS48556_SignVerify(t *testing.T) {

	const BGS = BLS48556.BGS
	const BFS = BLS48556.BFS
	const G1S = BFS + 1   /* Group 1 Size */
	const G2S = 8*BFS + 1 /* Group 2 Size */

	var S [BGS]byte
	var W [G2S]byte
	var SIG [G1S]byte
	var IKM [64]byte

	for i := 0; i < len(IKM); i++ {
		//IKM[i] = byte(i+1)
		IKM[i] = byte(rng.GetByte())
	}

	fmt.Printf("\nTesting Boneh-Lynn-Shacham BLS signature code\n")
	mess := "This is a test message"

	res := BLS48556.Init()
	assert.Equal(t, 0, res)

	res = BLS48556.KeyPairGenerate(IKM[:], S[:], W[:])
	assert.Equal(t, 0, res)

	fmt.Printf("Private key : 0x")
	printBinary(S[:])
	fmt.Printf("Public  key : 0x")
	printBinary(W[:])

	BLS48556.Core_Sign(SIG[:], []byte(mess), S[:])
	fmt.Printf("Signature : 0x")
	printBinary(SIG[:])

	res = BLS48556.Core_Verify(SIG[:], []byte(mess), W[:])
	assert.Equal(t, 0, res)
}

func Test_bls_BLS12381_PairingZ(t *testing.T) {
	P := BLS12381.ECP2_generator()
	Q := BLS12381.ECP_generator()
	z := BLS12381.Ate(P, Q)
	assert.Equal(t, "[[[043be6f062687b2871ec929b215beb21bd777fc2526913827528eb36be610d644c9f1471d8a50b8044cf9a05f4073a5c,17d542694a1f0540b82ebab355b4b70ec772093d7bb5ec8df0638026ba4d7021599121e640c3c00b16fb8b30815708fc],[0160b1bfa0f809c2978c214332188a0ee0b5284e1ecc9b98de21e18e19136da9c5b215138467d577f8def0c5c65dc881,0a583fbcc2cb1f28f0d9f7e3956c63e689c01629b2edac6642bbcad7f1beb1f214ff63e9303de93599693679d5700e0b]],[[13c6b5e2e3c1a53972594696ce9e69c9938c0737ce5f9f64f431a737c9a9be3d058b203e16eb3a5ab237890329c8815f,051445fb01745550c5cb8f4c38f15c125388a658a80edb5ef9ce599903dda9f3034c294c6cd68c0b89680e8ad3fe26bc],[0f194ab322c4a346e03e6811fc389f01da8f5d97d7c0f9db87d70d2f15458666aeaccc17e41763d5b41abed5c2dd193e,08d170e996b92742c35dc81a4bde6ccf830cff1840b44be1212b605ca70ea685883e9725b22e2e9c4dfd5691be6783f9]],[[0166fd54cf7557dc1d8687b24232c467f25cd54e0441a6610bf90321c9d1b5f9758aaa810c39d197a41054103682ad7b,00329385757b44b4b79315333b875d22acce78aebbe908b24e120f570fddd97d9a26aff9d43c1e66756bb4003467ec1f],[15dd606065d26ab2a4cf88a9668713a23653f6358a8e58b190c5efa8e39a6bc8fd1aa22cf53a3512707fc9ae1f1d1c6a,1514ac1ce4871af629a62fde9a7bd935b887228673d9d1cce1a49a1ff149c1777691750f43a102a140cad37ca59e7b79]]]", z.ToString())
}
