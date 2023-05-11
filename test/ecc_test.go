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

/* test driver and function exerciser for ECDH/ECIES/ECDSA API Functions */

package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

import "github.com/jclab-joseph/miracl-go/core"
import "github.com/jclab-joseph/miracl-go/core/ED25519"
import "github.com/jclab-joseph/miracl-go/core/NIST256"
import "github.com/jclab-joseph/miracl-go/core/GOLDILOCKS"

func Test_ecdh_ED25519(t *testing.T) {
	//	j:=0
	pp := "M0ng00se"
	res := 0

	var sha = ED25519.HASH_TYPE

	var S1 [ED25519.EGS]byte
	var W0 [2*ED25519.EFS + 1]byte
	var W1 [2*ED25519.EFS + 1]byte
	var Z0 [ED25519.EFS]byte
	var Z1 [ED25519.EFS]byte
	var SALT [8]byte
	var P1 [3]byte
	var P2 [4]byte
	var V [2*ED25519.EFS + 1]byte
	var M [17]byte
	var T [12]byte
	var CS [ED25519.EGS]byte
	var DS [ED25519.EGS]byte

	for i := 0; i < 8; i++ {
		SALT[i] = byte(i + 1)
	} // set Salt

	fmt.Printf("\nTesting ECDH/ECDSA/ECIES for curve ED25519\n")
	fmt.Printf("Alice's Passphrase= " + pp)
	fmt.Printf("\n")
	PW := []byte(pp)

	/* private key S0 of size MGS bytes derived from Password and Salt */

	S0 := core.PBKDF2(core.MC_SHA2, sha, PW, SALT[:], 1000, ED25519.EGS)

	fmt.Printf("Alice's private key= 0x")
	printBinary(S0)

	/* Generate Key pair S/W */
	ED25519.ECDH_KEY_PAIR_GENERATE(nil, S0, W0[:])

	fmt.Printf("Alice's public key= 0x")
	printBinary(W0[:])

	res = ED25519.ECDH_PUBLIC_KEY_VALIDATE(W0[:])
	assert.Equal(t, 0, res, "ECP Public Key is invalid")

	/* Random private key for other party */
	ED25519.ECDH_KEY_PAIR_GENERATE(rng, S1[:], W1[:])

	fmt.Printf("Servers private key= 0x")
	printBinary(S1[:])

	fmt.Printf("Servers public key= 0x")
	printBinary(W1[:])

	res = ED25519.ECDH_PUBLIC_KEY_VALIDATE(W1[:])
	assert.Equal(t, 0, res, "ECP Public Key is invalid")
	/* Calculate common key using DH - IEEE 1363 method */

	ED25519.ECDH_ECPSVDP_DH(S0, W1[:], Z0[:], 0)
	ED25519.ECDH_ECPSVDP_DH(S1[:], W0[:], Z1[:], 0)

	same := true
	for i := 0; i < ED25519.EFS; i++ {
		if Z0[i] != Z1[i] {
			same = false
		}
	}

	assert.True(t, same, "ECPSVDP-DH Failed")

	KEY := core.KDF2(core.MC_SHA2, sha, Z0[:], nil, ED25519.AESKEY)

	fmt.Printf("Alice's DH Key=  0x")
	printBinary(KEY)
	fmt.Printf("Servers DH Key=  0x")
	printBinary(KEY)

	if ED25519.CURVETYPE != ED25519.MONTGOMERY {
		fmt.Printf("Testing ECIES\n")

		P1[0] = 0x0
		P1[1] = 0x1
		P1[2] = 0x2
		P2[0] = 0x0
		P2[1] = 0x1
		P2[2] = 0x2
		P2[3] = 0x3

		for i := 0; i <= 16; i++ {
			M[i] = byte(i)
		}

		C := ED25519.ECDH_ECIES_ENCRYPT(sha, P1[:], P2[:], rng, W1[:], M[:], V[:], T[:])

		fmt.Printf("Ciphertext= \n")
		fmt.Printf("V= 0x")
		printBinary(V[:])
		fmt.Printf("C= 0x")
		printBinary(C)
		fmt.Printf("T= 0x")
		printBinary(T[:])

		RM := ED25519.ECDH_ECIES_DECRYPT(sha, P1[:], P2[:], V[:], C, T[:], S1[:])
		assert.NotNil(t, RM, "ECIES Decryption Failed")

		fmt.Printf("Message is 0x")
		printBinary(RM)

		fmt.Printf("Testing ECDSA\n")

		r := ED25519.ECDH_ECPSP_DSA(sha, rng, S0, M[:], CS[:], DS[:])
		assert.Equal(t, r, 0, "ECDSA Signature Failed")

		fmt.Printf("Signature= \n")
		fmt.Printf("C= 0x")
		printBinary(CS[:])
		fmt.Printf("D= 0x")
		printBinary(DS[:])

		r = ED25519.ECDH_ECPVP_DSA(sha, W0[:], M[:], CS[:], DS[:])
		assert.Equal(t, r, 0, "ECDSA Signature Failed")
	}
}

func Test_ecdh_NIST256(t *testing.T) {
	//	j:=0
	pp := "M0ng00se"
	res := 0

	var sha = NIST256.HASH_TYPE

	var S1 [NIST256.EGS]byte
	var W0 [2*NIST256.EFS + 1]byte
	var W1 [2*NIST256.EFS + 1]byte
	var Z0 [NIST256.EFS]byte
	var Z1 [NIST256.EFS]byte
	var SALT [8]byte
	var P1 [3]byte
	var P2 [4]byte
	var V [2*NIST256.EFS + 1]byte
	var M [17]byte
	var T [12]byte
	var CS [NIST256.EGS]byte
	var DS [NIST256.EGS]byte

	for i := 0; i < 8; i++ {
		SALT[i] = byte(i + 1)
	} // set Salt

	fmt.Printf("\nTesting ECDH/ECDSA/ECIES for curve NIST256\n")
	fmt.Printf("Alice's Passphrase= " + pp)
	fmt.Printf("\n")
	PW := []byte(pp)

	/* private key S0 of size MGS bytes derived from Password and Salt */

	S0 := core.PBKDF2(core.MC_SHA2, sha, PW, SALT[:], 1000, NIST256.EGS)

	fmt.Printf("Alice's private key= 0x")
	printBinary(S0)

	/* Generate Key pair S/W */
	NIST256.ECDH_KEY_PAIR_GENERATE(nil, S0, W0[:])

	fmt.Printf("Alice's public key= 0x")
	printBinary(W0[:])

	res = NIST256.ECDH_PUBLIC_KEY_VALIDATE(W0[:])
	if res != 0 {
		fmt.Printf("ECP Public Key is invalid!\n")
		return
	}

	/* Random private key for other party */
	NIST256.ECDH_KEY_PAIR_GENERATE(rng, S1[:], W1[:])

	fmt.Printf("Servers private key= 0x")
	printBinary(S1[:])

	fmt.Printf("Servers public key= 0x")
	printBinary(W1[:])

	res = NIST256.ECDH_PUBLIC_KEY_VALIDATE(W1[:])
	if res != 0 {
		fmt.Printf("ECP Public Key is invalid!\n")
		return
	}
	/* Calculate common key using DH - IEEE 1363 method */

	NIST256.ECDH_ECPSVDP_DH(S0, W1[:], Z0[:], 0)
	NIST256.ECDH_ECPSVDP_DH(S1[:], W0[:], Z1[:], 0)

	same := true
	for i := 0; i < NIST256.EFS; i++ {
		if Z0[i] != Z1[i] {
			same = false
		}
	}

	if !same {
		fmt.Printf("*** ECPSVDP-DH Failed\n")
		return
	}

	KEY := core.KDF2(core.MC_SHA2, sha, Z0[:], nil, NIST256.AESKEY)

	fmt.Printf("Alice's DH Key=  0x")
	printBinary(KEY)
	fmt.Printf("Servers DH Key=  0x")
	printBinary(KEY)

	if NIST256.CURVETYPE != NIST256.MONTGOMERY {
		fmt.Printf("Testing ECIES\n")

		P1[0] = 0x0
		P1[1] = 0x1
		P1[2] = 0x2
		P2[0] = 0x0
		P2[1] = 0x1
		P2[2] = 0x2
		P2[3] = 0x3

		for i := 0; i <= 16; i++ {
			M[i] = byte(i)
		}

		C := NIST256.ECDH_ECIES_ENCRYPT(sha, P1[:], P2[:], rng, W1[:], M[:], V[:], T[:])

		fmt.Printf("Ciphertext= \n")
		fmt.Printf("V= 0x")
		printBinary(V[:])
		fmt.Printf("C= 0x")
		printBinary(C)
		fmt.Printf("T= 0x")
		printBinary(T[:])

		RM := NIST256.ECDH_ECIES_DECRYPT(sha, P1[:], P2[:], V[:], C, T[:], S1[:])
		if RM == nil {
			fmt.Printf("*** ECIES Decryption Failed\n")
			return
		} else {
			fmt.Printf("Decryption succeeded\n")
		}

		fmt.Printf("Message is 0x")
		printBinary(RM)

		fmt.Printf("Testing ECDSA\n")

		if NIST256.ECDH_ECPSP_DSA(sha, rng, S0, M[:], CS[:], DS[:]) != 0 {
			fmt.Printf("***ECDSA Signature Failed\n")
			return
		}
		fmt.Printf("Signature= \n")
		fmt.Printf("C= 0x")
		printBinary(CS[:])
		fmt.Printf("D= 0x")
		printBinary(DS[:])

		if NIST256.ECDH_ECPVP_DSA(sha, W0[:], M[:], CS[:], DS[:]) != 0 {
			fmt.Printf("***ECDSA Verification Failed\n")
			return
		} else {
			fmt.Printf("ECDSA Signature/Verification succeeded \n")
		}
	}
}

func Test_ecdh_GOLDILOCKS(t *testing.T) {
	//	j:=0
	pp := "M0ng00se"
	res := 0

	var sha = GOLDILOCKS.HASH_TYPE

	var S1 [GOLDILOCKS.EGS]byte
	var W0 [2*GOLDILOCKS.EFS + 1]byte
	var W1 [2*GOLDILOCKS.EFS + 1]byte
	var Z0 [GOLDILOCKS.EFS]byte
	var Z1 [GOLDILOCKS.EFS]byte
	var SALT [8]byte
	var P1 [3]byte
	var P2 [4]byte
	var V [2*GOLDILOCKS.EFS + 1]byte
	var M [17]byte
	var T [12]byte
	var CS [GOLDILOCKS.EGS]byte
	var DS [GOLDILOCKS.EGS]byte

	for i := 0; i < 8; i++ {
		SALT[i] = byte(i + 1)
	} // set Salt

	fmt.Printf("\nTesting ECDH/ECDSA/ECIES for curve GOLDILOCKS\n")
	fmt.Printf("Alice's Passphrase= " + pp)
	fmt.Printf("\n")
	PW := []byte(pp)

	/* private key S0 of size MGS bytes derived from Password and Salt */

	S0 := core.PBKDF2(core.MC_SHA2, sha, PW, SALT[:], 1000, GOLDILOCKS.EGS)

	fmt.Printf("Alice's private key= 0x")
	printBinary(S0)

	/* Generate Key pair S/W */
	GOLDILOCKS.ECDH_KEY_PAIR_GENERATE(nil, S0, W0[:])

	fmt.Printf("Alice's public key= 0x")
	printBinary(W0[:])

	res = GOLDILOCKS.ECDH_PUBLIC_KEY_VALIDATE(W0[:])
	assert.Equal(t, 0, res)

	/* Random private key for other party */
	GOLDILOCKS.ECDH_KEY_PAIR_GENERATE(rng, S1[:], W1[:])

	fmt.Printf("Servers private key= 0x")
	printBinary(S1[:])

	fmt.Printf("Servers public key= 0x")
	printBinary(W1[:])

	res = GOLDILOCKS.ECDH_PUBLIC_KEY_VALIDATE(W1[:])
	assert.Equal(t, 0, res)
	/* Calculate common key using DH - IEEE 1363 method */

	GOLDILOCKS.ECDH_ECPSVDP_DH(S0, W1[:], Z0[:], 0)
	GOLDILOCKS.ECDH_ECPSVDP_DH(S1[:], W0[:], Z1[:], 0)

	same := true
	for i := 0; i < GOLDILOCKS.EFS; i++ {
		if Z0[i] != Z1[i] {
			same = false
		}
	}

	assert.True(t, same, "ECPSVDP-DH")

	KEY := core.KDF2(core.MC_SHA2, sha, Z0[:], nil, GOLDILOCKS.AESKEY)

	fmt.Printf("Alice's DH Key=  0x")
	printBinary(KEY)
	fmt.Printf("Servers DH Key=  0x")
	printBinary(KEY)

	if GOLDILOCKS.CURVETYPE != GOLDILOCKS.MONTGOMERY {
		fmt.Printf("Testing ECIES\n")

		P1[0] = 0x0
		P1[1] = 0x1
		P1[2] = 0x2
		P2[0] = 0x0
		P2[1] = 0x1
		P2[2] = 0x2
		P2[3] = 0x3

		for i := 0; i <= 16; i++ {
			M[i] = byte(i)
		}

		C := GOLDILOCKS.ECDH_ECIES_ENCRYPT(sha, P1[:], P2[:], rng, W1[:], M[:], V[:], T[:])

		fmt.Printf("Ciphertext= \n")
		fmt.Printf("V= 0x")
		printBinary(V[:])
		fmt.Printf("C= 0x")
		printBinary(C)
		fmt.Printf("T= 0x")
		printBinary(T[:])

		RM := GOLDILOCKS.ECDH_ECIES_DECRYPT(sha, P1[:], P2[:], V[:], C, T[:], S1[:])
		assert.NotNil(t, RM, "ECIES Decryption")

		fmt.Printf("Message is 0x")
		printBinary(RM)

		fmt.Printf("Testing ECDSA\n")

		r := GOLDILOCKS.ECDH_ECPSP_DSA(sha, rng, S0, M[:], CS[:], DS[:])
		assert.Equal(t, 0, r, "ECDH_ECPSP_DSA Verification")

		fmt.Printf("Signature= \n")
		fmt.Printf("C= 0x")
		printBinary(CS[:])
		fmt.Printf("D= 0x")
		printBinary(DS[:])

		r = GOLDILOCKS.ECDH_ECPVP_DSA(sha, W0[:], M[:], CS[:], DS[:])
		assert.Equal(t, 0, r, "ECDH_ECPVP_DSA Verification")
	}
}
