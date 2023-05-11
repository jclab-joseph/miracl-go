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

/* test driver and function exerciser for RSA API Functions */

package main

import (
	"fmt"
	"github.com/jclab-joseph/miracl-go/core"
	"github.com/jclab-joseph/miracl-go/core/RSA2048"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_rsa_2048(t *testing.T) {
	var sha = RSA2048.RSA_HASH_TYPE
	message := "Hello World\n"

	pub := RSA2048.New_public_key(RSA2048.FFLEN)
	priv := RSA2048.New_private_key(RSA2048.HFLEN)

	var ML [RSA2048.RFS]byte
	var C [RSA2048.RFS]byte
	var S [RSA2048.RFS]byte

	fmt.Printf("\nTesting RSA 2048-bit\n")
	fmt.Printf("Generating public/private key pair\n")
	RSA2048.RSA_KEY_PAIR(rng, 65537, priv, pub)

	M := []byte(message)

	fmt.Printf("Encrypting test string\n")
	E := core.RSA_OAEP_ENCODE(sha, M, rng, nil, RSA2048.RFS) /* OAEP encode message M to E  */

	RSA2048.RSA_ENCRYPT(pub, E, C[:]) /* encrypt encoded message */
	fmt.Printf("Ciphertext= 0x")
	printBinary(C[:])

	fmt.Printf("Decrypting test string\n")
	RSA2048.RSA_DECRYPT(priv, C[:], ML[:])
	MS := core.RSA_OAEP_DECODE(sha, nil, ML[:], RSA2048.RFS) /* OAEP decode message  */

	message = string(MS)
	fmt.Printf(message)

	T := core.RSA_PSS_ENCODE(sha, M, rng, RSA2048.RFS)
	fmt.Printf("T= 0x")
	printBinary(T[:])
	r := core.RSA_PSS_VERIFY(sha, M, T)
	assert.True(t, r, "PSS Encoding")

	fmt.Printf("Signing message\n")
	core.RSA_PKCS15(sha, M, C[:], RSA2048.RFS)

	RSA2048.RSA_DECRYPT(priv, C[:], S[:]) /* create signature in S */

	fmt.Printf("Signature= 0x")
	printBinary(S[:])

	RSA2048.RSA_ENCRYPT(pub, S[:], ML[:])

	cmp := true
	if len(C) != len(ML) {
		cmp = false
	} else {
		for j := 0; j < len(C); j++ {
			if C[j] != ML[j] {
				cmp = false
			}
		}
	}
	assert.True(t, cmp, "Signature verify")
}
