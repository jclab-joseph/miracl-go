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

package BLS48556

// Curve types
const WEIERSTRASS int = 0
const EDWARDS int = 1
const MONTGOMERY int = 2

// Pairing Friendly?
const NOT int = 0
const BN int = 1
const BLS int = 2

// Pairing Twist type
const D_TYPE int = 0
const M_TYPE int = 1

// Sparsity
const FP_ZERO int = 0
const FP_ONE int = 1
const FP_SPARSEST int = 2
const FP_SPARSER int = 3
const FP_SPARSE int = 4
const FP_DENSE int = 5

// Pairing x parameter sign
const POSITIVEX int = 0
const NEGATIVEX int = 1

// Curve type

const CURVETYPE int = WEIERSTRASS
const CURVE_PAIRING_TYPE int = BLS

// Pairings only

const SEXTIC_TWIST int = M_TYPE
const SIGN_OF_X int = POSITIVEX
const ATE_BITS int = 42
const G2_TABLE int = 35

// associated hash function and AES key size

const HASH_TYPE int = 64
const AESKEY int = 32

// These are manually decided policy decisions. To block any potential patent issues set to false.

const USE_GLV bool = true
const USE_GS_G2 bool = true
const USE_GS_GT bool = true

