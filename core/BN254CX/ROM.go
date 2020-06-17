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

/* Fixed Data in ROM - Field and Curve parameters */

package BN254CX

// Base Bits= 56
var Modulus = [...]Chunk{0x6623EF5C1B55B3, 0xD6EE18093EE1BE, 0x647A6366D3243F, 0x8702A0DB0BDDF, 0x24000000}
var ROI = [...]Chunk{0x6623EF5C1B55B2, 0xD6EE18093EE1BE, 0x647A6366D3243F, 0x8702A0DB0BDDF, 0x24000000}
var R2modp = [...]Chunk{0x466A0618A0800A, 0x2B3A22543056A3, 0x148515B09C6600, 0xEC9EA5606BDF50, 0x1C992E66}

const MConst Chunk = 0x4E205BF9789E85

var Fra = [...]Chunk{0xD9083355C80EA3, 0x7326F173F8215B, 0x8AACA718986867, 0xA63A0164AFE18B, 0x1359082F}
var Frb = [...]Chunk{0x8D1BBC06534710, 0x63C7269546C062, 0xD9CDBC4E3ABBD8, 0x623628A900DC53, 0x10A6F7D0}

const CURVE_Cof_I int = 1
const CURVE_A int = 0
const CURVE_B_I int = 2

var CURVE_B = [...]Chunk{0x2, 0x0, 0x0, 0x0, 0x0}
var CURVE_Order = [...]Chunk{0x11C0A636EB1F6D, 0xD6EE0CC906CEBE, 0x647A6366D2C43F, 0x8702A0DB0BDDF, 0x24000000}
var CURVE_Gx = [...]Chunk{0x6623EF5C1B55B2, 0xD6EE18093EE1BE, 0x647A6366D3243F, 0x8702A0DB0BDDF, 0x24000000}
var CURVE_Gy = [...]Chunk{0x1, 0x0, 0x0, 0x0, 0x0}
var CURVE_Bnx = [...]Chunk{0x3C012B1, 0x40, 0x0, 0x0, 0x0}
var CURVE_Cof = [...]Chunk{0x1, 0x0, 0x0, 0x0, 0x0}
var CURVE_Cru = [...]Chunk{0xE0931794235C97, 0xDF6471EF875631, 0xCA83F1440BD, 0x480000, 0x0}

var CURVE_Pxa = [...]Chunk{0x851CEEE4D2EC74, 0x85BFA03E2726C0, 0xF5C34BBB907C, 0x7053B256358B25, 0x19682D2C}
var CURVE_Pxb = [...]Chunk{0xA58E8B2E29CFE1, 0x97B0C209C30F47, 0x37A8E99743F81B, 0x3E19F64AA011C9, 0x1466B9EC}
var CURVE_Pya = [...]Chunk{0xFBFCEBCF0BE09F, 0xB33D847EC1B30C, 0x157DAEE2096361, 0x72332B8DD81E22, 0xA79EDD9}
var CURVE_Pyb = [...]Chunk{0x904B228898EE9D, 0x4EA569D2EDEBED, 0x512D8D3461C286, 0xECC4C09035C6E4, 0x6160C39}

var CURVE_W = [2][5]Chunk{{0x546349162FEB83, 0xB40381200, 0x6000, 0x0, 0x0}, {0x7802561, 0x80, 0x0, 0x0, 0x0}}
var CURVE_SB = [2][2][5]Chunk{{{0x5463491DB010E4, 0xB40381280, 0x6000, 0x0, 0x0}, {0x7802561, 0x80, 0x0, 0x0, 0x0}}, {{0x7802561, 0x80, 0x0, 0x0, 0x0}, {0xBD5D5D20BB33EA, 0xD6EE0188CEBCBD, 0x647A6366D2643F, 0x8702A0DB0BDDF, 0x24000000}}}
var CURVE_WB = [4][5]Chunk{{0x1C2118567A84B0, 0x3C012B040, 0x2000, 0x0, 0x0}, {0xCDF995BE220475, 0x94EDA8CA7F9A36, 0x8702A0DC07E, 0x300000, 0x0}, {0x66FCCAE0F10B93, 0x4A76D4653FCD3B, 0x4381506E03F, 0x180000, 0x0}, {0x1C21185DFAAA11, 0x3C012B0C0, 0x2000, 0x0, 0x0}}
var CURVE_BB = [4][4][5]Chunk{{{0x11C0A6332B0CBD, 0xD6EE0CC906CE7E, 0x647A6366D2C43F, 0x8702A0DB0BDDF, 0x24000000}, {0x11C0A6332B0CBC, 0xD6EE0CC906CE7E, 0x647A6366D2C43F, 0x8702A0DB0BDDF, 0x24000000}, {0x11C0A6332B0CBC, 0xD6EE0CC906CE7E, 0x647A6366D2C43F, 0x8702A0DB0BDDF, 0x24000000}, {0x7802562, 0x80, 0x0, 0x0, 0x0}}, {{0x7802561, 0x80, 0x0, 0x0, 0x0}, {0x11C0A6332B0CBC, 0xD6EE0CC906CE7E, 0x647A6366D2C43F, 0x8702A0DB0BDDF, 0x24000000}, {0x11C0A6332B0CBD, 0xD6EE0CC906CE7E, 0x647A6366D2C43F, 0x8702A0DB0BDDF, 0x24000000}, {0x11C0A6332B0CBC, 0xD6EE0CC906CE7E, 0x647A6366D2C43F, 0x8702A0DB0BDDF, 0x24000000}}, {{0x7802562, 0x80, 0x0, 0x0, 0x0}, {0x7802561, 0x80, 0x0, 0x0, 0x0}, {0x7802561, 0x80, 0x0, 0x0, 0x0}, {0x7802561, 0x80, 0x0, 0x0, 0x0}}, {{0x3C012B2, 0x40, 0x0, 0x0, 0x0}, {0xF004AC2, 0x100, 0x0, 0x0, 0x0}, {0x11C0A62F6AFA0A, 0xD6EE0CC906CE3E, 0x647A6366D2C43F, 0x8702A0DB0BDDF, 0x24000000}, {0x3C012B2, 0x40, 0x0, 0x0, 0x0}}}

