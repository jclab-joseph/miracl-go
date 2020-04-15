/*
   Copyright (C) 2019 MIRACL UK Ltd.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.


    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

     https://www.gnu.org/licenses/agpl-3.0.en.html

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   You can be released from the requirements of the license by purchasing
   a commercial license. Buying such a license is mandatory as soon as you
   develop commercial activities involving the MIRACL Core Crypto SDK
   without disclosing the source code of your own applications, or shipping
   the MIRACL Core Crypto SDK with a closed source product.
*/

/* Finite Field arithmetic */
/* CLINT mod p functions */

package BN254CX
import "go.bryk.io/miracl/core"

type FP struct {
	x   *BIG
	XES int32
}

/* Constructors */

func NewFP() *FP {
	F := new(FP)
	F.x = NewBIG()
	F.XES = 1
	return F
}

func NewFPint(a int) *FP {
	F := new(FP)
	if a < 0 {
		m := NewBIGints(Modulus)
		m.inc(a); m.norm();
		F.x = NewBIGcopy(m)
	} else {
		F.x = NewBIGint(a)
	}
	F.nres()
	return F
}

func NewFPbig(a *BIG) *FP {
	F := new(FP)
	F.x = NewBIGcopy(a)
	F.nres()
	return F
}

func NewFPcopy(a *FP) *FP {
	F := new(FP)
	F.x = NewBIGcopy(a.x)
	F.XES = a.XES
	return F
}

func NewFPrand(rng *core.RAND) *FP {
	m := NewBIGints(Modulus)
	w := Randomnum(m,rng)
	F := NewFPbig(w)
	return F
}

func (F *FP) toString() string {
	F.reduce()
	return F.redc().ToString()
}

/* convert to Montgomery n-residue form */
func (F *FP) nres() {
	if MODTYPE != PSEUDO_MERSENNE && MODTYPE != GENERALISED_MERSENNE {
		r := NewBIGints(R2modp)
		d := mul(F.x, r)
		F.x.copy(mod(d))
		F.XES = 2
	} else {
		md := NewBIGints(Modulus)
		F.x.Mod(md)
		F.XES = 1
	}
}

/* convert back to regular form */
func (F *FP) redc() *BIG {
	if MODTYPE != PSEUDO_MERSENNE && MODTYPE != GENERALISED_MERSENNE {
		d := NewDBIGscopy(F.x)
		return mod(d)
	} else {
		r := NewBIGcopy(F.x)
		return r
	}
}

/* reduce a DBIG to a BIG using the appropriate form of the modulus */

func mod(d *DBIG) *BIG {
	if MODTYPE == PSEUDO_MERSENNE {
		t := d.split(MODBITS)
		b := NewBIGdcopy(d)

		v := t.pmul(int(MConst))

		t.add(b)
		t.norm()

		tw := t.w[NLEN-1]
		t.w[NLEN-1] &= TMASK
		t.w[0] += (MConst * ((tw >> TBITS) + (v << (BASEBITS - TBITS))))

		t.norm()
		return t
	}
	if MODTYPE == MONTGOMERY_FRIENDLY {
		for i := 0; i < NLEN; i++ {
			top, bot := muladd(d.w[i], MConst-1, d.w[i], d.w[NLEN+i-1])
			d.w[NLEN+i-1] = bot
			d.w[NLEN+i] += top
		}
		b := NewBIG()

		for i := 0; i < NLEN; i++ {
			b.w[i] = d.w[NLEN+i]
		}
		b.norm()
		return b
	}

	if MODTYPE == GENERALISED_MERSENNE { // GoldiLocks only
		t := d.split(MODBITS)
		b := NewBIGdcopy(d)
		b.add(t)
		dd := NewDBIGscopy(t)
		dd.shl(MODBITS / 2)

		tt := dd.split(MODBITS)
		lo := NewBIGdcopy(dd)
		b.add(tt)
		b.add(lo)
		b.norm()
		tt.shl(MODBITS / 2)
		b.add(tt)

		carry := b.w[NLEN-1] >> TBITS
		b.w[NLEN-1] &= TMASK
		b.w[0] += carry

		ix := 224/int(BASEBITS)
		b.w[ix] += carry << (224 % BASEBITS)
		b.norm()
		return b
	}

	if MODTYPE == NOT_SPECIAL {
		md := NewBIGints(Modulus)
		return monty(md, MConst, d)
	}
	return NewBIG()
}

// find appoximation to quotient of a/m
// Out by at most 2.
// Note that MAXXES is bounded to be 2-bits less than half a word
func quo(n *BIG, m *BIG) int {
	var num Chunk
	var den Chunk
	hb := uint(CHUNK) / 2
	if TBITS < hb {
		sh := hb - TBITS
		num = (n.w[NLEN-1] << sh) | (n.w[NLEN-2] >> (BASEBITS - sh))
		den = (m.w[NLEN-1] << sh) | (m.w[NLEN-2] >> (BASEBITS - sh))

	} else {
		num = n.w[NLEN-1]
		den = m.w[NLEN-1]
	}
	return int(num / (den + 1))
}

/* reduce this mod Modulus */
func (F *FP) reduce() {
	m := NewBIGints(Modulus)
	r := NewBIGints(Modulus)
	var sb uint
	F.x.norm()

	if F.XES > 16 {
		q := quo(F.x, m)
		carry := r.pmul(q)
		r.w[NLEN-1] += carry << BASEBITS
		F.x.sub(r)
		F.x.norm()
		sb = 2
	} else {
		sb = logb2(uint32(F.XES - 1))
	}

	m.fshl(sb)
	for sb > 0 {
		sr := ssn(r, F.x, m)
		F.x.cmove(r, 1-sr)
		sb -= 1
	}

	F.XES = 1
}

/* test this=0? */
func (F *FP) iszilch() bool {
	W := NewFPcopy(F)
	W.reduce()
	return W.x.iszilch()
}

func (F *FP) isunity() bool {
	W:=NewFPcopy(F)
	W.reduce()
	return W.redc().isunity()
}

/* copy from FP b */
func (F *FP) copy(b *FP) {
	F.x.copy(b.x)
	F.XES = b.XES
}

/* set this=0 */
func (F *FP) zero() {
	F.x.zero()
	F.XES = 1
}

/* set this=1 */
func (F *FP) one() {
	F.x.one()
	F.nres()
}

/* return sign */
func (F *FP) sign() int {
	if BIG_ENDIAN_SIGN {
		m := NewBIGints(Modulus)
		m.dec(1)
		m.fshr(1)
		n := NewFPcopy(F);
		n.reduce()
		w := n.redc()
		cp:=Comp(w,m)
		return ((cp+1)&2)>>1		
	} else {
		W:=NewFPcopy(F)
		W.reduce()
		return W.redc().parity()
	}
}

/* normalise this */
func (F *FP) norm() {
	F.x.norm()
}

/* swap FPs depending on d */
func (F *FP) cswap(b *FP, d int) {
	c := int32(d)
	c = ^(c - 1)
	t := c & (F.XES ^ b.XES)
	F.XES ^= t
	b.XES ^= t
	F.x.cswap(b.x, d)
}

/* copy FPs depending on d */
func (F *FP) cmove(b *FP, d int) {
	F.x.cmove(b.x, d)
	c := int32(-d)
	F.XES ^= (F.XES ^ b.XES) & c
}

/* this*=b mod Modulus */
func (F *FP) mul(b *FP) {

	if int64(F.XES)*int64(b.XES) > int64(FEXCESS) {
		F.reduce()
	}

	d := mul(F.x, b.x)
	F.x.copy(mod(d))
	F.XES = 2
}

/* this = -this mod Modulus */
func (F *FP) neg() {
	m := NewBIGints(Modulus)
	sb := logb2(uint32(F.XES - 1))

	m.fshl(sb)
	F.x.rsub(m)

	F.XES = (1 << sb) + 1
	if F.XES > FEXCESS {
		F.reduce()
	}
}

/* this*=c mod Modulus, where c is a small int */
func (F *FP) imul(c int) {
	//	F.norm()
	s := false
	if c < 0 {
		c = -c
		s = true
	}

	if MODTYPE == PSEUDO_MERSENNE || MODTYPE == GENERALISED_MERSENNE {
		d := F.x.pxmul(c)
		F.x.copy(mod(d))
		F.XES = 2
	} else {
		if F.XES*int32(c) <= FEXCESS {
			F.x.pmul(c)
			F.XES *= int32(c)
		} else {
			n := NewFPint(c)
			F.mul(n)
		}
	}
	if s {
		F.neg()
		F.norm()
	}
}

/* this*=this mod Modulus */
func (F *FP) sqr() {
	if int64(F.XES)*int64(F.XES) > int64(FEXCESS) {
		F.reduce()
	}
	d := sqr(F.x)
	F.x.copy(mod(d))
	F.XES = 2
}

/* this+=b */
func (F *FP) add(b *FP) {
	F.x.add(b.x)
	F.XES += b.XES
	if F.XES > FEXCESS {
		F.reduce()
	}
}

/* this-=b */
func (F *FP) sub(b *FP) {
	n := NewFPcopy(b)
	n.neg()
	F.add(n)
}

func (F *FP) rsub(b *FP) {
	F.neg()
	F.add(b)
}

/* this/=2 mod Modulus */
func (F *FP) div2() {
	p:=NewBIGints(Modulus)
	pr:=F.x.parity()
	w:=NewBIGcopy(F.x)
	F.x.fshr(1)
	w.add(p); w.norm()
	w.fshr(1)
	F.x.cmove(w,pr)
}


/* return jacobi symbol (this/Modulus) */
func (F *FP) jacobi() int {
	w := F.redc()
	p := NewBIGints(Modulus)
	return w.Jacobi(p)
}

/* return TRUE if this==a */
func (F *FP) Equals(a *FP) bool {
	f := NewFPcopy(F)
	s := NewFPcopy(a)

	s.reduce()
	f.reduce()
	if Comp(s.x, f.x) == 0 {
		return true
	}
	return false
}

func (F *FP) pow(e *BIG) *FP {
	var tb []*FP
	var w [1 + (NLEN*int(BASEBITS)+3)/4]int8
	F.norm()
	t := NewBIGcopy(e)
	t.norm()
	nb := 1 + (t.nbits()+3)/4

	for i := 0; i < nb; i++ {
		lsbs := t.lastbits(4)
		t.dec(lsbs)
		t.norm()
		w[i] = int8(lsbs)
		t.fshr(4)
	}
	tb = append(tb, NewFPint(1))
	tb = append(tb, NewFPcopy(F))
	for i := 2; i < 16; i++ {
		tb = append(tb, NewFPcopy(tb[i-1]))
		tb[i].mul(F)
	}
	r := NewFPcopy(tb[w[nb-1]])
	for i := nb - 2; i >= 0; i-- {
		r.sqr()
		r.sqr()
		r.sqr()
		r.sqr()
		r.mul(tb[w[i]])
	}
	r.reduce()
	return r
}

// See https://eprint.iacr.org/2018/1038
// return this^(p-3)/4 or this^(p-5)/8
func (F *FP) fpow() *FP {
	ac := [11]int{1, 2, 3, 6, 12, 15, 30, 60, 120, 240, 255}
	var xp []*FP
	// phase 1
	xp = append(xp, NewFPcopy(F))
	xp = append(xp, NewFPcopy(F))
	xp[1].sqr()
	xp = append(xp, NewFPcopy(xp[1]))
	xp[2].mul(F)
	xp = append(xp, NewFPcopy(xp[2]))
	xp[3].sqr()
	xp = append(xp, NewFPcopy(xp[3]))
	xp[4].sqr()
	xp = append(xp, NewFPcopy(xp[4]))
	xp[5].mul(xp[2])
	xp = append(xp, NewFPcopy(xp[5]))
	xp[6].sqr()
	xp = append(xp, NewFPcopy(xp[6]))
	xp[7].sqr()
	xp = append(xp, NewFPcopy(xp[7]))
	xp[8].sqr()
	xp = append(xp, NewFPcopy(xp[8]))
	xp[9].sqr()
	xp = append(xp, NewFPcopy(xp[9]))
	xp[10].mul(xp[5])
	var n, c int

	e := int(PM1D2)

	n = int(MODBITS)
	if MODTYPE == GENERALISED_MERSENNE { // Goldilocks ONLY
		n /= 2
	}

	n-=(e+1)
	c=(int(MConst)+(1<<e)+1)/(1<<(e+1))
	
	nd := 0
	for c%2 == 0 {
		c/=2
		n-=1
		nd++
	}

	bw := 0
	w := 1
	for w < c {
		w *= 2
		bw += 1
	}
	k := w - c

	i := 10
	key := NewFP()

	if k != 0 {
		for ac[i] > k {
			i--
		}
		key.copy(xp[i])
		k -= ac[i]
	}

	for k != 0 {
		i--
		if ac[i] > k {
			continue
		}
		key.mul(xp[i])
		k -= ac[i]
	}
	// phase 2
	xp[1].copy(xp[2])
	xp[2].copy(xp[5])
	xp[3].copy(xp[10])

	j := 3
	m := 8
	nw := n - bw
	t := NewFP()
	for 2*m < nw {
		t.copy(xp[j])
		j++
		for i = 0; i < m; i++ {
			t.sqr()
		}
		xp[j].copy(xp[j-1])
		xp[j].mul(t)
		m *= 2
	}
	lo := nw - m
	r := NewFPcopy(xp[j])

	for lo != 0 {
		m /= 2
		j--
		if lo < m {
			continue
		}
		lo -= m
		t.copy(r)
		for i = 0; i < m; i++ {
			t.sqr()
		}
		r.copy(t)
		r.mul(xp[j])
	}
	// phase 3
	if bw != 0 {
		for i = 0; i < bw; i++ {
			r.sqr()
		}
		r.mul(key)
	}

	if MODTYPE == GENERALISED_MERSENNE { // Goldilocks ONLY
		key.copy(r)
		r.sqr()
		r.mul(F)
		for i = 0; i < n+1; i++ {
			r.sqr()
		}
		r.mul(key)
	}
	for nd>0 {
		r.sqr()
		nd--
	}
	return r
}

// calculates r=x^(p-1-2^e)/2^{e+1) where 2^e|p-1
func (F *FP) invsqrt() {
	if (MODTYPE == PSEUDO_MERSENNE || MODTYPE == GENERALISED_MERSENNE) {
		F.copy(F.fpow())
		return
	}
	e:=uint(PM1D2)
	m := NewBIGints(Modulus)
	m.dec(1);
	m.shr(e);
	m.dec(1);
	m.fshr(1);    
	F.copy(F.pow(m));
}

/* this=1/this mod Modulus */
func (F *FP) inverse() {
        e:=int(PM1D2)
		F.norm()
        s:=NewFPcopy(F)
        for i:=0;i<e-1;i++ {
            s.sqr()
            s.mul(F)
        }
        F.invsqrt()
        for i:=0;i<=e;i++ {
            F.sqr()
		}
        F.mul(s)
        F.reduce()
}

/* test for Quadratic residue */
func (F *FP) qr(h *FP) int {
	r:=NewFPcopy(F)
	e:=int(PM1D2)
	r.invsqrt()
	if h!=nil {
		h.copy(r)
	}

	r.sqr()
	r.mul(F)
	for i:=0;i<e-1;i++ {
            r.sqr()
	}

//	for i:=0;i<e;i++ { 
//		r.sqr()
//	}
//	s:=NewFPcopy(F)
//	for i:=0;i<e-1;i++ {
//		s.sqr()
//	}
//	r.mul(s)
	if r.isunity() {
		return 1
	} else {
		return 0
	}
}

/* return sqrt(this) mod Modulus */
func (F *FP) sqrt(h *FP) *FP {
	e:=int(PM1D2)
	g:=NewFPcopy(F)
	if h==nil {
		g.invsqrt()
	} else {
		g.copy(h)
	}

	m := NewBIGints(ROI)
	v := NewFPbig(m)

	t:=NewFPcopy(g)
	t.sqr()
	t.mul(F)

	r:=NewFPcopy(F)
	r.mul(g)
	b:=NewFPcopy(t)
       
	for k:=e;k>1;k-- {
		for j:=1;j<k-1;j++ {
			b.sqr()
		}
		var u int
		if b.isunity() {
			u=0
		} else {
			u=1
		}
		g.copy(r); g.mul(v)
		r.cmove(g,u)
		v.sqr()
		g.copy(t); g.mul(v)
		t.cmove(g,u)
		b.copy(t)
	}
	return r
}

/* return sqrt(this) mod Modulus 
func (F *FP) sqrt() *FP {
	F.reduce()
	if PM1D2 == 2 {
		var v *FP
		i := NewFPcopy(F)
		i.x.shl(1)
		if MODTYPE == PSEUDO_MERSENNE || MODTYPE == GENERALISED_MERSENNE {
			v = i.fpow()
		} else {
			b := NewBIGints(Modulus)
			b.dec(5)
			b.norm()
			b.shr(3)
			v = i.pow(b)
		}

		i.mul(v)
		i.mul(v)
		i.x.dec(1)
		r := NewFPcopy(F)
		r.mul(v)
		r.mul(i)
		r.reduce()
		return r
	} else {
		var r *FP
		if MODTYPE == PSEUDO_MERSENNE || MODTYPE == GENERALISED_MERSENNE {
			r = F.fpow()
			r.mul(F)
		} else {
			b := NewBIGints(Modulus)
			b.inc(1)
			b.norm()
			b.shr(2)
			r = F.pow(b)
		}
		return r
	}
} */


