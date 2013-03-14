/*
 * dstatic.d
 *
 * This module implements the static subset of D.
 *
 * License: Public Domain
 *
 */

module mindrt.dstatic;

import util;
import mindrt.common;

extern(C):

/******************************************
 * Given a pointer:
 *		If it is an Object, return that Object.
 *		If it is an interface, return the Object implementing the interface.
 *		If it is null, return null.
 *		Else, undefined crash
 */

Object _d_toObject(void* p) {
	Object o;

	if (p) {
		o = cast(Object)p;
		ClassInfo oc = o.classinfo;
		Interface *pi = **cast(Interface ***)p;

		/* Interface.offset lines up with ClassInfo.name.ptr,
		 * so we rely on pointers never being less than 64K,
		 * and Objects never being greater.
		 */
		if (pi.offset < 0x10000) {
			//printf("\tpi.offset = %d\n", pi.offset);
			o = cast(Object)(p - pi.offset);
		}
	}
	return o;
}

/*************************************
 * Attempts to cast Object o to class c.
 * Returns o if successful, null if not.
 */

Object _d_interface_cast(void* p, ClassInfo c) {
	Object o;

	//printf("_d_interface_cast(p = %p, c = '%.*s')\n", p, c.name);
	if (p) {
		Interface *pi = **cast(Interface ***)p;

		//printf("\tpi.offset = %d\n", pi.offset);
		o = cast(Object)(p - pi.offset);
		return _d_dynamic_cast(o, c);
	}
	return o;
}

Object _d_dynamic_cast(Object o, ClassInfo c) {
	ClassInfo oc;
	size_t offset = 0;

	//printf("_d_dynamic_cast(o = %p, c = '%.*s')\n", o, c.name);

	if (o) {
		oc = o.classinfo;
		if (_d_isbaseof2(oc, c, offset)) {
			//printf("\toffset = %d\n", offset);
			o = cast(Object)(cast(void*)o + offset);
		}
		else
			o = null;
	}
	//printf("\tresult = %p\n", o);
	return o;
}

int _d_isbaseof2(ClassInfo oc, ClassInfo c, inout size_t offset) {
	int i;

	if (oc is c)
		return 1;
	do {
		if (oc.base is c)
			return 1;
		for (i = 0; i < oc.interfaces.length; i++) {
			ClassInfo ic;

			ic = oc.interfaces[i].classinfo;
			if (ic is c) {
				offset = oc.interfaces[i].offset;
				return 1;
			}
		}
		for (i = 0; i < oc.interfaces.length; i++) {
			ClassInfo ic;

			ic = oc.interfaces[i].classinfo;
			if (_d_isbaseof2(ic, c, offset)) {
				offset = oc.interfaces[i].offset;
				return 1;
			}
		}
		oc = oc.base;
	} while (oc);
	return 0;
}

int _d_isbaseof(ClassInfo oc, ClassInfo c) {
	int i;

	if (oc is c)
		return 1;
	do {
		if (oc.base is c)
			return 1;
		for (i = 0; i < oc.interfaces.length; i++) {
			ClassInfo ic;

			ic = oc.interfaces[i].classinfo;
			if (ic is c || _d_isbaseof(ic, c))
				return 1;
		}
		oc = oc.base;
	} while (oc);
	return 0;
}

/*********************************
 * Find the vtbl[] associated with Interface ic.
 */

void *_d_interface_vtbl(ClassInfo ic, Object o) {
	int i;
	ClassInfo oc;

	//printf("__d_interface_vtbl(o = %p, ic = %p)\n", o, ic);

	assert(o);

	oc = o.classinfo;
	for (i = 0; i < oc.interfaces.length; i++) {
		ClassInfo oic;

		oic = oc.interfaces[i].classinfo;
		if (oic is ic) {
			return cast(void *)oc.interfaces[i].vtbl;
		}
	}
	assert(0);
}

int _d_obj_eq(Object o1, Object o2) {
    return o1 is o2 || (o1 && o1.opEquals(o2));
}

int _d_obj_cmp(Object o1, Object o2) {
    return o1.opCmp(o2);
}

int _d_switch_string(char[][] table, char[] ca) {
	int low;
	int high;
	int mid;
	int c;
	char[] pca;

	low = 0;
	high = table.length;

	if (high &&
		ca.length >= table[0].length &&
		ca.length <= table[high - 1].length) {
		// Looking for 0 length string, which would only be at the beginning
		if (ca.length == 0)
			return 0;

		char c1 = ca[0];

		// Do binary search
		while (low < high) {
			mid = (low + high) >> 1;
			pca = table[mid];
			c = ca.length - pca.length;
			if (c == 0) {
				c = cast(ubyte)c1 - cast(ubyte)pca[0];
				if (c == 0) {
					c = memcmp(ca.ptr, pca.ptr, ca.length);
					if (c == 0) {
						return mid;
					}
				}
			}
			if (c < 0) {
				high = mid;
			}
			else {
				low = mid + 1;
			}
		}
	}

	return -1;				// not found
}

int _d_switch_ustring(wchar[][] table, wchar[] ca) {
	int low;
	int high;
	int mid;
	int c;
	wchar[] pca;

	low = 0;
	high = table.length;

	// Do binary search
	while (low < high) {
		mid = (low + high) >> 1;
		pca = table[mid];
		c = ca.length - pca.length;
		if (c == 0) {
			c = memcmp(ca.ptr, pca.ptr, ca.length * wchar.sizeof);
			if (c == 0) {
				return mid;
			}
		}
		if (c < 0) {
			high = mid;
		}
		else {
			low = mid + 1;
		}
	}

	return -1;				// not found
}

int _d_switch_dstring(dchar[][] table, dchar[] ca) {
	int low;
	int high;
	int mid;
	int c;
	dchar[] pca;

	low = 0;
	high = table.length;

	// Do binary search
	while (low < high) {
		mid = (low + high) >> 1;
		pca = table[mid];
		c = ca.length - pca.length;
		if (c == 0) {
			c = memcmp(ca.ptr, pca.ptr, ca.length * dchar.sizeof);
			if (c == 0) {
				return mid;
			}
		}
		if (c < 0) {
			high = mid;
		}
		else {
			low = mid + 1;
		}
	}

	return -1;				// not found
}

void[] _d_arraycase(uint tsize, uint fsize, void[] a) {
	uint length = a.length;
	uint nbytes;

	nbytes = length * fsize;
	if (nbytes % tsize != 0) {
		// throw new Error ("array case misalignment");
	}

	length = nbytes / tsize;
	*cast(uint *)&a = length;
	return a;
}

template ArrayInit(char[] name, char[] type) {
	const char[] ArrayInit = `

		void _d_array_init_` ~ name ~ `(` ~ type ~ `* a, size_t n, ` ~ type ~ ` v) {
			auto p = a;
			auto end = a + n;

			while (p !is end) {
				*p++ = v;
			}
		}

		`;
}

mixin(ArrayInit!("i1", "bool"));
mixin(ArrayInit!("i8", "ubyte"));
mixin(ArrayInit!("i16", "ushort"));
mixin(ArrayInit!("i32", "uint"));
mixin(ArrayInit!("i64", "ulong"));
mixin(ArrayInit!("float", "float"));
mixin(ArrayInit!("double", "double"));
mixin(ArrayInit!("pointer", "void*"));

void _d_array_init_mem(void* a, size_t na, void* v, size_t nv) {
	auto p = a;
	auto end = a + na * nv;

	while (p !is end) {
		memcpy(p,v,nv);
		p+=nv;
	}
}

// for array cast
size_t _d_array_cast_len(size_t len, size_t elemsz, size_t newelemsz) {
	if (newelemsz == 1) {
		return len*elemsz;
	}
	else if (len % newelemsz) {
		// throw new Exception("Bad array case");
	}

	return (len*elemsz)/newelemsz;
}

void _d_assert( char[] file, uint line ) {
    onAssertError( file, line );
}

void _d_assert_msg( char[] msg, char[] file, uint line ) {
    onAssertErrorMsg( file, line, msg );
}

void _d_array_bounds( char[] file, uint line ) {
    onArrayBoundsError( file, line );
}

void _d_switch_error( char[] file, uint line ) {
    onSwitchError( file, line );
}

private void onAssertError(char[] file, size_t line) {
	//kprintfln!("Error in {}, line {}: assertion failed.")(file, line);
	asm { l: hlt; jmp l; }
}

private void onAssertErrorMsg(char[] file, size_t line, char[] msg) {
	//kprintfln!("Error in {}, line {}: assertion failed: \"{}\"")(file, line, msg);
	asm { l: hlt; jmp l; }
}

private void onArrayBoundsError(char[] file, size_t line) {
	//kprintfln!("Error in {}, line {}: array index out of bounds.")(file, line);
	asm { l: hlt; jmp l; }
}

private void onSwitchError(char[] file, size_t line) {
	//kprintfln!("Error in {}, line {}: switch has no case or default to handle the switched-upon value.")(file, line);
	asm { l: hlt; jmp l; }
}

private {
	const ubyte[256] UTF8stride = [
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
	4,4,4,4,4,4,4,4,5,5,5,5,6,6,0xFF,0xFF,
	];
}

Array _adReverseChar(char[] a) {
	if(a.length > 1) {
		char[6] tmp;
		char[6] tmplo;
		char* lo = a.ptr;
		char* hi = &a[length - 1];

		while (lo < hi) {
			auto clo = *lo;
			auto chi = *hi;

			if (clo <= 0x7F && chi <= 0x7F) {
				*lo = chi;
				*hi = clo;
				lo++;
				hi--;
				continue;
			}

			uint stridelo = UTF8stride[clo];

			uint stridehi = 1;
			while ((chi & 0xC0) == 0x80) {
				chi = *--hi;
				stridehi++;
				assert(hi >= lo);
			}
			if (lo == hi)
				break;

			if (stridelo == stridehi) {
				memcpy(tmp.ptr, lo, stridelo);
				memcpy(lo, hi, stridelo);
				memcpy(hi, tmp.ptr, stridelo);
				lo += stridelo;
				hi--;
				continue;
			}

			/* Shift the whole array. This is woefully inefficient
			 */
			memcpy(tmp.ptr, hi, stridehi);
			memcpy(tmplo.ptr, lo, stridelo);
			memmove(lo + stridehi, lo + stridelo , (hi - lo) - stridelo);
			memcpy(lo, tmp.ptr, stridehi);
			memcpy(hi + cast(int) stridehi - cast(int) stridelo, tmplo.ptr, stridelo);

			lo += stridehi;
			hi = hi - 1 + (cast(int) stridehi - cast(int) stridelo);
		}
	}

	Array aaa = *cast(Array*)(&a);
	return aaa;
}

Array _adReverseWchar(wchar[] a) {
	if (a.length > 1) {
		wchar[2] tmp;
		wchar* lo = a.ptr;
		wchar* hi = &a[length - 1];

		while (lo < hi) {
			auto clo = *lo;
			auto chi = *hi;

			if ((clo < 0xD800 || clo > 0xDFFF) &&
			  (chi < 0xD800 || chi > 0xDFFF)) {
				*lo = chi;
				*hi = clo;
				lo++;
				hi--;
				continue;
			}

			int stridelo = 1 + (clo >= 0xD800 && clo <= 0xDBFF);

			int stridehi = 1;
			if (chi >= 0xDC00 && chi <= 0xDFFF) {
				chi = *--hi;
				stridehi++;
				assert(hi >= lo);
			}
			if (lo == hi)
				break;

			if (stridelo == stridehi) {
				int stmp;

				assert(stridelo == 2);
				assert(stmp.sizeof == 2 * (*lo).sizeof);
				stmp = *cast(int*)lo;
				*cast(int*)lo = *cast(int*)hi;
				*cast(int*)hi = stmp;
				lo += stridelo;
				hi--;
				continue;
			}

			/* Shift the whole array. This is woefully inefficient
			 */
			memcpy(tmp.ptr, hi, stridehi * wchar.sizeof);
			memcpy(hi + cast(int) stridehi - cast(int) stridelo, lo, stridelo * wchar.sizeof);
			memmove(lo + stridehi, lo + stridelo , (hi - (lo + stridelo)) * wchar.sizeof);
			memcpy(lo, tmp.ptr, stridehi * wchar.sizeof);

			lo += stridehi;
			hi = hi - 1 + (cast(int) stridehi - cast(int) stridelo);
		}
	}

	Array aaa = *cast(Array*)(&a);
	return aaa;
}

int _adCmpChar(Array a1, Array a2) {
	version (Asm86) {
		asm {
			naked					;

			push	EDI 			;
			push	ESI 			;

			mov    ESI,a1+4[4+ESP]	;
			mov    EDI,a2+4[4+ESP]	;

			mov    ECX,a1[4+ESP]	;
			mov    EDX,a2[4+ESP]	;

			cmp 	ECX,EDX 		;
			jb		GotLength		;

			mov 	ECX,EDX 		;

	GotLength:
			cmp    ECX,4			;
			jb	  DoBytes			;

			// Do alignment if neither is dword aligned
			test	ESI,3			;
			jz	  Aligned			;

			test	EDI,3			;
			jz	  Aligned			;
	DoAlign:
			mov    AL,[ESI] 		; //align ESI to dword bounds
			mov    DL,[EDI] 		;

			cmp    AL,DL			;
			jnz    Unequal			;

			inc    ESI				;
			inc    EDI				;

			test	ESI,3			;

			lea    ECX,[ECX-1]		;
			jnz    DoAlign			;
	Aligned:
			mov    EAX,ECX			;

			// do multiple of 4 bytes at a time

			shr    ECX,2			;
			jz	  TryOdd			;

			repe					;
			cmpsd					;

			jnz    UnequalQuad		;

	TryOdd:
			mov    ECX,EAX			;
	DoBytes:
			// if still equal and not end of string, do up to 3 bytes slightly
			// slower.

			and    ECX,3			;
			jz	  Equal 			;

			repe					;
			cmpsb					;

			jnz    Unequal			;
	Equal:
			mov    EAX,a1[4+ESP]	;
			mov    EDX,a2[4+ESP]	;

			sub    EAX,EDX			;
			pop    ESI				;

			pop    EDI				;
			ret 					;

	UnequalQuad:
			mov    EDX,[EDI-4]		;
			mov    EAX,[ESI-4]		;

			cmp    AL,DL			;
			jnz    Unequal			;

			cmp    AH,DH			;
			jnz    Unequal			;

			shr    EAX,16			;

			shr    EDX,16			;

			cmp    AL,DL			;
			jnz    Unequal			;

			cmp    AH,DH			;
	Unequal:
			sbb    EAX,EAX			;
			pop    ESI				;

			or	   EAX,1			;
			pop    EDI				;

			ret 					;
		}
	}
	else {
		int len;
		int c;

		len = a1.length;
		if (a2.length < len)
			len = a2.length;
		c = memcmp(cast(char *)a1.data, cast(char *)a2.data, len);
		if (!c)
			c = cast(int)a1.length - cast(int)a2.length;
		return c;
	}
}

Array _adReverse(Array a, size_t szelem) {
	if (a.length >= 2) {
		byte*	 tmp;
		byte[16] buffer;

		void* lo = a.data;
		void* hi = a.data + (a.length - 1) * szelem;

		tmp = buffer.ptr;
		if (szelem > 16) {
			version(GNU) {
				tmp = cast(byte*)alloca(szelem);
			}
		}

		for (; lo < hi; lo += szelem, hi -= szelem) {
			memcpy(tmp, lo,  szelem);
			memcpy(lo,	hi,  szelem);
			memcpy(hi,	tmp, szelem);
		}
	}
	return a;
}

int _adEq(Array a1, Array a2, TypeInfo ti) {
  return ti.equals(&a1, &a2);
}

int _adCmp(Array a1, Array a2, TypeInfo ti) {
  return ti.compare(&a1, &a2);
}

Array _adSort(Array a, TypeInfo ti) {
	static const uint Qsort_Threshold = 7;

	struct StackEntry {
		byte *l;
		byte *r;
	}

	size_t elem_size = ti.tsize();
	size_t qsort_limit = elem_size * Qsort_Threshold;

	static assert(ubyte.sizeof == 1);
	static assert(ubyte.max == 255);

	StackEntry[size_t.sizeof * 8] stack; // log2( size_t.max )
	StackEntry * sp = stack.ptr;
	byte* lbound = cast(byte *) a.data;
	byte* rbound = cast(byte *) a.data + a.length * elem_size;
	byte* li = void;
	byte* ri = void;

	while (1) {
		if (rbound - lbound > qsort_limit) {
			ti.swap(lbound,
				lbound + (
						  ((rbound - lbound) >>> 1) -
						  (((rbound - lbound) >>> 1) % elem_size)
						  ));

			li = lbound + elem_size;
			ri = rbound - elem_size;

			if (ti.compare(li, ri) > 0)
				ti.swap(li, ri);
			if (ti.compare(lbound, ri) > 0)
				ti.swap(lbound, ri);
			if (ti.compare(li, lbound) > 0)
				ti.swap(li, lbound);

			while (1) {
				do
					li += elem_size;
				while (ti.compare(li, lbound) < 0);
				do
					ri -= elem_size;
				while (ti.compare(ri, lbound) > 0);
if (li > ri)
					break;
				ti.swap(li, ri);
			}
			ti.swap(lbound, ri);
			if (ri - lbound > rbound - li) {
				sp.l = lbound;
				sp.r = ri;
				lbound = li;
			}
			else {
				sp.l = li;
				sp.r = rbound;
				rbound = ri;
			}
			++sp;
		}
		else {
			// Use insertion sort
			for (ri = lbound, li = lbound + elem_size;
				 li < rbound;
				 ri = li, li += elem_size) {
				for ( ; ti.compare(ri, ri + elem_size) > 0;
					  ri -= elem_size) {
					ti.swap(ri, ri + elem_size);
					if (ri == lbound)
						break;
				}
			}
			if (sp != stack.ptr) {
				--sp;
				lbound = sp.l;
				rbound = sp.r;
			}
			else
				return a;
		}
	}
}

void[] _d_arraycast(size_t tsize, size_t fsize, void[] a) {
	auto length = a.length;
	auto nbytes = length * fsize;

	if(nbytes % tsize != 0)
		assert (0, "array cast misalignment");

	length = nbytes / tsize;
	*cast(size_t *)&a = length; // jam new length
	return a;
}

byte[] _d_arraycopy(size_t size, byte[] from, byte[] to) {
	if(to.length != from.length)
		assert (0, "lengths don't match for array copy");
	else if(cast(byte *)to + to.length * size <= cast(byte *)from || cast(byte *)from + from.length * size <= cast(byte *)to)
		memcpy(cast(byte *)to, cast(byte *)from, to.length * size);
	else
		assert (0, "overlapping array copy");

	return to;
}

void _d_array_slice_copy(void* dst, size_t dstlen, void* src, size_t srclen) {
	if (dstlen != srclen)
		assert(0, "lengths don't match for array copy");
	else if (dst+dstlen <=src || src+srclen <= dst)
		memcpy(dst, src, dstlen);
	else
		assert(0, "overlapping array copy");
}
