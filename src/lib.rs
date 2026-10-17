#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(all(target_arch = "bpf", feature = "weak-linkage"), feature(linkage))]

mod fp;

#[cfg(target_arch = "bpf")]
use core::ffi::c_void;

#[cfg(target_arch = "bpf")]
const SOL_MEMCMP: usize = 0x5FDCDE31;
#[cfg(target_arch = "bpf")]
const SOL_MEMCPY: usize = 0x717CC4A3;
#[cfg(target_arch = "bpf")]
const SOL_MEMMOVE: usize = 0x434371F8;
#[cfg(target_arch = "bpf")]
const SOL_MEMSET: usize = 0x3770FB22;
#[cfg(target_arch = "bpf")]
const INLINE_MEMCMP_THRESHOLD: usize = 32;
#[cfg(target_arch = "bpf")]
const INLINE_MEMCPY_THRESHOLD: usize = 40;
#[cfg(target_arch = "bpf")]
const INLINE_MEMMOVE_THRESHOLD: usize = 40;
#[cfg(target_arch = "bpf")]
const INLINE_MEMSET_THRESHOLD: usize = 80;

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn sol_memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut result = 0i32;
    let syscall: unsafe extern "C" fn(*const u8, *const u8, usize, *mut i32) -> i32 =
        unsafe { core::mem::transmute(SOL_MEMCMP) };
    unsafe {
        syscall(a, b, n, &mut result as *mut i32);
    }
    result
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn sol_memcpy(dst: *mut u8, src: *const u8, n: usize) {
    let syscall: unsafe extern "C" fn(*mut u8, *const u8, usize) =
        unsafe { core::mem::transmute(SOL_MEMCPY) };
    unsafe {
        syscall(dst, src, n);
    }
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn sol_memmove(dst: *mut u8, src: *const u8, n: usize) {
    let syscall: unsafe extern "C" fn(*mut u8, *const u8, usize) =
        unsafe { core::mem::transmute(SOL_MEMMOVE) };
    unsafe {
        syscall(dst, src, n);
    }
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn sol_memset(s: *mut u8, c: u8, n: usize) {
    let syscall: unsafe extern "C" fn(*mut u8, u8, usize) =
        unsafe { core::mem::transmute(SOL_MEMSET) };
    unsafe {
        syscall(s, c, n);
    }
}

#[cfg(target_arch = "bpf")]
#[cfg_attr(feature = "weak-linkage", linkage = "weak_odr")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    let a = a.cast::<u8>();
    let b = b.cast::<u8>();

    if n > INLINE_MEMCMP_THRESHOLD {
        sol_memcmp(a, b, n)
    } else {
        let mut i = 0usize;
        while i + 8 <= n {
            let wa = unsafe { core::ptr::read_unaligned(a.add(i) as *const u64) };
            let wb = unsafe { core::ptr::read_unaligned(b.add(i) as *const u64) };
            if wa != wb {
                break;
            }
            i += 8;
        }

        while i < n {
            if unsafe { *a.add(i) != *b.add(i) } {
                return unsafe { *a.add(i) as i32 - *b.add(i) as i32 };
            }
            i += 1;
        }

        0
    }
}

#[cfg(target_arch = "bpf")]
#[cfg_attr(feature = "weak-linkage", linkage = "weak_odr")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    memcmp(a, b, n)
}

#[cfg(target_arch = "bpf")]
#[cfg_attr(feature = "weak-linkage", linkage = "weak_odr")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let dst_u8 = dst.cast::<u8>();
    let src_u8 = src.cast::<u8>();

    if n > INLINE_MEMCPY_THRESHOLD {
        sol_memcpy(dst_u8, src_u8, n);
    } else {
        unsafe { copy_forward(dst_u8, src_u8, n) };
    }
    dst
}

#[cfg(target_arch = "bpf")]
#[cfg_attr(feature = "weak-linkage", linkage = "weak_odr")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let dst_u8 = dst.cast::<u8>();
    let src_u8 = src.cast::<u8>();

    if n > INLINE_MEMMOVE_THRESHOLD {
        sol_memmove(dst_u8, src_u8, n);
    } else if (dst_u8 as usize) <= (src_u8 as usize) {
        unsafe { copy_forward(dst_u8, src_u8, n) };
    } else {
        unsafe { copy_backward(dst_u8, src_u8, n) };
    }
    dst
}

#[cfg(target_arch = "bpf")]
#[cfg_attr(feature = "weak-linkage", linkage = "weak_odr")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let s_u8 = s.cast::<u8>();
    let c = c as u8;

    if n > INLINE_MEMSET_THRESHOLD {
        sol_memset(s_u8, c, n);
    } else {
        let pattern = (c as u64) * 0x0101_0101_0101_0101;
        let mut i = 0usize;
        while i + 8 <= n {
            unsafe { core::ptr::write_unaligned(s_u8.add(i) as *mut u64, pattern) };
            i += 8;
        }

        while i < n {
            unsafe { *s_u8.add(i) = c };
            i += 1;
        }
    }
    s
}

#[cfg(target_arch = "bpf")]
#[cfg_attr(feature = "weak-linkage", linkage = "weak_odr")]
#[unsafe(no_mangle)]
pub unsafe fn __multi3(a: i128, b: i128) -> i128 {
    const HALF_BITS: u32 = 32;
    const LOWER_MASK: u64 = u32::MAX as u64;

    let x_low = a as u64;
    let x_high = (a >> 64) as u64;
    let y_low = b as u64;
    let y_high = (b >> 64) as u64;

    // Inline __mulddi3(x_low, y_low)
    let mut low = (x_low & LOWER_MASK) * (y_low & LOWER_MASK);

    let mut t = low >> HALF_BITS;
    low &= LOWER_MASK;

    t = t.wrapping_add((x_low >> HALF_BITS) * (y_low & LOWER_MASK));
    low = low.wrapping_add((t & LOWER_MASK) << HALF_BITS);
    let mut high = t >> HALF_BITS;

    t = low >> HALF_BITS;
    low &= LOWER_MASK;

    t = t.wrapping_add((y_low >> HALF_BITS) * (x_low & LOWER_MASK));
    low = low.wrapping_add((t & LOWER_MASK) << HALF_BITS);
    high = high.wrapping_add(t >> HALF_BITS);

    high = high.wrapping_add((x_low >> HALF_BITS) * (y_low >> HALF_BITS));

    // r.s.high += x.s.high * y.s.low + x.s.low * y.s.high
    high = high
        .wrapping_add(x_high.wrapping_mul(y_low))
        .wrapping_add(x_low.wrapping_mul(y_high));

    ((high as u128) << 64 | low as u128) as i128
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
unsafe fn copy_forward(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = 0usize;
    while i + 8 <= n {
        let w = unsafe { core::ptr::read_unaligned(src.add(i) as *const u64) };
        unsafe { core::ptr::write_unaligned(dst.add(i) as *mut u64, w) };
        i += 8;
    }

    while i < n {
        unsafe { *dst.add(i) = *src.add(i) };
        i += 1;
    }
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
unsafe fn copy_backward(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = n;
    while i >= 8 {
        i -= 8;
        let w = unsafe { core::ptr::read_unaligned(src.add(i) as *const u64) };
        unsafe { core::ptr::write_unaligned(dst.add(i) as *mut u64, w) };
    }

    while i > 0 {
        i -= 1;
        unsafe { *dst.add(i) = *src.add(i) };
    }
}

/// Leading zeros by binary search, the VM has no instruction for it and LLVM's expansion is longer
#[cfg(target_arch = "bpf")]
#[inline(always)]
fn clz64(mut x: u64) -> u32 {
    if x == 0 {
        return 64;
    }
    let mut n = 0;
    if x >> 32 == 0 {
        n += 32;
        x <<= 32;
    }
    if x >> 48 == 0 {
        n += 16;
        x <<= 16;
    }
    if x >> 56 == 0 {
        n += 8;
        x <<= 8;
    }
    if x >> 60 == 0 {
        n += 4;
        x <<= 4;
    }
    if x >> 62 == 0 {
        n += 2;
        x <<= 2;
    }
    if x >> 63 == 0 {
        n += 1;
    }
    n
}

/// 128-by-64 division in 32-bit digits for a normalized `v` (top bit set) and `un32 < v`
#[cfg(target_arch = "bpf")]
#[inline(always)]
fn divlu_norm(un32: u64, un10: u64, v: u64) -> (u64, u64) {
    const B: u64 = 1 << 32;
    const MASK: u64 = B - 1;

    let (vn1, vn0) = (v >> 32, v & MASK);
    let (un1, un0) = (un10 >> 32, un10 & MASK);

    let mut q1 = un32 / vn1;
    let mut rhat = un32 - q1 * vn1;
    while q1 >= B || q1 * vn0 > (rhat << 32) + un1 {
        q1 -= 1;
        rhat += vn1;
        if rhat >= B {
            break;
        }
    }

    let un21 = (un32 << 32)
        .wrapping_add(un1)
        .wrapping_sub(q1.wrapping_mul(v));
    let mut q0 = un21 / vn1;
    let mut rhat = un21 - q0 * vn1;
    while q0 >= B || q0 * vn0 > (rhat << 32) + un0 {
        q0 -= 1;
        rhat += vn1;
        if rhat >= B {
            break;
        }
    }

    let r = (un21 << 32)
        .wrapping_add(un0)
        .wrapping_sub(q0.wrapping_mul(v));
    ((q1 << 32) | q0, r)
}

/// Full 64x64 product as (hi, lo) from 32-bit halves
#[cfg(target_arch = "bpf")]
#[inline(always)]
fn mul64(a: u64, b: u64) -> (u64, u64) {
    const MASK: u64 = (1 << 32) - 1;
    let (a1, a0, b1, b0) = (a >> 32, a & MASK, b >> 32, b & MASK);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 32) + (p01 & MASK) + (p10 & MASK);
    (
        p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32),
        (mid << 32) | (p00 & MASK),
    )
}

/**
 * u128 division on 64-bit halves. It never divides or shifts a whole u128, since LLVM lowers
 * those to libcalls, this one included. A zero divisor gives a quotient of 0 and leaves the
 * remainder as the dividend, like eBPF's own division, safe Rust never gets here because `/`
 * checks for zero first
 **/
#[cfg(target_arch = "bpf")]
#[inline(always)]
fn udivmod128(n: u128, d: u128) -> (u128, u128) {
    let (n_hi, n_lo) = ((n >> 64) as u64, n as u64);
    let (d_hi, d_lo) = ((d >> 64) as u64, d as u64);

    if d_hi == 0 {
        if d_lo == 0 {
            return (0, n);
        }
        if n_hi == 0 {
            return ((n_lo / d_lo) as u128, (n_lo % d_lo) as u128);
        }

        // Under 2^32 every partial remainder shifted by 32 bits still fits a u64
        if d_lo >> 32 == 0 {
            let mut q: u128 = 0;
            let mut r: u64 = 0;
            for word in [
                n_hi >> 32,
                n_hi & 0xFFFF_FFFF,
                n_lo >> 32,
                n_lo & 0xFFFF_FFFF,
            ] {
                let cur = (r << 32) | word;
                q = (q << 32) | (cur / d_lo) as u128;
                r = cur % d_lo;
            }
            return (q, r as u128);
        }

        let (q_hi, r_hi) = (n_hi / d_lo, n_hi % d_lo);
        let s = clz64(d_lo);
        let v = d_lo << s;
        let un32 = if s == 0 {
            r_hi
        } else {
            (r_hi << s) | (n_lo >> (64 - s))
        };
        let (q_lo, r) = divlu_norm(un32, n_lo << s, v);
        return (((q_hi as u128) << 64) | q_lo as u128, (r >> s) as u128);
    }

    if d_hi > n_hi || (d_hi == n_hi && d_lo > n_lo) {
        return (0, n);
    }

    let s = clz64(d_hi);

    // With 32 quotient bits or fewer one native division of the top 64 bits lands at most a few
    // units low, the shift test equals s - clz64(n_hi) < 32 without counting zeros on large quotients
    if s < 32 || n_hi >> (95 - s) == 0 {
        let k = clz64(n_hi);
        let (nt, dt) = if k == 0 {
            (n_hi, d_hi)
        } else {
            (
                (n_hi << k) | (n_lo >> (64 - k)),
                (d_hi << k) | (d_lo >> (64 - k)),
            )
        };
        let mut q = if dt == u64::MAX { 0 } else { nt / (dt + 1) };
        let (p_hi, p_lo) = mul64(q, d_lo);
        let p_hi = p_hi + q * d_hi;
        let (mut r_lo, borrow) = n_lo.overflowing_sub(p_lo);
        let mut r_hi = n_hi - p_hi - borrow as u64;
        while r_hi > d_hi || (r_hi == d_hi && r_lo >= d_lo) {
            q += 1;
            let (lo, borrow) = r_lo.overflowing_sub(d_lo);
            r_lo = lo;
            r_hi = r_hi - d_hi - borrow as u64;
        }
        return (q as u128, ((r_hi as u128) << 64) | r_lo as u128);
    }

    // The quotient fits in 64 bits, estimate it from the top 64 bits of the normalized divisor
    let v1 = if s == 0 {
        d_hi
    } else {
        (d_hi << s) | (d_lo >> (64 - s))
    };
    let (q1, _) = divlu_norm(n_hi >> 1, (n_lo >> 1) | (n_hi << 63), v1);
    let mut q = (q1 >> (63 - s)).saturating_sub(1);

    let (p_hi, p_lo) = mul64(q, d_lo);
    let p_hi = p_hi + q * d_hi;
    let (mut r_lo, borrow) = n_lo.overflowing_sub(p_lo);
    let mut r_hi = n_hi - p_hi - borrow as u64;
    if r_hi > d_hi || (r_hi == d_hi && r_lo >= d_lo) {
        q += 1;
        let (lo, borrow) = r_lo.overflowing_sub(d_lo);
        r_lo = lo;
        r_hi = r_hi - d_hi - borrow as u64;
    }

    (q as u128, ((r_hi as u128) << 64) | r_lo as u128)
}

#[cfg(target_arch = "bpf")]
#[cfg_attr(feature = "weak-linkage", linkage = "weak_odr")]
#[unsafe(no_mangle)]
pub unsafe fn __udivti3(n: u128, d: u128) -> u128 {
    udivmod128(n, d).0
}

#[cfg(target_arch = "bpf")]
#[cfg_attr(feature = "weak-linkage", linkage = "weak_odr")]
#[unsafe(no_mangle)]
pub unsafe fn __umodti3(n: u128, d: u128) -> u128 {
    udivmod128(n, d).1
}
