#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    memcmp(a, b, n)
}

#[cfg(target_arch = "bpf")]
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
#[unsafe(no_mangle)]
pub unsafe fn __multi3(a: i128, b: i128) {
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

    // LLVM23 returns i128 as two i64 values in r0 and r2.
    // use assembly to match the ABI before we patch rustc
    unsafe {
        core::arch::asm!(
            "r0 = {low}",
            "r2 = {high}",
            low = in(reg) low,
            high = in(reg) high,
            out("r0") _,
            out("r2") _,
            options(nomem, nostack),
        );
    }
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
