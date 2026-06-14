#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

#[cfg(target_arch = "bpf")]
const SOL_MEMCMP: usize = 0x5FDCDE31;
#[cfg(target_arch = "bpf")]
const INLINE_MEMCMP_THRESHOLD: usize = 32;

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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    if n > INLINE_MEMCMP_THRESHOLD {
        sol_memcmp(a, b, n)
    } else {
        let mut i = 0usize;
        while i + 8 <= n {
            let wa = unsafe { core::ptr::read_unaligned(a.add(i) as *const u64) };
            let wb = unsafe { core::ptr::read_unaligned(b.add(i) as *const u64) };
            if wa != wb {
                return 1;
            }
            i += 8;
        }

        while i < n {
            if unsafe { *a.add(i) != *b.add(i) } {
                return 1;
            }
            i += 1;
        }

        0
    }
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
