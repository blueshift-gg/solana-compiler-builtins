#![cfg_attr(target_arch = "bpf", no_std)]

#[cfg(target_arch = "bpf")]
use core::ffi::c_void;

#[cfg(target_arch = "bpf")]
const INLINE_MEMCMP_THRESHOLD: usize = 32;
#[cfg(target_arch = "bpf")]
const INLINE_MEMCPY_THRESHOLD: usize = 40;
#[cfg(target_arch = "bpf")]
const INLINE_MEMMOVE_THRESHOLD: usize = 40;
#[cfg(target_arch = "bpf")]
const INLINE_MEMSET_THRESHOLD: usize = 80;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(target_arch = "bpf")]
unsafe extern "C" {
    fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32;
    fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
}

#[cfg(target_arch = "bpf")]
fn make_array<const N: usize>(n: u8) -> [u8; N] {
    // return array of fixed size N filled with n
    [n; N]
}

#[cfg(target_arch = "bpf")]
unsafe fn test_memcmp_eq(n: usize) -> bool {
    let a = make_array::<100>(3);
    let b = make_array::<100>(3);
    unsafe { memcmp(a.as_ptr().cast::<c_void>(), b.as_ptr().cast::<c_void>(), n) == 0 }
}

#[cfg(target_arch = "bpf")]
unsafe fn test_memcmp_ne(n: usize) -> bool {
    let a = make_array::<100>(4);
    let mut b = make_array::<100>(4);

    unsafe {
        // flip the last byte in b
        let last = core::ptr::read_volatile(b.as_ptr().add(n - 1));
        core::ptr::write_volatile(b.as_mut_ptr().add(n - 1), last ^ 0xFF);
    }

    unsafe { memcmp(a.as_ptr().cast::<c_void>(), b.as_ptr().cast::<c_void>(), n) != 0 }
}

#[cfg(target_arch = "bpf")]
unsafe fn test_memcpy(n: usize) -> bool {
    let src = make_array::<100>(1);
    let mut dst = make_array::<100>(2);
    unsafe {
        // copy from src to dst
        memcpy(
            dst.as_mut_ptr().cast::<c_void>(),
            src.as_ptr().cast::<c_void>(),
            n,
        );
    }
    dst[..n] == src[..n]
}

#[cfg(target_arch = "bpf")]
unsafe fn test_memmove_nonoverlap(n: usize) -> bool {
    let src = make_array::<100>(1);
    let mut dst = make_array::<100>(2);
    unsafe {
        memmove(
            dst.as_mut_ptr().cast::<c_void>(),
            src.as_ptr().cast::<c_void>(),
            n,
        );
    }
    dst[..n] == src[..n]
}

#[cfg(target_arch = "bpf")]
unsafe fn test_memmove_overlap_backward(n: usize) -> bool {
    let mut a = make_array::<100>(5);
    // change byte at position n to 6
    a[n] = 6;
    unsafe {
        // copy backward (shift right by 1)
        memmove(
            a.as_mut_ptr().add(1).cast::<c_void>(),
            a.as_ptr().cast::<c_void>(),
            n,
        );
    }
    // a should go back to its original state
    a[1..1 + n] == make_array::<100>(5)[..n]
}

#[cfg(target_arch = "bpf")]
unsafe fn test_memmove_overlap_forward(n: usize) -> bool {
    let mut a = make_array::<100>(5);
    // change byte at position 0 to 6
    a[0] = 6;
    unsafe {
        // copy forward (shift left by 1)
        memmove(
            a.as_mut_ptr().cast::<c_void>(),
            a.as_ptr().add(1).cast::<c_void>(),
            n,
        );
    }
    // a should go back to its original state
    a[..n] == make_array::<100>(5)[..n]
}

#[cfg(target_arch = "bpf")]
unsafe fn test_memset(n: usize, c: u8) -> bool {
    let mut a = make_array::<100>(0xFF);
    unsafe {
        memset(a.as_mut_ptr().cast::<c_void>(), c as i32, n);
    }
    a[..n] == make_array::<100>(c)[..n]
}

#[cfg(target_arch = "bpf")]
fn test_multi3() -> bool {
    let mut a: i128 = 0x1111_2222_3333_4444;
    let mut b: i128 = 3;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    let prod = a.wrapping_mul(b);
    prod == 0x3333_6666_9999_CCCCi128
}

#[cfg(target_arch = "bpf")]
fn add_f64(a: f64, b: f64) -> f64 {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a + b)
}

#[cfg(target_arch = "bpf")]
fn mul_f64(a: f64, b: f64) -> f64 {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a * b)
}

#[cfg(target_arch = "bpf")]
fn test_adddf3() -> bool {
    add_f64(3.5, 2.0).to_bits() == 5.5f64.to_bits()
        && add_f64(-1.5, 0.25).to_bits() == (-1.25f64).to_bits()
        && add_f64(1.0, -1.0).to_bits() == 0.0f64.to_bits()
}

#[cfg(target_arch = "bpf")]
fn test_muldf3() -> bool {
    mul_f64(3.5, 2.0).to_bits() == 7.0f64.to_bits()
        && mul_f64(0.5, 0.5).to_bits() == 0.25f64.to_bits()
        && mul_f64(-2.0, 3.0).to_bits() == (-6.0f64).to_bits()
}

#[cfg(target_arch = "bpf")]
fn is_nan(x: f64) -> bool {
    (x.to_bits() & 0x7FFF_FFFF_FFFF_FFFF) > 0x7FF0_0000_0000_0000
}

#[cfg(target_arch = "bpf")]
fn test_adddf3_ieee() -> bool {
    is_nan(add_f64(f64::NAN, 1.0))
        && add_f64(f64::INFINITY, 1.0).to_bits() == f64::INFINITY.to_bits()
        && is_nan(add_f64(f64::INFINITY, f64::NEG_INFINITY))
        && add_f64(0.0, -0.0).to_bits() == 0.0f64.to_bits()
        && add_f64(-0.0, -0.0).to_bits() == (-0.0f64).to_bits()
        && add_f64(f64::from_bits(1), f64::from_bits(1)).to_bits() == f64::from_bits(2).to_bits()
        && add_f64(0.1, 0.2).to_bits() == (0.1f64 + 0.2f64).to_bits()
        && add_f64(f64::MAX, f64::MAX).to_bits() == f64::INFINITY.to_bits()
}

#[cfg(target_arch = "bpf")]
fn test_muldf3_ieee() -> bool {
    is_nan(mul_f64(f64::NAN, 2.0))
        && mul_f64(f64::INFINITY, 2.0).to_bits() == f64::INFINITY.to_bits()
        && is_nan(mul_f64(f64::INFINITY, 0.0))
        && mul_f64(-1.0, 0.0).to_bits() == (-0.0f64).to_bits()
        && mul_f64(-1.0, -0.0).to_bits() == 0.0f64.to_bits()
        && mul_f64(f64::from_bits(2), 0.5).to_bits() == f64::from_bits(1).to_bits()
        && mul_f64(f64::MAX, 2.0).to_bits() == f64::INFINITY.to_bits()
        && mul_f64(f64::from_bits(1), 0.5).to_bits() == 0.0f64.to_bits()
}

#[cfg(target_arch = "bpf")]
unsafe extern "C" {
    fn __floatundidf(i: u64) -> f64;
    fn __fixunsdfdi(f: f64) -> u64;
}

#[cfg(target_arch = "bpf")]
fn u64_to_f64(i: u64) -> f64 {
    let mut i = i;
    core::hint::black_box(&mut i);
    unsafe { core::hint::black_box(__floatundidf(i)) }
}

#[cfg(target_arch = "bpf")]
fn f64_to_u64(f: f64) -> u64 {
    let mut f = f;
    core::hint::black_box(&mut f);
    unsafe { core::hint::black_box(__fixunsdfdi(f)) }
}

#[cfg(target_arch = "bpf")]
fn test_floatundidf() -> bool {
    u64_to_f64(0).to_bits() == 0.0f64.to_bits()
        && u64_to_f64(1).to_bits() == 1.0f64.to_bits()
        && u64_to_f64(2).to_bits() == 2.0f64.to_bits()
        && u64_to_f64(3).to_bits() == 0x4008_0000_0000_0000
        && u64_to_f64(1u64 << 52).to_bits() == 0x4330_0000_0000_0000
        && u64_to_f64((1u64 << 52) + 1).to_bits() == 0x4330_0000_0000_0001
        && u64_to_f64((1u64 << 53) - 1).to_bits() == 0x433F_FFFF_FFFF_FFFF
        && u64_to_f64(1u64 << 53).to_bits() == 0x4340_0000_0000_0000
        && u64_to_f64(1u64 << 63).to_bits() == 0x43E0_0000_0000_0000
        && u64_to_f64((1u64 << 53) + 1).to_bits() == 0x4340_0000_0000_0000
        && u64_to_f64((1u64 << 53) + 3).to_bits() == 0x4340_0000_0000_0002
        && u64_to_f64((1u64 << 54) + 2).to_bits() == 0x4350_0000_0000_0000
        && u64_to_f64((1u64 << 54) + 6).to_bits() == 0x4350_0000_0000_0002
        && u64_to_f64(0xFFFF_FFFF_FFFF_F800).to_bits() == 0x43EF_FFFF_FFFF_FFFF
        && u64_to_f64(u64::MAX).to_bits() == 0x43F0_0000_0000_0000
}

#[cfg(target_arch = "bpf")]
fn test_fixunsdfdi() -> bool {
    // Truncation toward zero.
    f64_to_u64(0.0) == 0
        && f64_to_u64(0.5) == 0
        && f64_to_u64(1.0) == 1
        && f64_to_u64(1.9999999) == 1
        && f64_to_u64(2.5) == 2
        && f64_to_u64(255.75) == 255
        && f64_to_u64(f64::from_bits(0x3FEF_FFFF_FFFF_FFFF)) == 0
        && f64_to_u64(f64::from_bits(1)) == 0
        && f64_to_u64(9007199254740992.0) == 9007199254740992 // 2^53
        && f64_to_u64(9223372036854775808.0) == 9223372036854775808 // 2^63
        && f64_to_u64(13835058055282163712.0) == 13835058055282163712 // 2^63 + 2^62
        && f64_to_u64(f64::from_bits(0x43EF_FFFF_FFFF_FFFF)) == 18446744073709549568
        && f64_to_u64(f64::from_bits(0x43F0_0000_0000_0000)) == u64::MAX // 2^64
        && f64_to_u64(f64::MAX) == u64::MAX // huge finite, via the <= EXP_MASK branch
        && f64_to_u64(f64::INFINITY) == u64::MAX
        && f64_to_u64(-0.0) == 0
        && f64_to_u64(-1.0) == 0
        && f64_to_u64(-1e300) == 0
        && f64_to_u64(f64::NEG_INFINITY) == 0
        && f64_to_u64(f64::NAN) == 0
        && f64_to_u64(f64::from_bits(0xFFF8_0000_0000_0000)) == 0
}

#[cfg(target_arch = "bpf")]
fn ge_f64(a: f64, b: f64) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a >= b)
}

#[cfg(target_arch = "bpf")]
fn gt_f64(a: f64, b: f64) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a > b)
}

#[cfg(target_arch = "bpf")]
fn test_gedf2() -> bool {
    ge_f64(2.0, 1.0) // greater
        && ge_f64(1.0, 1.0) // equal
        && !ge_f64(1.0, 2.0) // less
        && ge_f64(-1.0, -2.0) // both negative, greater
        && !ge_f64(-2.0, -1.0) // both negative, less
        && ge_f64(-1.0, -1.0) // both negative, equal
        && ge_f64(0.0, -0.0) // +0 >= -0
        && ge_f64(-0.0, 0.0) // -0 >= +0
        && ge_f64(1.0, -1.0) // mixed sign
        && !ge_f64(-1.0, 1.0)
        && ge_f64(f64::INFINITY, f64::MAX)
        && ge_f64(f64::MAX, f64::NEG_INFINITY)
        && ge_f64(f64::INFINITY, f64::INFINITY) // equal +inf
        && ge_f64(f64::NEG_INFINITY, f64::NEG_INFINITY) // equal -inf
        && !ge_f64(f64::NEG_INFINITY, f64::INFINITY) // -inf < +inf
        && ge_f64(f64::from_bits(1), 0.0) // smallest subnormal >= 0
        && !ge_f64(f64::NAN, 1.0) // NaN is unordered
        && !ge_f64(1.0, f64::NAN)
        && !ge_f64(f64::NAN, f64::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_gtdf2() -> bool {
    gt_f64(2.0, 1.0) // greater
        && !gt_f64(1.0, 1.0) // equal is NOT greater
        && !gt_f64(1.0, 2.0) // less
        && gt_f64(-1.0, -2.0) // both negative, greater
        && !gt_f64(-2.0, -1.0) // both negative, less
        && !gt_f64(-1.0, -1.0) // both negative, equal is NOT greater
        && !gt_f64(0.0, -0.0) // +0 is not > -0
        && !gt_f64(-0.0, 0.0) // -0 is not > +0
        && gt_f64(1.0, -1.0) // mixed sign
        && !gt_f64(-1.0, 1.0)
        && gt_f64(f64::INFINITY, f64::MAX)
        && !gt_f64(f64::INFINITY, f64::INFINITY) // equal +inf is NOT greater
        && !gt_f64(f64::NEG_INFINITY, f64::NEG_INFINITY) // equal -inf is NOT greater
        && gt_f64(f64::INFINITY, f64::NEG_INFINITY) // +inf > -inf
        && !gt_f64(f64::NEG_INFINITY, f64::INFINITY) // -inf is not > +inf
        && gt_f64(f64::MIN_POSITIVE, 0.0) // smallest normal > 0
        && gt_f64(f64::from_bits(1), 0.0) // smallest subnormal > 0
        && !gt_f64(f64::NAN, 1.0) // NaN is unordered
        && !gt_f64(1.0, f64::NAN)
        && !gt_f64(f64::NAN, f64::NAN)
}

#[unsafe(no_mangle)]
pub fn entrypoint(_input: *mut u8) -> u64 {
    #[cfg(target_arch = "bpf")]
    {
        // memcmp
        if !unsafe { test_memcmp_eq(INLINE_MEMCMP_THRESHOLD) } {
            return 1;
        }
        if !unsafe { test_memcmp_eq(INLINE_MEMCMP_THRESHOLD + 1) } {
            return 2;
        }
        if !unsafe { test_memcmp_ne(INLINE_MEMCMP_THRESHOLD) } {
            return 3;
        }
        if !unsafe { test_memcmp_ne(INLINE_MEMCMP_THRESHOLD + 1) } {
            return 4;
        }

        // memcpy
        if !unsafe { test_memcpy(INLINE_MEMCPY_THRESHOLD) } {
            return 5;
        }
        if !unsafe { test_memcpy(INLINE_MEMCPY_THRESHOLD + 1) } {
            return 6;
        }

        // memmove
        if !unsafe { test_memmove_nonoverlap(INLINE_MEMMOVE_THRESHOLD) } {
            return 7;
        }
        if !unsafe { test_memmove_nonoverlap(INLINE_MEMMOVE_THRESHOLD + 1) } {
            return 8;
        }
        if !unsafe { test_memmove_overlap_backward(INLINE_MEMMOVE_THRESHOLD) } {
            return 9;
        }
        if !unsafe { test_memmove_overlap_backward(INLINE_MEMMOVE_THRESHOLD + 1) } {
            return 10;
        }
        if !unsafe { test_memmove_overlap_forward(INLINE_MEMMOVE_THRESHOLD) } {
            return 11;
        }
        if !unsafe { test_memmove_overlap_forward(INLINE_MEMMOVE_THRESHOLD + 1) } {
            return 12;
        }

        // memset
        if !unsafe { test_memset(INLINE_MEMSET_THRESHOLD, 0xAB) } {
            return 13;
        }
        if !unsafe { test_memset(INLINE_MEMSET_THRESHOLD + 1, 0xAB) } {
            return 14;
        }

        // __multi3
        if !test_multi3() {
            return 15;
        }

        // __adddf3 / __muldf3
        if !test_adddf3() {
            return 16;
        }
        if !test_muldf3() {
            return 17;
        }

        // __adddf3 / __muldf3 IEEE-754 special values
        if !test_adddf3_ieee() {
            return 18;
        }
        if !test_muldf3_ieee() {
            return 19;
        }

        // __floatundidf / __fixunsdfdi
        if !test_floatundidf() {
            return 20;
        }
        if !test_fixunsdfdi() {
            return 21;
        }

        // __gedf2 / __gtdf2
        if !test_gedf2() {
            return 22;
        }
        if !test_gtdf2() {
            return 23;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use mollusk_svm::{result::Check, Mollusk};
    use solana_instruction::Instruction;

    #[test]
    fn builtins_test() {
        let program_id = [2u8; 32].into();
        let mollusk = Mollusk::new(
            &program_id,
            "target/bpfel-unknown-none/release/libprogram_test",
        );
        mollusk.process_and_validate_instruction(
            &Instruction {
                program_id,
                accounts: vec![],
                data: vec![],
            },
            &[],
            &[Check::success()],
        );
    }
}
