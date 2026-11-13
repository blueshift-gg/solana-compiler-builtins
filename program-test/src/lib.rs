#![cfg_attr(target_arch = "bpf", no_std)]
use solana_compiler_builtins as _;

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
fn multiply_matches(mut a: i128, mut b: i128, expected: i128) -> bool {
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    a.wrapping_mul(b) == expected
}

#[cfg(target_arch = "bpf")]
fn test_multi3() -> bool {
    multiply_matches(0x1111_2222_3333_4444, 3, 0x3333_6666_9999_CCCCi128)
        && multiply_matches(1i128 << 100, 3, 3i128 << 100)
        && multiply_matches(-(1i128 << 100), 3, -(3i128 << 100))
        && multiply_matches(i128::MAX, 2, -2)
}

#[cfg(target_arch = "bpf")]
fn udivmod_matches(mut n: u128, mut d: u128, q: u128, r: u128) -> bool {
    core::hint::black_box(&mut n);
    core::hint::black_box(&mut d);
    n / d == q && n % d == r
}

#[cfg(target_arch = "bpf")]
fn test_udivmodti3() -> bool {
    udivmod_matches(0x64, 0x7, 0xE, 0x2)
        && udivmod_matches(0xFFFF_FFFF_FFFF_FFFF, 0x3, 0x5555_5555_5555_5555, 0x0)
        && udivmod_matches(
            0x10_0000_0000_0000_0000_0000_3039,
            0x3E8,
            0x418_9374_BC6A_7EF9_DB22_D0F1,
            0x2D1,
        )
        && udivmod_matches(
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF,
            0x1_0000_0001_0000_0001_0000_0001,
            0x0,
        )
        && udivmod_matches(
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0xDE0_B6B3_A764_0000,
            0x12_725D_D1D2_43AB_A0E7,
            0x532_DF79_74C3_FFFF,
        )
        && udivmod_matches(
            0x8000_0000_0000_0001_0000_0000_0000_0005,
            0x1_0000_0000_0000_0001,
            0x8000_0000_0000_0000,
            0x8000_0000_0000_0005,
        )
        && udivmod_matches(
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0x1,
            0x0,
        )
        && udivmod_matches(
            0x1_0000_0000_0000_0000_0000,
            0x10_0000_0000_0000_0000_0000_0000,
            0x0,
            0x1_0000_0000_0000_0000_0000,
        )
        && udivmod_matches(
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0x1,
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0x0,
        )
        && udivmod_matches(
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0x1_0000_0000_0000_0000,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
        )
        && udivmod_matches(
            0x1_8EE9_0FF6_C373_E0EE_4E3F_0AD2,
            0xDB4_DA5F_49F8_B478,
            0x1D_1A94_9D8C,
            0xCD9_8CBF_CE2E_C132,
        )
        && udivmod_matches(
            0x8000_0000_0000_0000_0000_0001,
            0x8000_0000_0000_0000_0000_0000,
            0x1,
            0x1,
        )
        && udivmod_matches(
            0x8000_0000_0000_0000_0000_0000,
            0x8000_0000_0000_0000_0000_0000,
            0x1,
            0x0,
        )
        && udivmod_matches(
            0x1234_5678_9ABC_DEF0_1122_3344_5566_7788,
            0x1234_5678_9ABC_DEF0_1122_3344_5566_7787,
            0x1,
            0x1,
        )
        && udivmod_matches(
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE,
            0x1,
            0x1,
        )
        && udivmod_matches(
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000_0000_0000_0000_0000,
            0x1,
            0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
        )
        && udivmod_matches(
            0xAC85_A081_0625_55D6_7C6A_A3A6_40C7,
            0xAC85_A081_9378_6CCC_DB21,
            0xFFFF_FFFF,
            0x1F32_898B_34C2_1073_1BE8,
        )
        && udivmod_matches(
            0x33B_2E3C_A30B_AE79_87D0_803C_E7FF_FFFF,
            0x33B_2E3C_9FD0_803C_E800_0000,
            0x1_0000_0000,
            0x33B_2E3C_9FD0_803C_E7FF_FFFF,
        )
        && udivmod_matches(
            0x20_0000_0000_0000_0000_0000_6079,
            0x10_0000_0000_0000_0000_0000_3039,
            0x2,
            0x7,
        )
        && udivmod_matches(
            0x2468_ACF1_0000_0000_0000_0000,
            0x1234_5678_FFFF_FFFF_FFFF_FFFF,
            0x1,
            0x1234_5678_0000_0000_0000_0001,
        )
        && udivmod_matches(
            0x2468_ACF1_FFFF_FFFF_FFFF_FFFF,
            0x1234_5678_FFFF_FFFF_FFFF_FFFF,
            0x2,
            0x1,
        )
        && udivmod_matches(
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000_0000_0001,
            0x1_FFFF_FFFF,
            0x7FFF_FFFF_FFFF_FFFE_0000_0000,
        )
        && udivmod_matches(
            0xFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0x80_0000_0000_0000_0000_0003,
            0x1_FFFF_FFFF,
            0x7F_FFFF_FFFF_FFFA_0000_0002,
        )
        && udivmod_matches(
            0x100_0000_0000_0000_0000_0000_0000_0000,
            0x80_0000_0000_0000_0000_0003,
            0x1_FFFF_FFFF,
            0x7F_FFFF_FFFF_FFFA_0000_0003,
        )
        && udivmod_matches(
            0x100_0000_0000_0000_0000_0000_0000_0000,
            0x80_0000_0000_0000_0000_0000,
            0x2_0000_0000,
            0x0,
        )
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
fn sub_f64(a: f64, b: f64) -> f64 {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a - b)
}

#[cfg(target_arch = "bpf")]
fn div_f64(a: f64, b: f64) -> f64 {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a / b)
}

#[cfg(target_arch = "bpf")]
fn neg_f64(a: f64) -> f64 {
    let mut a = a;
    core::hint::black_box(&mut a);
    core::hint::black_box(-a)
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
fn test_subdf3() -> bool {
    sub_f64(3.5, 2.0).to_bits() == 1.5f64.to_bits()
        && sub_f64(-1.5, 0.25).to_bits() == (-1.75f64).to_bits()
        && sub_f64(1.0, 1.0).to_bits() == 0.0f64.to_bits()
        && sub_f64(-0.0, 0.0).to_bits() == (-0.0f64).to_bits()
        && sub_f64(0.0, -0.0).to_bits() == 0.0f64.to_bits()
        && sub_f64(f64::MAX, f64::NEG_INFINITY).to_bits() == f64::INFINITY.to_bits()
        && sub_f64(f64::NEG_INFINITY, f64::INFINITY).to_bits() == f64::NEG_INFINITY.to_bits()
        && is_nan(sub_f64(f64::INFINITY, f64::INFINITY))
        && is_nan(sub_f64(f64::NAN, 1.0))
        && sub_f64(f64::MIN_POSITIVE, f64::from_bits(1)).to_bits() == 0x000F_FFFF_FFFF_FFFF
        && sub_f64(f64::from_bits(1), f64::from_bits(1)).to_bits() == 0
}

#[cfg(target_arch = "bpf")]
fn test_divdf3() -> bool {
    div_f64(7.0, 2.0).to_bits() == 3.5f64.to_bits()
        && div_f64(-9.0, 4.0).to_bits() == (-2.25f64).to_bits()
        && div_f64(1.0, 3.0).to_bits() == 0x3FD5_5555_5555_5555
        && div_f64(f64::INFINITY, 2.0).to_bits() == f64::INFINITY.to_bits()
        && div_f64(f64::NEG_INFINITY, -2.0).to_bits() == f64::INFINITY.to_bits()
        && div_f64(2.0, f64::INFINITY).to_bits() == 0.0f64.to_bits()
        && div_f64(-2.0, f64::INFINITY).to_bits() == (-0.0f64).to_bits()
        && div_f64(1.0, 0.0).to_bits() == f64::INFINITY.to_bits()
        && div_f64(1.0, -0.0).to_bits() == f64::NEG_INFINITY.to_bits()
        && div_f64(-0.0, -3.0).to_bits() == 0.0f64.to_bits()
        && is_nan(div_f64(0.0, 0.0))
        && is_nan(div_f64(f64::INFINITY, f64::INFINITY))
        && is_nan(div_f64(f64::NAN, 1.0))
        && div_f64(f64::MAX, 0.5).to_bits() == f64::INFINITY.to_bits()
        && div_f64(f64::MAX, f64::MAX).to_bits() == 1.0f64.to_bits()
        && div_f64(f64::MIN_POSITIVE, 2.0).to_bits() == 0x0008_0000_0000_0000
        && div_f64(f64::from_bits(1), f64::from_bits(1)).to_bits() == 1.0f64.to_bits()
        && div_f64(1.0, f64::from_bits(0x3FF0_0000_0000_0001)).to_bits() == 0x3FEF_FFFF_FFFF_FFFE
        && div_f64(f64::from_bits(0x001F_FFFF_FFFF_FFFF), 2.0).to_bits() == 0x0010_0000_0000_0000
        && div_f64(-f64::from_bits(0x001F_FFFF_FFFF_FFFF), 2.0).to_bits() == 0x8010_0000_0000_0000
        && div_f64(f64::from_bits(1), 2.0).to_bits() == 0
}

#[cfg(target_arch = "bpf")]
fn test_negdf2() -> bool {
    neg_f64(3.5).to_bits() == (-3.5f64).to_bits()
        && neg_f64(-0.0).to_bits() == 0.0f64.to_bits()
        && neg_f64(0.0).to_bits() == (-0.0f64).to_bits()
        && neg_f64(f64::INFINITY).to_bits() == f64::NEG_INFINITY.to_bits()
        && neg_f64(f64::NEG_INFINITY).to_bits() == f64::INFINITY.to_bits()
        && neg_f64(f64::MIN_POSITIVE).to_bits() == (-f64::MIN_POSITIVE).to_bits()
        && neg_f64(f64::from_bits(1)).to_bits() == 0x8000_0000_0000_0001
        && neg_f64(f64::from_bits(0x7FF8_0000_0000_0001)).to_bits() == 0xFFF8_0000_0000_0001
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
fn u64_to_f64(i: u64) -> f64 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f64)
}

#[cfg(target_arch = "bpf")]
fn f64_to_u64(f: f64) -> u64 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as u64)
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
fn lt_f64(a: f64, b: f64) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a < b)
}

#[cfg(target_arch = "bpf")]
fn le_f64(a: f64, b: f64) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a <= b)
}

#[cfg(target_arch = "bpf")]
fn eq_f64(a: f64, b: f64) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a == b)
}

#[cfg(target_arch = "bpf")]
fn ne_f64(a: f64, b: f64) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a != b)
}

#[cfg(target_arch = "bpf")]
fn ge_f32(a: f32, b: f32) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a >= b)
}

#[cfg(target_arch = "bpf")]
fn gt_f32(a: f32, b: f32) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a > b)
}

#[cfg(target_arch = "bpf")]
fn lt_f32(a: f32, b: f32) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a < b)
}

#[cfg(target_arch = "bpf")]
fn le_f32(a: f32, b: f32) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a <= b)
}

#[cfg(target_arch = "bpf")]
fn eq_f32(a: f32, b: f32) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a == b)
}

#[cfg(target_arch = "bpf")]
fn ne_f32(a: f32, b: f32) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a != b)
}

#[cfg(target_arch = "bpf")]
fn unord_sf(a: f32, b: f32) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a.is_nan() || b.is_nan())
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

#[cfg(target_arch = "bpf")]
fn test_ltdf2() -> bool {
    !lt_f64(2.0, 1.0) // greater
        && !lt_f64(1.0, 1.0) // equal is NOT less
        && lt_f64(1.0, 2.0) // less
        && !lt_f64(-1.0, -2.0) // both negative, greater
        && lt_f64(-2.0, -1.0) // both negative, less
        && !lt_f64(-1.0, -1.0) // both negative, equal is NOT less
        && !lt_f64(0.0, -0.0) // +0 is not < -0
        && !lt_f64(-0.0, 0.0) // -0 is not < +0
        && !lt_f64(1.0, -1.0) // mixed sign
        && lt_f64(-1.0, 1.0)
        && !lt_f64(f64::INFINITY, f64::MAX)
        && lt_f64(f64::NEG_INFINITY, f64::MAX)
        && !lt_f64(f64::INFINITY, f64::INFINITY) // equal +inf is NOT less
        && !lt_f64(f64::NEG_INFINITY, f64::NEG_INFINITY)
        && lt_f64(f64::NEG_INFINITY, f64::INFINITY) // -inf < +inf
        && !lt_f64(f64::MIN_POSITIVE, 0.0) // smallest normal is not < 0
        && !lt_f64(f64::from_bits(1), 0.0) // smallest subnormal is not < 0
        && lt_f64(0.0, f64::from_bits(1))
        && !lt_f64(f64::NAN, 1.0) // NaN is unordered
        && !lt_f64(1.0, f64::NAN)
        && !lt_f64(f64::NAN, f64::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_ledf2() -> bool {
    !le_f64(2.0, 1.0) // greater
        && le_f64(1.0, 1.0) // equal
        && le_f64(1.0, 2.0) // less
        && !le_f64(-1.0, -2.0) // both negative, greater
        && le_f64(-2.0, -1.0) // both negative, less
        && le_f64(-1.0, -1.0) // both negative, equal
        && le_f64(0.0, -0.0) // +0 <= -0
        && le_f64(-0.0, 0.0) // -0 <= +0
        && !le_f64(1.0, -1.0) // mixed sign
        && le_f64(-1.0, 1.0)
        && !le_f64(f64::INFINITY, f64::MAX)
        && le_f64(f64::NEG_INFINITY, f64::MAX)
        && le_f64(f64::INFINITY, f64::INFINITY) // equal +inf
        && le_f64(f64::NEG_INFINITY, f64::NEG_INFINITY) // equal -inf
        && le_f64(f64::NEG_INFINITY, f64::INFINITY) // -inf <= +inf
        && !le_f64(f64::from_bits(1), 0.0) // smallest subnormal is not <= 0
        && le_f64(0.0, f64::from_bits(1))
        && !le_f64(f64::NAN, 1.0) // NaN is unordered
        && !le_f64(1.0, f64::NAN)
        && !le_f64(f64::NAN, f64::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_eqdf2() -> bool {
    !eq_f64(2.0, 1.0) // greater
        && eq_f64(1.0, 1.0) // equal
        && !eq_f64(1.0, 2.0) // less
        && !eq_f64(-1.0, -2.0) // both negative, greater
        && !eq_f64(-2.0, -1.0) // both negative, less
        && eq_f64(-1.0, -1.0) // both negative, equal
        && eq_f64(0.0, -0.0) // +0 == -0
        && eq_f64(-0.0, 0.0) // -0 == +0
        && !eq_f64(1.0, -1.0) // mixed sign
        && !eq_f64(-1.0, 1.0)
        && eq_f64(f64::INFINITY, f64::INFINITY) // equal +inf
        && eq_f64(f64::NEG_INFINITY, f64::NEG_INFINITY) // equal -inf
        && !eq_f64(f64::INFINITY, f64::NEG_INFINITY)
        && !eq_f64(f64::MAX, f64::from_bits(0x7FEF_FFFF_FFFF_FFFE)) // MAX-1ulp
        && !eq_f64(f64::NAN, f64::NAN) // NaN is not equal to itself
        && !eq_f64(f64::NAN, 1.0)
        && !eq_f64(1.0, f64::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_nedf2() -> bool {
    ne_f64(2.0, 1.0) // greater
        && !ne_f64(1.0, 1.0) // equal
        && ne_f64(1.0, 2.0) // less
        && ne_f64(-1.0, -2.0) // both negative, greater
        && ne_f64(-2.0, -1.0) // both negative, less
        && !ne_f64(-1.0, -1.0) // both negative, equal
        && !ne_f64(0.0, -0.0) // +0 != -0 is false
        && !ne_f64(-0.0, 0.0) // -0 != +0 is false
        && ne_f64(1.0, -1.0) // mixed sign
        && ne_f64(-1.0, 1.0)
        && !ne_f64(f64::INFINITY, f64::INFINITY) // equal +inf
        && !ne_f64(f64::NEG_INFINITY, f64::NEG_INFINITY) // equal -inf
        && ne_f64(f64::INFINITY, f64::NEG_INFINITY)
        && ne_f64(f64::from_bits(1), 0.0) // smallest subnormal is not 0
        && ne_f64(f64::NAN, f64::NAN) // NaN is not equal to itself
        && ne_f64(f64::NAN, 1.0)
        && ne_f64(1.0, f64::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_ltsf2() -> bool {
    !lt_f32(2.0, 1.0) // greater
        && !lt_f32(1.0, 1.0) // equal is NOT less
        && lt_f32(1.0, 2.0) // less
        && !lt_f32(-1.0, -2.0) // both negative, greater
        && lt_f32(-2.0, -1.0) // both negative, less
        && !lt_f32(-1.0, -1.0) // both negative, equal is NOT less
        && !lt_f32(0.0, -0.0) // +0 is not < -0
        && !lt_f32(-0.0, 0.0) // -0 is not < +0
        && !lt_f32(1.0, -1.0) // mixed sign
        && lt_f32(-1.0, 1.0)
        && !lt_f32(f32::INFINITY, f32::MAX)
        && lt_f32(f32::NEG_INFINITY, f32::MAX)
        && !lt_f32(f32::INFINITY, f32::INFINITY) // equal +inf is NOT less
        && !lt_f32(f32::NEG_INFINITY, f32::NEG_INFINITY)
        && lt_f32(f32::NEG_INFINITY, f32::INFINITY) // -inf < +inf
        && !lt_f32(f32::MIN_POSITIVE, 0.0) // smallest normal is not < 0
        && !lt_f32(f32::from_bits(1), 0.0) // smallest subnormal is not < 0
        && lt_f32(0.0, f32::from_bits(1))
        && !lt_f32(f32::NAN, 1.0) // NaN is unordered
        && !lt_f32(1.0, f32::NAN)
        && !lt_f32(f32::NAN, f32::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_lesf2() -> bool {
    !le_f32(2.0, 1.0) // greater
        && le_f32(1.0, 1.0) // equal
        && le_f32(1.0, 2.0) // less
        && !le_f32(-1.0, -2.0) // both negative, greater
        && le_f32(-2.0, -1.0) // both negative, less
        && le_f32(-1.0, -1.0) // both negative, equal
        && le_f32(0.0, -0.0) // +0 <= -0
        && le_f32(-0.0, 0.0) // -0 <= +0
        && !le_f32(1.0, -1.0) // mixed sign
        && le_f32(-1.0, 1.0)
        && !le_f32(f32::INFINITY, f32::MAX)
        && le_f32(f32::NEG_INFINITY, f32::MAX)
        && le_f32(f32::INFINITY, f32::INFINITY) // equal +inf
        && le_f32(f32::NEG_INFINITY, f32::NEG_INFINITY) // equal -inf
        && le_f32(f32::NEG_INFINITY, f32::INFINITY) // -inf <= +inf
        && !le_f32(f32::from_bits(1), 0.0) // smallest subnormal is not <= 0
        && le_f32(0.0, f32::from_bits(1))
        && !le_f32(f32::NAN, 1.0) // NaN is unordered
        && !le_f32(1.0, f32::NAN)
        && !le_f32(f32::NAN, f32::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_eqsf2() -> bool {
    !eq_f32(2.0, 1.0) // greater
        && eq_f32(1.0, 1.0) // equal
        && !eq_f32(1.0, 2.0) // less
        && !eq_f32(-1.0, -2.0) // both negative, greater
        && !eq_f32(-2.0, -1.0) // both negative, less
        && eq_f32(-1.0, -1.0) // both negative, equal
        && eq_f32(0.0, -0.0) // +0 == -0
        && eq_f32(-0.0, 0.0) // -0 == +0
        && !eq_f32(1.0, -1.0) // mixed sign
        && !eq_f32(-1.0, 1.0)
        && eq_f32(f32::INFINITY, f32::INFINITY) // equal +inf
        && eq_f32(f32::NEG_INFINITY, f32::NEG_INFINITY) // equal -inf
        && !eq_f32(f32::INFINITY, f32::NEG_INFINITY)
        && !eq_f32(f32::MAX, f32::from_bits(0x7F7F_FFFE)) // MAX-1ulp
        && !eq_f32(f32::NAN, f32::NAN) // NaN is not equal to itself
        && !eq_f32(f32::NAN, 1.0)
        && !eq_f32(1.0, f32::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_nesf2() -> bool {
    ne_f32(2.0, 1.0) // greater
        && !ne_f32(1.0, 1.0) // equal
        && ne_f32(1.0, 2.0) // less
        && ne_f32(-1.0, -2.0) // both negative, greater
        && ne_f32(-2.0, -1.0) // both negative, less: ne is true for any unequal pair
        && !ne_f32(-1.0, -1.0) // both negative, equal
        && !ne_f32(0.0, -0.0) // +0 != -0 is false
        && !ne_f32(-0.0, 0.0) // -0 != +0 is false
        && ne_f32(1.0, -1.0) // mixed sign
        && ne_f32(-1.0, 1.0)
        && !ne_f32(f32::INFINITY, f32::INFINITY) // equal +inf
        && !ne_f32(f32::NEG_INFINITY, f32::NEG_INFINITY) // equal -inf
        && ne_f32(f32::INFINITY, f32::NEG_INFINITY)
        && ne_f32(f32::from_bits(1), 0.0) // smallest subnormal is not 0
        && ne_f32(f32::NAN, f32::NAN) // NaN is not equal to itself
        && ne_f32(f32::NAN, 1.0)
        && ne_f32(1.0, f32::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_gtsf2() -> bool {
    gt_f32(2.0, 1.0) // greater
        && !gt_f32(1.0, 1.0) // equal is NOT greater
        && !gt_f32(1.0, 2.0) // less
        && gt_f32(-1.0, -2.0) // both negative, greater
        && !gt_f32(-2.0, -1.0) // both negative, less
        && !gt_f32(-1.0, -1.0) // both negative, equal is NOT greater
        && !gt_f32(0.0, -0.0) // +0 is not > -0
        && !gt_f32(-0.0, 0.0) // -0 is not > +0
        && gt_f32(1.0, -1.0) // mixed sign
        && !gt_f32(-1.0, 1.0)
        && gt_f32(f32::INFINITY, f32::MAX)
        && !gt_f32(f32::INFINITY, f32::INFINITY) // equal +inf is NOT greater
        && !gt_f32(f32::NEG_INFINITY, f32::NEG_INFINITY) // equal -inf is NOT greater
        && gt_f32(f32::INFINITY, f32::NEG_INFINITY) // +inf > -inf
        && !gt_f32(f32::NEG_INFINITY, f32::INFINITY) // -inf is not > +inf
        && gt_f32(f32::MIN_POSITIVE, 0.0) // smallest normal > 0
        && gt_f32(f32::from_bits(1), 0.0) // smallest subnormal > 0
        && !gt_f32(f32::NAN, 1.0) // NaN is unordered
        && !gt_f32(1.0, f32::NAN)
        && !gt_f32(f32::NAN, f32::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_gesf2() -> bool {
    ge_f32(2.0, 1.0) // greater
        && ge_f32(1.0, 1.0) // equal
        && !ge_f32(1.0, 2.0) // less
        && ge_f32(-1.0, -2.0) // both negative, greater
        && !ge_f32(-2.0, -1.0) // both negative, less
        && ge_f32(-1.0, -1.0) // both negative, equal
        && ge_f32(0.0, -0.0) // +0 >= -0
        && ge_f32(-0.0, 0.0) // -0 >= +0
        && ge_f32(1.0, -1.0) // mixed sign
        && !ge_f32(-1.0, 1.0)
        && ge_f32(f32::INFINITY, f32::MAX)
        && ge_f32(f32::MAX, f32::NEG_INFINITY)
        && ge_f32(f32::INFINITY, f32::INFINITY) // equal +inf
        && ge_f32(f32::NEG_INFINITY, f32::NEG_INFINITY) // equal -inf
        && !ge_f32(f32::NEG_INFINITY, f32::INFINITY) // -inf < +inf
        && ge_f32(f32::from_bits(1), 0.0) // smallest subnormal >= 0
        && !ge_f32(f32::NAN, 1.0) // NaN is unordered
        && !ge_f32(1.0, f32::NAN)
        && !ge_f32(f32::NAN, f32::NAN)
}

#[cfg(target_arch = "bpf")]
fn test_unordsf2() -> bool {
    unord_sf(f32::NAN, 1.0)
        && unord_sf(1.0, f32::NAN)
        && unord_sf(f32::NAN, f32::NAN)
        && !unord_sf(1.0, 2.0)
        && !unord_sf(0.0, -0.0)
        && !unord_sf(f32::INFINITY, f32::NEG_INFINITY) // inf is not NaN
}

#[cfg(target_arch = "bpf")]
fn i64_to_f64(i: i64) -> f64 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f64)
}

#[cfg(target_arch = "bpf")]
fn i32_to_f64(i: i32) -> f64 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f64)
}

#[cfg(target_arch = "bpf")]
fn i16_to_f64(i: i16) -> f64 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f64)
}

#[cfg(target_arch = "bpf")]
fn i8_to_f64(i: i8) -> f64 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f64)
}

#[cfg(target_arch = "bpf")]
fn u32_to_f64(i: u32) -> f64 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f64)
}

#[cfg(target_arch = "bpf")]
fn f64_to_i64(f: f64) -> i64 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as i64)
}

#[cfg(target_arch = "bpf")]
fn f64_to_i32(f: f64) -> i32 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as i32)
}

#[cfg(target_arch = "bpf")]
fn f64_to_u32(f: f64) -> u32 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as u32)
}

#[cfg(target_arch = "bpf")]
fn f64_to_i8(f: f64) -> i8 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as i8)
}

#[cfg(target_arch = "bpf")]
fn f64_to_i16(f: f64) -> i16 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as i16)
}

#[cfg(target_arch = "bpf")]
fn f64_to_u8(f: f64) -> u8 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as u8)
}

#[cfg(target_arch = "bpf")]
fn f64_to_u16(f: f64) -> u16 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as u16)
}

#[cfg(target_arch = "bpf")]
fn f32_to_i64(f: f32) -> i64 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as i64)
}

#[cfg(target_arch = "bpf")]
fn f32_to_u64(f: f32) -> u64 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as u64)
}

#[cfg(target_arch = "bpf")]
fn f32_to_i32(f: f32) -> i32 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as i32)
}

#[cfg(target_arch = "bpf")]
fn f32_to_u32(f: f32) -> u32 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as u32)
}

#[cfg(target_arch = "bpf")]
fn f32_to_i8(f: f32) -> i8 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as i8)
}

#[cfg(target_arch = "bpf")]
fn f32_to_i16(f: f32) -> i16 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as i16)
}

#[cfg(target_arch = "bpf")]
fn f32_to_u8(f: f32) -> u8 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as u8)
}

#[cfg(target_arch = "bpf")]
fn f32_to_u16(f: f32) -> u16 {
    let mut f = f;
    core::hint::black_box(&mut f);
    core::hint::black_box(f as u16)
}

#[cfg(target_arch = "bpf")]
fn unord_df(a: f64, b: f64) -> bool {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a.is_nan() || b.is_nan())
}

#[cfg(target_arch = "bpf")]
fn test_floatdidf() -> bool {
    i64_to_f64(0).to_bits() == 0.0f64.to_bits()
        && i64_to_f64(1).to_bits() == 1.0f64.to_bits()
        && i64_to_f64(-1).to_bits() == (-1.0f64).to_bits()
        && i64_to_f64(3).to_bits() == 0x4008_0000_0000_0000
        && i64_to_f64(-3).to_bits() == 0xC008_0000_0000_0000
        && i64_to_f64(1 << 53).to_bits() == 0x4340_0000_0000_0000
        && i64_to_f64((1 << 53) + 1).to_bits() == 0x4340_0000_0000_0000 // ties-to-even rounds down
        && i64_to_f64((1 << 53) + 3).to_bits() == 0x4340_0000_0000_0002 // ties-to-even rounds up
        && i64_to_f64(-((1 << 53) + 1)).to_bits() == 0xC340_0000_0000_0000
        && i64_to_f64(i64::MAX).to_bits() == 0x43E0_0000_0000_0000 // rounds up to 2^63
        && i64_to_f64(i64::MIN).to_bits() == 0xC3E0_0000_0000_0000 // exact -2^63
        && i64_to_f64(-123456789).to_bits() == 0xC19D_6F34_5400_0000
}

#[cfg(target_arch = "bpf")]
fn test_floatsidf() -> bool {
    i16_to_f64(0).to_bits() == 0.0f64.to_bits()
        && i16_to_f64(1).to_bits() == 1.0f64.to_bits()
        && i16_to_f64(-1).to_bits() == (-1.0f64).to_bits()
        && i16_to_f64(3).to_bits() == 0x4008_0000_0000_0000
        && i16_to_f64(-3).to_bits() == 0xC008_0000_0000_0000
        && i16_to_f64(i16::MAX).to_bits() == 0x40DF_FFC0_0000_0000
        && i16_to_f64(i16::MIN).to_bits() == 0xC0E0_0000_0000_0000
        && i16_to_f64(-12345).to_bits() == 0xC0C8_1C80_0000_0000
        && i8_to_f64(0).to_bits() == 0.0f64.to_bits()
        && i8_to_f64(1).to_bits() == 1.0f64.to_bits()
        && i8_to_f64(-1).to_bits() == (-1.0f64).to_bits()
        && i8_to_f64(3).to_bits() == 0x4008_0000_0000_0000
        && i8_to_f64(-3).to_bits() == 0xC008_0000_0000_0000
        && i8_to_f64(127).to_bits() == 0x405F_C000_0000_0000 // i8::MAX
        && i8_to_f64(-128).to_bits() == 0xC060_0000_0000_0000 // i8::MIN
        && i32_to_f64(0).to_bits() == 0.0f64.to_bits()
        && i32_to_f64(1).to_bits() == 1.0f64.to_bits()
        && i32_to_f64(-1).to_bits() == (-1.0f64).to_bits()
        && i32_to_f64(3).to_bits() == 0x4008_0000_0000_0000
        && i32_to_f64(-3).to_bits() == 0xC008_0000_0000_0000
        && i32_to_f64(123456789).to_bits() == 0x419D_6F34_5400_0000 // exact
        && i32_to_f64(i32::MAX).to_bits() == 0x41DF_FFFF_FFC0_0000 // exact, all i32 exact in f64
        && i32_to_f64(i32::MIN).to_bits() == 0xC1E0_0000_0000_0000 // exact -2^31
}

#[cfg(target_arch = "bpf")]
fn test_floatunsidf() -> bool {
    u32_to_f64(0).to_bits() == 0.0f64.to_bits()
        && u32_to_f64(1).to_bits() == 1.0f64.to_bits()
        && u32_to_f64(3).to_bits() == 0x4008_0000_0000_0000
        && u32_to_f64(65535).to_bits() == 0x40EF_FFE0_0000_0000
        && u32_to_f64(16777216).to_bits() == 0x4170_0000_0000_0000
        && u32_to_f64(16777217).to_bits() == 0x4170_0000_1000_0000 // exact in f64
        && u32_to_f64(2147483648).to_bits() == 0x41E0_0000_0000_0000
        && u32_to_f64(u32::MAX).to_bits() == 0x41EF_FFFF_FFE0_0000
}

#[cfg(target_arch = "bpf")]
fn test_fixdfdi() -> bool {
    // Truncation toward zero.
    f64_to_i64(0.0) == 0
        && f64_to_i64(-0.0) == 0
        && f64_to_i64(0.5) == 0
        && f64_to_i64(-0.5) == 0
        && f64_to_i64(1.0) == 1
        && f64_to_i64(-1.0) == -1
        && f64_to_i64(1.9999999) == 1
        && f64_to_i64(-1.9999999) == -1
        && f64_to_i64(4503599627370496.0) == 4503599627370496 // 2^52
        && f64_to_i64(9223372036854774784.0) == 9223372036854774784 // 2^63 - 2^11
        && f64_to_i64(-9223372036854775808.0) == i64::MIN // exact -2^63
        && f64_to_i64(9223372036854775808.0) == i64::MAX // +2^63 saturates
        && f64_to_i64(13835058055282163712.0) == i64::MAX // 1.5 * 2^63 saturates
        && f64_to_i64(-13835058055282163712.0) == i64::MIN // -1.5 * 2^63 saturates
        && f64_to_i64(18446744073709551616.0) == i64::MAX // 2^64 saturates
        && f64_to_i64(-18446744073709551616.0) == i64::MIN // -2^64 saturates
        && f64_to_i64(f64::MAX) == i64::MAX // huge finite saturates
        && f64_to_i64(f64::INFINITY) == i64::MAX
        && f64_to_i64(f64::NEG_INFINITY) == i64::MIN
        && f64_to_i64(f64::NAN) == 0
}

#[cfg(target_arch = "bpf")]
fn test_unorddf2() -> bool {
    unord_df(f64::NAN, 1.0)
        && unord_df(1.0, f64::NAN)
        && unord_df(f64::NAN, f64::NAN)
        && !unord_df(1.0, 2.0)
        && !unord_df(0.0, -0.0)
        && !unord_df(f64::INFINITY, f64::NEG_INFINITY) // inf is not NaN
}

#[cfg(target_arch = "bpf")]
fn add_f32(a: f32, b: f32) -> f32 {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a + b)
}

#[cfg(target_arch = "bpf")]
fn sub_f32(a: f32, b: f32) -> f32 {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a - b)
}

#[cfg(target_arch = "bpf")]
fn mul_f32(a: f32, b: f32) -> f32 {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a * b)
}

#[cfg(target_arch = "bpf")]
fn div_f32(a: f32, b: f32) -> f32 {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    core::hint::black_box(a / b)
}

#[cfg(target_arch = "bpf")]
fn u32_to_f32(i: u32) -> f32 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f32)
}

#[cfg(target_arch = "bpf")]
fn u8_to_f32(u: u8) -> f32 {
    let mut u = u;
    core::hint::black_box(&mut u);
    core::hint::black_box(u as f32)
}

#[cfg(target_arch = "bpf")]
fn u16_to_f32(u: u16) -> f32 {
    let mut u = u;
    core::hint::black_box(&mut u);
    core::hint::black_box(u as f32)
}

#[cfg(target_arch = "bpf")]
fn i8_to_f32(i: i8) -> f32 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f32)
}

#[cfg(target_arch = "bpf")]
fn i16_to_f32(i: i16) -> f32 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f32)
}

#[cfg(target_arch = "bpf")]
fn i32_to_f32(i: i32) -> f32 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f32)
}

#[cfg(target_arch = "bpf")]
fn i64_to_f32(i: i64) -> f32 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f32)
}

#[cfg(target_arch = "bpf")]
fn u64_to_f32(i: u64) -> f32 {
    let mut i = i;
    core::hint::black_box(&mut i);
    core::hint::black_box(i as f32)
}

#[cfg(target_arch = "bpf")]
fn is_nan_f32(x: f32) -> bool {
    (x.to_bits() & 0x7FFF_FFFF) > 0x7F80_0000
}

#[cfg(target_arch = "bpf")]
fn test_addsf3() -> bool {
    add_f32(3.5, 2.0).to_bits() == 5.5f32.to_bits()
        && add_f32(-1.5, 0.25).to_bits() == (-1.25f32).to_bits()
        && add_f32(1.0, -1.0).to_bits() == 0.0f32.to_bits()
        && add_f32(u8_to_f32(200), u8_to_f32(100)).to_bits() == 300.0f32.to_bits()
}

#[cfg(target_arch = "bpf")]
fn test_addsf3_ieee() -> bool {
    is_nan_f32(add_f32(f32::NAN, 1.0))
        && add_f32(f32::INFINITY, 1.0).to_bits() == f32::INFINITY.to_bits()
        && is_nan_f32(add_f32(f32::INFINITY, f32::NEG_INFINITY))
        && add_f32(0.0, -0.0).to_bits() == 0.0f32.to_bits()
        && add_f32(-0.0, -0.0).to_bits() == (-0.0f32).to_bits()
        && add_f32(f32::from_bits(1), f32::from_bits(1)).to_bits() == f32::from_bits(2).to_bits()
        && add_f32(0.1, 0.2).to_bits() == 0x3E99_999A
        && add_f32(f32::MAX, f32::MAX).to_bits() == f32::INFINITY.to_bits()
}

#[cfg(target_arch = "bpf")]
fn test_subsf3() -> bool {
    sub_f32(3.5, 2.0).to_bits() == 1.5f32.to_bits()
        && sub_f32(-1.5, 0.25).to_bits() == (-1.75f32).to_bits()
        && sub_f32(1.0, 1.0).to_bits() == 0.0f32.to_bits()
        && sub_f32(-0.0, 0.0).to_bits() == (-0.0f32).to_bits()
        && sub_f32(0.0, -0.0).to_bits() == 0.0f32.to_bits()
        && sub_f32(f32::MIN_POSITIVE, f32::from_bits(1)).to_bits() == 0x007F_FFFF
        && sub_f32(f32::from_bits(1), f32::from_bits(1)).to_bits() == 0
        && sub_f32(f32::INFINITY, f32::NEG_INFINITY).to_bits() == f32::INFINITY.to_bits()
        && sub_f32(f32::NEG_INFINITY, f32::INFINITY).to_bits() == f32::NEG_INFINITY.to_bits()
        && is_nan_f32(sub_f32(f32::INFINITY, f32::INFINITY))
        && is_nan_f32(sub_f32(f32::NAN, 1.0))
}

#[cfg(target_arch = "bpf")]
fn test_mulsf3() -> bool {
    mul_f32(3.5, 2.0).to_bits() == 7.0f32.to_bits()
        && mul_f32(0.5, 0.5).to_bits() == 0.25f32.to_bits()
        && mul_f32(-2.0, 3.0).to_bits() == (-6.0f32).to_bits()
}

#[cfg(target_arch = "bpf")]
fn test_mulsf3_ieee() -> bool {
    is_nan_f32(mul_f32(f32::NAN, 2.0))
        && mul_f32(f32::INFINITY, 2.0).to_bits() == f32::INFINITY.to_bits()
        && is_nan_f32(mul_f32(f32::INFINITY, 0.0))
        && mul_f32(-1.0, 0.0).to_bits() == (-0.0f32).to_bits()
        && mul_f32(-1.0, -0.0).to_bits() == 0.0f32.to_bits()
        && mul_f32(f32::from_bits(2), 0.5).to_bits() == f32::from_bits(1).to_bits()
        && mul_f32(f32::MAX, 2.0).to_bits() == f32::INFINITY.to_bits()
        && mul_f32(f32::from_bits(1), 0.5).to_bits() == 0
}

#[cfg(target_arch = "bpf")]
fn test_divsf3() -> bool {
    div_f32(7.0, 2.0).to_bits() == 3.5f32.to_bits()
        && div_f32(-9.0, 4.0).to_bits() == (-2.25f32).to_bits()
        && div_f32(1.0, 3.0).to_bits() == 0x3EAA_AAAB
        && div_f32(f32::INFINITY, 2.0).to_bits() == f32::INFINITY.to_bits()
        && div_f32(f32::NEG_INFINITY, -2.0).to_bits() == f32::INFINITY.to_bits()
        && div_f32(2.0, f32::INFINITY).to_bits() == 0.0f32.to_bits()
        && div_f32(-2.0, f32::INFINITY).to_bits() == (-0.0f32).to_bits()
        && div_f32(1.0, 0.0).to_bits() == f32::INFINITY.to_bits()
        && div_f32(1.0, -0.0).to_bits() == f32::NEG_INFINITY.to_bits()
        && div_f32(-0.0, -3.0).to_bits() == 0.0f32.to_bits()
        && is_nan_f32(div_f32(0.0, 0.0))
        && is_nan_f32(div_f32(f32::INFINITY, f32::INFINITY))
        && is_nan_f32(div_f32(f32::NAN, 1.0))
        && div_f32(f32::MAX, 0.5).to_bits() == f32::INFINITY.to_bits()
        && div_f32(f32::MAX, f32::MAX).to_bits() == 1.0f32.to_bits()
        && div_f32(f32::MIN_POSITIVE, 2.0).to_bits() == 0x0040_0000
        && div_f32(f32::from_bits(1), 2.0).to_bits() == 0
        && div_f32(1.0, f32::from_bits(0x3F80_0001)).to_bits() == 0x3F7F_FFFE
        && div_f32(f32::from_bits(0x00FF_FFFF), 2.0).to_bits() == 0x0080_0000
        && div_f32(-f32::from_bits(0x00FF_FFFF), 2.0).to_bits() == 0x8080_0000
        && div_f32(f32::from_bits(0x007F_FFFF), f32::from_bits(0x3F7F_FFFF)).to_bits()
            == 0x007F_FFFF
}

#[cfg(target_arch = "bpf")]
fn test_floatunsisf() -> bool {
    u32_to_f32(0).to_bits() == 0.0f32.to_bits()
        && u32_to_f32(1).to_bits() == 1.0f32.to_bits()
        && u32_to_f32(3).to_bits() == 0x4040_0000
        && u32_to_f32(u32::MAX).to_bits() == 0x4F80_0000 // rounds up to 2^32
        && u32_to_f32(16777216).to_bits() == 0x4B80_0000 // exact 2^24
        && u32_to_f32(16777217).to_bits() == 0x4B80_0000 // ties-to-even rounds down
        && u32_to_f32(16777218).to_bits() == 0x4B80_0001 // exact
        && u32_to_f32(16777219).to_bits() == 0x4B80_0002 // ties-to-even rounds up
        && u8_to_f32(0).to_bits() == 0.0f32.to_bits()
        && u8_to_f32(255).to_bits() == 255.0f32.to_bits()
        && u16_to_f32(0).to_bits() == 0.0f32.to_bits()
        && u16_to_f32(65535).to_bits() == 0x477F_FF00 // u16::MAX, exact
}

#[cfg(target_arch = "bpf")]
fn test_floatsisf() -> bool {
    i32_to_f32(0).to_bits() == 0.0f32.to_bits()
        && i32_to_f32(1).to_bits() == 1.0f32.to_bits()
        && i32_to_f32(-1).to_bits() == (-1.0f32).to_bits()
        && i32_to_f32(3).to_bits() == 0x4040_0000
        && i32_to_f32(-3).to_bits() == 0xC040_0000
        && i32_to_f32(16777216).to_bits() == 0x4B80_0000 // exact 2^24
        && i32_to_f32(16777217).to_bits() == 0x4B80_0000 // ties-to-even rounds down
        && i32_to_f32(16777218).to_bits() == 0x4B80_0001 // exact
        && i32_to_f32(16777219).to_bits() == 0x4B80_0002 // ties-to-even rounds up
        && i32_to_f32(-16777219).to_bits() == 0xCB80_0002 // negative tie rounds to even
        && i32_to_f32(i32::MAX).to_bits() == 0x4F00_0000 // rounds up to 2^31
        && i32_to_f32(i32::MIN).to_bits() == 0xCF00_0000 // exact -2^31
        && i8_to_f32(127).to_bits() == 0x42FE_0000 // i8::MAX, exact
        && i8_to_f32(-128).to_bits() == 0xC300_0000 // i8::MIN, exact
        && i8_to_f32(-1).to_bits() == (-1.0f32).to_bits()
        && i16_to_f32(i16::MAX).to_bits() == 0x46FF_FE00 // 32767, exact
        && i16_to_f32(i16::MIN).to_bits() == 0xC700_0000 // -32768, exact
}

#[cfg(target_arch = "bpf")]
fn test_floatdisf() -> bool {
    i64_to_f32(0).to_bits() == 0.0f32.to_bits()
        && i64_to_f32(1).to_bits() == 1.0f32.to_bits()
        && i64_to_f32(-1).to_bits() == (-1.0f32).to_bits()
        && i64_to_f32(3).to_bits() == 0x4040_0000
        && i64_to_f32(-3).to_bits() == 0xC040_0000
        && i64_to_f32(16777216).to_bits() == 0x4B80_0000 // exact 2^24
        && i64_to_f32(16777219).to_bits() == 0x4B80_0002 // ties-to-even rounds up
        && i64_to_f32(-16777219).to_bits() == 0xCB80_0002 // negative tie rounds to even
        && i64_to_f32(123456789).to_bits() == 0x4CEB_79A3 // exact
        && i64_to_f32(i64::MAX).to_bits() == 0x5F00_0000 // rounds up to 2^63
        && i64_to_f32(i64::MIN).to_bits() == 0xDF00_0000 // exact -2^63
}

#[cfg(target_arch = "bpf")]
fn test_floatundisf() -> bool {
    u64_to_f32(0).to_bits() == 0.0f32.to_bits()
        && u64_to_f32(1).to_bits() == 1.0f32.to_bits()
        && u64_to_f32(3).to_bits() == 0x4040_0000
        && u64_to_f32(16777216).to_bits() == 0x4B80_0000 // exact 2^24
        && u64_to_f32(16777219).to_bits() == 0x4B80_0002 // ties-to-even rounds up
        && u64_to_f32(123456789).to_bits() == 0x4CEB_79A3 // exact
        && u64_to_f32(1 << 63).to_bits() == 0x5F00_0000 // exact 2^63
        && u64_to_f32((1 << 63) + 1).to_bits() == 0x5F00_0000 // below midpoint rounds down
        && u64_to_f32(u64::MAX).to_bits() == 0x5F80_0000 // rounds up to 2^64
}

#[cfg(target_arch = "bpf")]
fn test_fixsfdi() -> bool {
    f32_to_i64(0.0) == 0
        && f32_to_i64(1.5) == 1
        && f32_to_i64(-1.5) == -1
        && f32_to_i64(0.5) == 0
        && f32_to_i64(-0.5) == 0
        && f32_to_i64(123456789.0) == 123456792 // f32 literal rounds 123456789 -> 123456792
        && f32_to_i64(-123456789.0) == -123456792 // same rounding, negative
        && f32_to_i64(2147483647.0) == 2147483648 // i32::MAX rounds up to 2^31 in f32
        && f32_to_i64(f32::MAX) == i64::MAX // saturates
        && f32_to_i64(f32::MIN) == i64::MIN // saturates
        && f32_to_i64(f32::INFINITY) == i64::MAX
        && f32_to_i64(f32::NEG_INFINITY) == i64::MIN
        && f32_to_i64(f32::NAN) == 0
        && f32_to_i64(-9223372036854775808.0) == i64::MIN // exact -2^63
}

#[cfg(target_arch = "bpf")]
fn test_fixunssfdi() -> bool {
    f32_to_u64(0.0) == 0
        && f32_to_u64(1.5) == 1
        && f32_to_u64(0.5) == 0
        && f32_to_u64(123456789.0) == 123456792 // f32 literal rounds 123456789 -> 123456792
        && f32_to_u64(-1.5) == 0 // negatives truncate/saturate to 0
        && f32_to_u64(u64::MAX as f32) == u64::MAX // 2^64 saturates
        && f32_to_u64(f32::INFINITY) == u64::MAX
        && f32_to_u64(f32::NAN) == 0
        && f32_to_u64(9223372036854775808.0) == 1 << 63 // exact 2^63
}

#[cfg(target_arch = "bpf")]
fn test_fixdfsi() -> bool {
    f64_to_i32(0.0) == 0
        && f64_to_i32(1.5) == 1
        && f64_to_i32(-1.5) == -1
        && f64_to_i32(0.5) == 0
        && f64_to_i32(-0.5) == 0
        && f64_to_i32(2147483647.0) == 2147483647 // exact
        && f64_to_i32(2147483648.0) == i32::MAX // 2^31 saturates
        && f64_to_i32(-2147483649.0) == i32::MIN // saturates
        && f64_to_i32(f64::INFINITY) == i32::MAX
        && f64_to_i32(f64::NEG_INFINITY) == i32::MIN
        && f64_to_i32(f64::NAN) == 0
        && f64_to_i16(32767.0) == 32767 // exact
        && f64_to_i16(32768.0) == i16::MAX // saturates
        && f64_to_i16(-32768.0) == i16::MIN // exact
        && f64_to_i16(-32769.0) == i16::MIN // saturates
        && f64_to_i16(2.9) == 2
        && f64_to_i8(127.0) == 127
        && f64_to_i8(128.0) == i8::MAX // saturates
        && f64_to_i8(-128.0) == i8::MIN // exact
        && f64_to_i8(-129.0) == i8::MIN // saturates
        && f64_to_i8(3.9) == 3
}

#[cfg(target_arch = "bpf")]
fn test_fixunsdfsi() -> bool {
    f64_to_u32(0.0) == 0
        && f64_to_u32(1.5) == 1
        && f64_to_u32(0.5) == 0
        && f64_to_u32(4294967295.0) == u32::MAX // exact 2^32 - 1
        && f64_to_u32(4294967296.0) == u32::MAX // 2^32 saturates
        && f64_to_u32(-1.5) == 0
        && f64_to_u32(f64::INFINITY) == u32::MAX
        && f64_to_u32(f64::NAN) == 0
        && f64_to_u8(255.0) == 255
        && f64_to_u8(300.0) == u8::MAX // saturates
        && f64_to_u8(-1.0) == 0
        && f64_to_u16(65535.0) == 65535 // exact
        && f64_to_u16(65536.0) == u16::MAX // saturates
        && f64_to_u16(-0.5) == 0
}

#[cfg(target_arch = "bpf")]
fn test_fixsfsi() -> bool {
    f32_to_i32(0.0) == 0
        && f32_to_i32(1.5) == 1
        && f32_to_i32(-1.5) == -1
        && f32_to_i32(0.5) == 0
        && f32_to_i32(-0.5) == 0
        && f32_to_i32(123456792.0) == 123456792 // exact 24-bit value
        && f32_to_i32(2147483648.0) == i32::MAX // 2^31 saturates
        && f32_to_i32(-2147483648.0) == i32::MIN // exact -2^31
        && f32_to_i32(f32::INFINITY) == i32::MAX
        && f32_to_i32(f32::NEG_INFINITY) == i32::MIN
        && f32_to_i32(f32::NAN) == 0
        && f32_to_i8(127.0) == 127
        && f32_to_i8(200.0) == i8::MAX // saturates
        && f32_to_i8(-128.0) == i8::MIN // exact
        && f32_to_i8(3.9) == 3
        && f32_to_i16(32767.0) == 32767 // exact
        && f32_to_i16(32768.0) == i16::MAX // saturates
        && f32_to_i16(-32768.0) == i16::MIN // exact
        && f32_to_i16(-32769.0) == i16::MIN // saturates
}

#[cfg(target_arch = "bpf")]
fn test_fixunssfsi() -> bool {
    f32_to_u32(0.0) == 0
        && f32_to_u32(1.5) == 1
        && f32_to_u32(0.5) == 0
        && f32_to_u32(123456792.0) == 123456792 // exact 24-bit value
        && f32_to_u32(4294967296.0) == u32::MAX // 2^32 saturates
        && f32_to_u32(-1.5) == 0
        && f32_to_u32(f32::INFINITY) == u32::MAX
        && f32_to_u32(f32::NAN) == 0
        && f32_to_u8(255.0) == 255
        && f32_to_u8(300.0) == u8::MAX // saturates
        && f32_to_u8(-0.5) == 0
        && f32_to_u16(65535.0) == 65535 // exact
        && f32_to_u16(65536.0) == u16::MAX // saturates
        && f32_to_u16(-0.5) == 0
}

pub mod sel {
    pub const MEMCMP: u8 = 0;
    pub const MEMCPY: u8 = 1;
    pub const MEMMOVE: u8 = 2;
    pub const MEMSET: u8 = 3;
    pub const MULTI3: u8 = 4;
    pub const ADDDF3: u8 = 5;
    pub const MULDF3: u8 = 6;
    pub const FLOATUNDIDF: u8 = 7;
    pub const FIXUNSDFDI: u8 = 8;
    pub const GEDF2: u8 = 9;
    pub const GTDF2: u8 = 10;
    pub const SUBDF3: u8 = 11;
    pub const DIVDF3: u8 = 12;
    pub const NEGDF2: u8 = 13;
    pub const UDIVMODTI3: u8 = 14;
    pub const FLOATDIDF: u8 = 15;
    pub const FIXDFDI: u8 = 16;
    pub const UNORDDF2: u8 = 17;
    pub const ADDSF3: u8 = 18;
    pub const SUBSF3: u8 = 19;
    pub const MULSF3: u8 = 20;
    pub const DIVSF3: u8 = 21;
    pub const FLOATUNSISF: u8 = 22;
    pub const LTDF2: u8 = 23;
    pub const LEDF2: u8 = 24;
    pub const EQDF2: u8 = 25;
    pub const NEDF2: u8 = 26;
    pub const LTSF2: u8 = 27;
    pub const LESF2: u8 = 28;
    pub const EQSF2: u8 = 29;
    pub const NESF2: u8 = 30;
    pub const GTSF2: u8 = 31;
    pub const GESF2: u8 = 32;
    pub const UNORDSF2: u8 = 33;
    pub const FLOATSIDF: u8 = 34;
    pub const FLOATUNSIDF: u8 = 35;
    pub const FLOATSISF: u8 = 36;
    pub const FLOATDISF: u8 = 37;
    pub const FLOATUNDISF: u8 = 38;
    pub const FIXSFDI: u8 = 39;
    pub const FIXUNSSFDI: u8 = 40;
    pub const FIXDFSI: u8 = 41;
    pub const FIXUNSDFSI: u8 = 42;
    pub const FIXSFSI: u8 = 43;
    pub const FIXUNSSFSI: u8 = 44;
}

#[unsafe(no_mangle)]
pub fn entrypoint(_input: *mut u8) -> u64 {
    #[cfg(target_arch = "bpf")]
    {
        let selector = unsafe { *_input.add(16) };

        let ok = match selector {
            sel::MEMCMP => unsafe {
                test_memcmp_eq(INLINE_MEMCMP_THRESHOLD)
                    && test_memcmp_eq(INLINE_MEMCMP_THRESHOLD + 1)
                    && test_memcmp_ne(INLINE_MEMCMP_THRESHOLD)
                    && test_memcmp_ne(INLINE_MEMCMP_THRESHOLD + 1)
            },
            sel::MEMCPY => unsafe {
                test_memcpy(INLINE_MEMCPY_THRESHOLD) && test_memcpy(INLINE_MEMCPY_THRESHOLD + 1)
            },
            sel::MEMMOVE => unsafe {
                test_memmove_nonoverlap(INLINE_MEMMOVE_THRESHOLD)
                    && test_memmove_nonoverlap(INLINE_MEMMOVE_THRESHOLD + 1)
                    && test_memmove_overlap_backward(INLINE_MEMMOVE_THRESHOLD)
                    && test_memmove_overlap_backward(INLINE_MEMMOVE_THRESHOLD + 1)
                    && test_memmove_overlap_forward(INLINE_MEMMOVE_THRESHOLD)
                    && test_memmove_overlap_forward(INLINE_MEMMOVE_THRESHOLD + 1)
            },
            sel::MEMSET => unsafe {
                test_memset(INLINE_MEMSET_THRESHOLD, 0xAB)
                    && test_memset(INLINE_MEMSET_THRESHOLD + 1, 0xAB)
            },
            sel::MULTI3 => test_multi3(),
            sel::ADDDF3 => test_adddf3() && test_adddf3_ieee(),
            sel::MULDF3 => test_muldf3() && test_muldf3_ieee(),
            sel::SUBDF3 => test_subdf3(),
            sel::DIVDF3 => test_divdf3(),
            sel::NEGDF2 => test_negdf2(),
            sel::UDIVMODTI3 => test_udivmodti3(),
            sel::FLOATUNDIDF => test_floatundidf(),
            sel::FIXUNSDFDI => test_fixunsdfdi(),
            sel::GEDF2 => test_gedf2(),
            sel::GTDF2 => test_gtdf2(),
            sel::LTDF2 => test_ltdf2(),
            sel::LEDF2 => test_ledf2(),
            sel::EQDF2 => test_eqdf2(),
            sel::NEDF2 => test_nedf2(),
            sel::LTSF2 => test_ltsf2(),
            sel::LESF2 => test_lesf2(),
            sel::EQSF2 => test_eqsf2(),
            sel::NESF2 => test_nesf2(),
            sel::GTSF2 => test_gtsf2(),
            sel::GESF2 => test_gesf2(),
            sel::UNORDSF2 => test_unordsf2(),
            sel::FLOATSIDF => test_floatsidf(),
            sel::FLOATUNSIDF => test_floatunsidf(),
            sel::FLOATDIDF => test_floatdidf(),
            sel::FIXDFDI => test_fixdfdi(),
            sel::UNORDDF2 => test_unorddf2(),
            sel::ADDSF3 => test_addsf3() && test_addsf3_ieee(),
            sel::SUBSF3 => test_subsf3(),
            sel::MULSF3 => test_mulsf3() && test_mulsf3_ieee(),
            sel::DIVSF3 => test_divsf3(),
            sel::FLOATUNSISF => test_floatunsisf(),
            sel::FLOATSISF => test_floatsisf(),
            sel::FLOATDISF => test_floatdisf(),
            sel::FLOATUNDISF => test_floatundisf(),
            sel::FIXSFDI => test_fixsfdi(),
            sel::FIXUNSSFDI => test_fixunssfdi(),
            sel::FIXDFSI => test_fixdfsi(),
            sel::FIXUNSDFSI => test_fixunsdfsi(),
            sel::FIXSFSI => test_fixsfsi(),
            sel::FIXUNSSFSI => test_fixunssfsi(),
            // Unknown selector: fail loudly.
            _ => false,
        };

        if !ok {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use mollusk_svm::{result::Check, Mollusk};
    use solana_instruction::Instruction;

    use super::sel;

    fn run(selector: u8) {
        let program_id = [2u8; 32].into();
        let mollusk = Mollusk::new(
            &program_id,
            "target/bpfel-unknown-none/release/libprogram_test",
        );
        mollusk.process_and_validate_instruction(
            &Instruction {
                program_id,
                accounts: vec![],
                data: vec![selector],
            },
            &[],
            &[Check::success()],
        );
    }

    #[test]
    fn memcmp() {
        run(sel::MEMCMP);
    }

    #[test]
    fn memcpy() {
        run(sel::MEMCPY);
    }

    #[test]
    fn memmove() {
        run(sel::MEMMOVE);
    }

    #[test]
    fn memset() {
        run(sel::MEMSET);
    }

    #[test]
    fn multi3() {
        run(sel::MULTI3);
    }

    #[test]
    fn adddf3() {
        run(sel::ADDDF3);
    }

    #[test]
    fn muldf3() {
        run(sel::MULDF3);
    }

    #[test]
    fn subdf3() {
        run(sel::SUBDF3);
    }

    #[test]
    fn divdf3() {
        run(sel::DIVDF3);
    }

    #[test]
    fn negdf2() {
        run(sel::NEGDF2);
    }

    #[test]
    fn udivmodti3() {
        run(sel::UDIVMODTI3);
    }

    #[test]
    fn floatundidf() {
        run(sel::FLOATUNDIDF);
    }

    #[test]
    fn fixunsdfdi() {
        run(sel::FIXUNSDFDI);
    }

    #[test]
    fn gedf2() {
        run(sel::GEDF2);
    }

    #[test]
    fn gtdf2() {
        run(sel::GTDF2);
    }

    #[test]
    fn ltdf2() {
        run(sel::LTDF2);
    }

    #[test]
    fn ledf2() {
        run(sel::LEDF2);
    }

    #[test]
    fn eqdf2() {
        run(sel::EQDF2);
    }

    #[test]
    fn nedf2() {
        run(sel::NEDF2);
    }

    #[test]
    fn ltsf2() {
        run(sel::LTSF2);
    }

    #[test]
    fn gesf2() {
        run(sel::GESF2);
    }

    #[test]
    fn gtsf2() {
        run(sel::GTSF2);
    }

    #[test]
    fn lesf2() {
        run(sel::LESF2);
    }

    #[test]
    fn eqsf2() {
        run(sel::EQSF2);
    }

    #[test]
    fn nesf2() {
        run(sel::NESF2);
    }

    #[test]
    fn unordsf2() {
        run(sel::UNORDSF2);
    }

    #[test]
    fn floatsidf() {
        run(sel::FLOATSIDF);
    }

    #[test]
    fn floatunsidf() {
        run(sel::FLOATUNSIDF);
    }

    #[test]
    fn floatdidf() {
        run(sel::FLOATDIDF);
    }

    #[test]
    fn fixdfdi() {
        run(sel::FIXDFDI);
    }

    #[test]
    fn unorddf2() {
        run(sel::UNORDDF2);
    }

    #[test]
    fn addsf3() {
        run(sel::ADDSF3);
    }

    #[test]
    fn subsf3() {
        run(sel::SUBSF3);
    }

    #[test]
    fn mulsf3() {
        run(sel::MULSF3);
    }

    #[test]
    fn divsf3() {
        run(sel::DIVSF3);
    }

    #[test]
    fn floatunsisf() {
        run(sel::FLOATUNSISF);
    }

    #[test]
    fn floatsisf() {
        run(sel::FLOATSISF);
    }

    #[test]
    fn floatdisf() {
        run(sel::FLOATDISF);
    }

    #[test]
    fn floatundisf() {
        run(sel::FLOATUNDISF);
    }

    #[test]
    fn fixsfdi() {
        run(sel::FIXSFDI);
    }

    #[test]
    fn fixunssfdi() {
        run(sel::FIXUNSSFDI);
    }

    #[test]
    fn fixdfsi() {
        run(sel::FIXDFSI);
    }

    #[test]
    fn fixunsdfsi() {
        run(sel::FIXUNSDFSI);
    }

    #[test]
    fn fixsfsi() {
        run(sel::FIXSFSI);
    }

    #[test]
    fn fixunssfsi() {
        run(sel::FIXUNSSFSI);
    }
}
