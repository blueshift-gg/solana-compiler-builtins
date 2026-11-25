#![cfg_attr(target_arch = "bpf", no_std)]
use solana_compiler_builtins as _;

mod mem_bench;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(target_arch = "bpf")]
fn multiply_matches(mut a: i128, mut b: i128, expected: i128) -> bool {
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    a.wrapping_mul(b) == expected
}

#[cfg(target_arch = "bpf")]
fn test_multi3() -> bool {
    multiply_matches(
        0x1111_2222_3333_4444,
        3,
        0x3333_6666_9999_CCCCi128,
    ) && multiply_matches(1i128 << 100, 3, 3i128 << 100)
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
        && udivmod_matches(0x10_0000_0000_0000_0000_0000_3039, 0x3E8, 0x418_9374_BC6A_7EF9_DB22_D0F1, 0x2D1)
        && udivmod_matches(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF, 0x1_0000_0001_0000_0001_0000_0001, 0x0)
        && udivmod_matches(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0xDE0_B6B3_A764_0000, 0x12_725D_D1D2_43AB_A0E7, 0x532_DF79_74C3_FFFF)
        && udivmod_matches(0x8000_0000_0000_0001_0000_0000_0000_0005, 0x1_0000_0000_0000_0001, 0x8000_0000_0000_0000, 0x8000_0000_0000_0005)
        && udivmod_matches(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0x1, 0x0)
        && udivmod_matches(0x1_0000_0000_0000_0000_0000, 0x10_0000_0000_0000_0000_0000_0000, 0x0, 0x1_0000_0000_0000_0000_0000)
        && udivmod_matches(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0x1, 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0x0)
        && udivmod_matches(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0x1_0000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF)
        && udivmod_matches(0x1_8EE9_0FF6_C373_E0EE_4E3F_0AD2, 0xDB4_DA5F_49F8_B478, 0x1D_1A94_9D8C, 0xCD9_8CBF_CE2E_C132)
        && udivmod_matches(0x8000_0000_0000_0000_0000_0001, 0x8000_0000_0000_0000_0000_0000, 0x1, 0x1)
        && udivmod_matches(0x8000_0000_0000_0000_0000_0000, 0x8000_0000_0000_0000_0000_0000, 0x1, 0x0)
        && udivmod_matches(0x1234_5678_9ABC_DEF0_1122_3344_5566_7788, 0x1234_5678_9ABC_DEF0_1122_3344_5566_7787, 0x1, 0x1)
        && udivmod_matches(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE, 0x1, 0x1)
        && udivmod_matches(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0000_0000_0000_0000_0000, 0x1, 0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF)
        && udivmod_matches(0xAC85_A081_0625_55D6_7C6A_A3A6_40C7, 0xAC85_A081_9378_6CCC_DB21, 0xFFFF_FFFF, 0x1F32_898B_34C2_1073_1BE8)
        && udivmod_matches(0x33B_2E3C_A30B_AE79_87D0_803C_E7FF_FFFF, 0x33B_2E3C_9FD0_803C_E800_0000, 0x1_0000_0000, 0x33B_2E3C_9FD0_803C_E7FF_FFFF)
        && udivmod_matches(0x20_0000_0000_0000_0000_0000_6079, 0x10_0000_0000_0000_0000_0000_3039, 0x2, 0x7)
        && udivmod_matches(0x2468_ACF1_0000_0000_0000_0000, 0x1234_5678_FFFF_FFFF_FFFF_FFFF, 0x1, 0x1234_5678_0000_0000_0000_0001)
        && udivmod_matches(0x2468_ACF1_FFFF_FFFF_FFFF_FFFF, 0x1234_5678_FFFF_FFFF_FFFF_FFFF, 0x2, 0x1)
        && udivmod_matches(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0000_0000_0001, 0x1_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFE_0000_0000)
        && udivmod_matches(0xFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, 0x80_0000_0000_0000_0000_0003, 0x1_FFFF_FFFF, 0x7F_FFFF_FFFF_FFFA_0000_0002)
        && udivmod_matches(0x100_0000_0000_0000_0000_0000_0000_0000, 0x80_0000_0000_0000_0000_0003, 0x1_FFFF_FFFF, 0x7F_FFFF_FFFF_FFFA_0000_0003)
        && udivmod_matches(0x100_0000_0000_0000_0000_0000_0000_0000, 0x80_0000_0000_0000_0000_0000, 0x2_0000_0000, 0x0)
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
        && sub_f64(f64::MIN_POSITIVE, f64::from_bits(1)).to_bits()
            == 0x000F_FFFF_FFFF_FFFF
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
        && div_f64(1.0, f64::from_bits(0x3FF0_0000_0000_0001)).to_bits()
            == 0x3FEF_FFFF_FFFF_FFFE
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
        && neg_f64(f64::from_bits(0x7FF8_0000_0000_0001)).to_bits()
            == 0xFFF8_0000_0000_0001
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

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Selector {
    Multi3,
    AddDf3,
    MulDf3,
    FloatUnDiDf,
    FixUnsDfDi,
    GeDf2,
    GtDf2,
    SubDf3,
    DivDf3,
    NegDf2,
    UDivModTi3,
    MemBench,
}

impl Selector {
    #[cfg(target_arch = "bpf")]
    fn from_u8(value: u8) -> Option<Self> {
        [
            Self::Multi3,
            Self::AddDf3,
            Self::MulDf3,
            Self::FloatUnDiDf,
            Self::FixUnsDfDi,
            Self::GeDf2,
            Self::GtDf2,
            Self::SubDf3,
            Self::DivDf3,
            Self::NegDf2,
            Self::UDivModTi3,
            Self::MemBench,
        ]
        .get(value as usize)
        .copied()
    }
}

#[unsafe(no_mangle)]
pub fn entrypoint(_input: *mut u8) -> u64 {
    #[cfg(target_arch = "bpf")]
    {
        let Some(selector) = Selector::from_u8(unsafe { *_input.add(16) }) else {
            return 1;
        };

        let ok = match selector {
            Selector::Multi3 => test_multi3(),
            Selector::AddDf3 => test_adddf3() && test_adddf3_ieee(),
            Selector::MulDf3 => test_muldf3() && test_muldf3_ieee(),
            Selector::SubDf3 => test_subdf3(),
            Selector::DivDf3 => test_divdf3(),
            Selector::NegDf2 => test_negdf2(),
            Selector::UDivModTi3 => test_udivmodti3(),
            Selector::FloatUnDiDf => test_floatundidf(),
            Selector::FixUnsDfDi => test_fixunsdfdi(),
            Selector::GeDf2 => test_gedf2(),
            Selector::GtDf2 => test_gtdf2(),
            Selector::MemBench => unsafe { mem_bench::run(_input) },
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

    use super::Selector;

    fn run(selector: Selector) {
        let program_id = [2u8; 32].into();
        Mollusk::new(
            &program_id,
            "target/bpfel-unknown-none/release/libprogram_test",
        )
        .process_and_validate_instruction(
            &Instruction {
                program_id,
                accounts: vec![],
                data: vec![selector as u8],
            },
            &[],
            &[Check::success()],
        );
    }

    #[test]
    fn multi3() {
        run(Selector::Multi3);
    }

    #[test]
    fn adddf3() {
        run(Selector::AddDf3);
    }

    #[test]
    fn muldf3() {
        run(Selector::MulDf3);
    }

    #[test]
    fn subdf3() {
        run(Selector::SubDf3);
    }

    #[test]
    fn divdf3() {
        run(Selector::DivDf3);
    }

    #[test]
    fn negdf2() {
        run(Selector::NegDf2);
    }

    #[test]
    fn udivmodti3() {
        run(Selector::UDivModTi3);
    }

    #[test]
    fn floatundidf() {
        run(Selector::FloatUnDiDf);
    }

    #[test]
    fn fixunsdfdi() {
        run(Selector::FixUnsDfDi);
    }

    #[test]
    fn gedf2() {
        run(Selector::GeDf2);
    }

    #[test]
    fn gtdf2() {
        run(Selector::GtDf2);
    }
}
