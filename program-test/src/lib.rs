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
    a + b
}

#[cfg(target_arch = "bpf")]
fn mul_f64(a: f64, b: f64) -> f64 {
    let mut a = a;
    let mut b = b;
    core::hint::black_box(&mut a);
    core::hint::black_box(&mut b);
    a * b
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
