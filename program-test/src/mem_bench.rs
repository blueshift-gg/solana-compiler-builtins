#[cfg(any(target_arch = "bpf", test))]
mod cases {
    pub const NOOP: u8 = 0;
    pub const DYNAMIC_MEMCPY: u8 = 1;
    pub const DYNAMIC_MEMMOVE_FORWARD: u8 = 2;
    pub const DYNAMIC_MEMMOVE_BACKWARD: u8 = 3;
    pub const DYNAMIC_MEMSET: u8 = 4;
    pub const DYNAMIC_MEMCMP: u8 = 5;
    pub const FIXED_MEMCPY: u8 = 6;
    pub const FIXED_MEMMOVE_FORWARD: u8 = 7;
    pub const FIXED_MEMMOVE_BACKWARD: u8 = 8;
    pub const FIXED_MEMSET: u8 = 9;
    pub const FIXED_MEMCMP: u8 = 10;
    pub const CORRECTNESS: u8 = 11;

    #[cfg(test)]
    pub const DYNAMIC_CASES: [u8; 5] = [
        DYNAMIC_MEMCPY,
        DYNAMIC_MEMMOVE_FORWARD,
        DYNAMIC_MEMMOVE_BACKWARD,
        DYNAMIC_MEMSET,
        DYNAMIC_MEMCMP,
    ];
    #[cfg(test)]
    pub const FIXED_CASES: [u8; 5] = [
        FIXED_MEMCPY,
        FIXED_MEMMOVE_FORWARD,
        FIXED_MEMMOVE_BACKWARD,
        FIXED_MEMSET,
        FIXED_MEMCMP,
    ];
    pub const FIXED_LENGTHS: [u8; 20] = [
        0, 1, 2, 3, 7, 8, 9, 31, 32, 33, 39, 40, 41, 47, 48, 79, 80, 81, 127, 128,
    ];
}

#[cfg(any(target_arch = "bpf", test))]
pub use cases::*;

#[cfg(target_arch = "bpf")]
mod target {
    use core::{hint::black_box, mem::MaybeUninit, ptr, slice};
    use solana_compiler_builtins::{memcmp, memcpy, memmove, memset};

    use super::*;

    const INLINE_MEMCMP_THRESHOLD: usize = 32;
    const INLINE_MEMCPY_THRESHOLD: usize = 2;
    const INLINE_MEMMOVE_FORWARD_THRESHOLD: usize = 2;
    const INLINE_MEMMOVE_BACKWARD_THRESHOLD: usize = 1;
    const INLINE_MEMSET_THRESHOLD: usize = 2;

    type Case = unsafe fn(*mut u8, *const u8, *mut u8, usize);

    #[inline(never)]
    unsafe fn fixed_memcpy<const N: usize>(a: *mut u8, _: *const u8, dst: *mut u8, _: usize) {
        unsafe { ptr::copy_nonoverlapping(a, dst, N) }
    }

    #[inline(never)]
    unsafe fn fixed_memmove_forward<const N: usize>(
        a: *mut u8,
        _: *const u8,
        dst: *mut u8,
        _: usize,
    ) {
        unsafe { ptr::copy(a, dst, N) }
    }

    #[inline(never)]
    unsafe fn fixed_memmove_backward<const N: usize>(
        a: *mut u8,
        _: *const u8,
        _: *mut u8,
        _: usize,
    ) {
        unsafe { ptr::copy(a, a.add(1), N) }
    }

    #[inline(never)]
    unsafe fn fixed_memset<const N: usize>(_: *mut u8, _: *const u8, dst: *mut u8, _: usize) {
        unsafe { ptr::write_bytes(dst, 0, N) }
    }

    #[inline(never)]
    unsafe fn fixed_memcmp<const N: usize>(a: *mut u8, b: *const u8, dst: *mut u8, _: usize) {
        let order = unsafe { slice::from_raw_parts(a, N).cmp(slice::from_raw_parts(b, N)) };
        unsafe { *dst = order as u8 }
    }

    macro_rules! fixed_case {
        ($index:expr, $function:ident) => {
            match $index {
                0 => Some($function::<0> as Case),
                1 => Some($function::<1> as Case),
                2 => Some($function::<2> as Case),
                3 => Some($function::<3> as Case),
                4 => Some($function::<7> as Case),
                5 => Some($function::<8> as Case),
                6 => Some($function::<9> as Case),
                7 => Some($function::<31> as Case),
                8 => Some($function::<32> as Case),
                9 => Some($function::<33> as Case),
                10 => Some($function::<39> as Case),
                11 => Some($function::<40> as Case),
                12 => Some($function::<41> as Case),
                13 => Some($function::<47> as Case),
                14 => Some($function::<48> as Case),
                15 => Some($function::<79> as Case),
                16 => Some($function::<80> as Case),
                17 => Some($function::<81> as Case),
                18 => Some($function::<127> as Case),
                19 => Some($function::<128> as Case),
                _ => None,
            }
        };
    }

    pub unsafe fn run(input: *mut u8) -> bool {
        let data = unsafe { input.add(16) };
        let case_id = unsafe { *data.add(1) };
        let argument = unsafe { *data.add(2) };
        if case_id == CORRECTNESS {
            let memcmp_eq = |n| {
                let a = [3u8; 100];
                let b = [3u8; 100];
                unsafe { memcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) == 0 }
            };
            let memcmp_ne = |n| {
                let a = [4u8; 100];
                let mut b = [4u8; 100];
                unsafe {
                    let last = ptr::read_volatile(b.as_ptr().add(n - 1));
                    ptr::write_volatile(b.as_mut_ptr().add(n - 1), last ^ 0xFF);
                    memcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) != 0
                }
            };
            let memcpy_ok = |n| {
                let src = [1u8; 100];
                let mut dst = [2u8; 100];
                unsafe { memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), n) };
                dst[..n] == src[..n]
            };
            let memmove_nonoverlap = |n| {
                let src = [1u8; 100];
                let mut dst = [2u8; 100];
                unsafe { memmove(dst.as_mut_ptr().cast(), src.as_ptr().cast(), n) };
                dst[..n] == src[..n]
            };
            let memmove_backward = |n| {
                let mut a = [5u8; 100];
                a[n] = 6;
                unsafe {
                    memmove(
                        a.as_mut_ptr().add(1).cast(),
                        a.as_ptr().cast(),
                        n,
                    )
                };
                a[1..1 + n] == [5u8; 100][..n]
            };
            let memmove_forward = |n| {
                let mut a = [5u8; 100];
                a[0] = 6;
                unsafe {
                    memmove(
                        a.as_mut_ptr().cast(),
                        a.as_ptr().add(1).cast(),
                        n,
                    )
                };
                a[..n] == [5u8; 100][..n]
            };
            let memset_ok = |n| {
                let mut a = [0xFFu8; 100];
                unsafe { memset(a.as_mut_ptr().cast(), 0xAB, n) };
                a[..n] == [0xABu8; 100][..n]
            };

            return memcmp_eq(INLINE_MEMCMP_THRESHOLD)
                && memcmp_eq(INLINE_MEMCMP_THRESHOLD + 1)
                && memcmp_ne(INLINE_MEMCMP_THRESHOLD)
                && memcmp_ne(INLINE_MEMCMP_THRESHOLD + 1)
                && memcpy_ok(INLINE_MEMCPY_THRESHOLD)
                && memcpy_ok(INLINE_MEMCPY_THRESHOLD + 1)
                && memmove_nonoverlap(INLINE_MEMMOVE_FORWARD_THRESHOLD)
                && memmove_nonoverlap(INLINE_MEMMOVE_FORWARD_THRESHOLD + 1)
                && memmove_backward(INLINE_MEMMOVE_BACKWARD_THRESHOLD)
                && memmove_backward(INLINE_MEMMOVE_BACKWARD_THRESHOLD + 1)
                && memmove_forward(INLINE_MEMMOVE_FORWARD_THRESHOLD)
                && memmove_forward(INLINE_MEMMOVE_FORWARD_THRESHOLD + 1)
                && memset_ok(INLINE_MEMSET_THRESHOLD)
                && memset_ok(INLINE_MEMSET_THRESHOLD + 1);
        }
        let case = match case_id {
            NOOP => Some((|_, _, _, _| {}) as Case),
            DYNAMIC_MEMCPY => Some((|a, _, dst, n| unsafe {
                ptr::copy_nonoverlapping(a, dst, n)
            }) as Case),
            DYNAMIC_MEMMOVE_FORWARD => {
                Some((|a, _, dst, n| unsafe { ptr::copy(a, dst, n) }) as Case)
            }
            DYNAMIC_MEMMOVE_BACKWARD => {
                Some((|a, _, _, n| unsafe { ptr::copy(a, a.add(1), n) }) as Case)
            }
            DYNAMIC_MEMSET => {
                Some((|_, _, dst, n| unsafe { ptr::write_bytes(dst, 0, n) }) as Case)
            }
            DYNAMIC_MEMCMP => Some((|a, b, dst, n| unsafe {
                *dst = slice::from_raw_parts(a, n).cmp(slice::from_raw_parts(b, n)) as u8;
            }) as Case),
            FIXED_MEMCPY => fixed_case!(argument, fixed_memcpy),
            FIXED_MEMMOVE_FORWARD => fixed_case!(argument, fixed_memmove_forward),
            FIXED_MEMMOVE_BACKWARD => fixed_case!(argument, fixed_memmove_backward),
            FIXED_MEMSET => fixed_case!(argument, fixed_memset),
            FIXED_MEMCMP => fixed_case!(argument, fixed_memcmp),
            _ => None,
        };
        let Some(case) = case else {
            return false;
        };
        let n = if (FIXED_MEMCPY..=FIXED_MEMCMP).contains(&case_id) {
            let Some(n) = FIXED_LENGTHS.get(argument as usize) else {
                return false;
            };
            *n as usize
        } else {
            argument as usize
        };
        if n > 128 {
            return false;
        }

        let mut dst = MaybeUninit::<[u8; 128]>::uninit();
        unsafe {
            black_box(case)(data.add(8), data.add(136), dst.as_mut_ptr().cast(), n);
        }
        true
    }
}

#[cfg(target_arch = "bpf")]
pub use target::run;

#[cfg(test)]
mod tests {
    use mollusk_svm::{result::Check, Mollusk};
    use solana_instruction::Instruction;

    use super::*;
    use crate::Selector;

    #[test]
    fn memory_operations() {
        // The last value in each dynamic row repeats through size 128.
        const DYNAMIC_EXPECTED: [&[u64]; 5] = [
            &[45, 48, 51, 56],
            &[47, 50, 53, 57],
            &[44, 48, 59, 54],
            &[44, 46, 48, 56],
            &[
                56, 66, 75, 84, 93, 102, 111, 120, 112, 122, 131, 140, 149, 158, 167, 176, 167, 177,
                186, 195, 204, 213, 222, 231, 222, 232, 241, 250, 259, 268, 277, 286, 277, 67,
            ],
        ];
        const FIXED_EXPECTED: [[u64; 20]; 5] = [
            [
                40, 45, 45, 48, 57, 57, 60, 103, 106, 109, 119, 122, 123, 136, 139, 199, 202, 203,
                296, 299,
            ],
            [
                41, 46, 46, 49, 58, 58, 61, 148, 153, 158, 180, 185, 188, 213, 218, 340, 345, 348,
                533, 538,
            ],
            [
                42, 47, 47, 50, 59, 59, 62, 149, 154, 159, 181, 186, 189, 214, 219, 341, 346, 349,
                534, 539,
            ],
            [
                40, 45, 44, 46, 51, 50, 52, 73, 75, 77, 81, 83, 83, 90, 92, 121, 123, 123, 170, 172,
            ],
            [
                43, 54, 60, 64, 94, 104, 100, 240, 241, 253, 289, 290, 300, 339, 340, 533, 535, 545,
                829, 830,
            ],
        ];

        let program_id = [2u8; 32].into();
        let mollusk = Mollusk::new(
            &program_id,
            "target/bpfel-unknown-none/release/libprogram_test",
        );
        let run = |case, argument| {
            let mut data = vec![5; 264];
            data[0] = Selector::MemBench as u8;
            data[1] = case;
            data[2] = argument;
            mollusk
                .process_and_validate_instruction(
                    &Instruction {
                        program_id,
                        accounts: vec![],
                        data,
                    },
                    &[],
                    &[Check::success()],
                )
                .compute_units_consumed
        };

        assert_eq!(run(CORRECTNESS, 0), 775);
        assert_eq!(run(NOOP, 0), 34);

        for (case, expected) in DYNAMIC_CASES.into_iter().zip(DYNAMIC_EXPECTED) {
            for argument in 0..=128 {
                let expected = expected[usize::from(argument).min(expected.len() - 1)];
                assert_eq!(
                    run(case, argument),
                    expected,
                    "dynamic memory case {case}, size {argument}"
                );
            }
        }

        for (case, expected) in FIXED_CASES.into_iter().zip(FIXED_EXPECTED) {
            for (index, (&size, expected)) in FIXED_LENGTHS.iter().zip(expected).enumerate() {
                assert_eq!(
                    run(case, index as u8),
                    expected,
                    "fixed memory case {case}, size {size}"
                );
            }
        }
    }

}
