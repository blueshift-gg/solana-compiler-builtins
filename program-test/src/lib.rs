#![cfg_attr(target_arch = "bpf", no_std)]

#[cfg(target_arch = "bpf")]
const INLINE_MEMCMP_THRESHOLD: usize = 32;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(target_arch = "bpf")]
unsafe extern "C" {
    fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32;
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
    unsafe { memcmp(a.as_ptr(), b.as_ptr(), n) == 0 }
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

    unsafe { memcmp(a.as_ptr(), b.as_ptr(), n) != 0 }
}

#[unsafe(no_mangle)]
pub fn entrypoint(_input: *mut u8) -> u64 {
    #[cfg(target_arch = "bpf")]
    {
        // memcmp tests

        if !unsafe { test_memcmp_eq(INLINE_MEMCMP_THRESHOLD) } {
            return 1;
        }
        if !unsafe { test_memcmp_ne(INLINE_MEMCMP_THRESHOLD) } {
            return 2;
        }
        // these will take the syscall path (greater than threshold)
        if !unsafe { test_memcmp_eq(INLINE_MEMCMP_THRESHOLD + 1) } {
            return 3;
        }
        if !unsafe { test_memcmp_ne(INLINE_MEMCMP_THRESHOLD + 1) } {
            return 4;
        }

        // TODO: other builtins tests..
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
