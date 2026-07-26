#[cfg(target_arch = "bpf")]
#[inline]
fn widen_mul_u64(a: u64, b: u64) -> (u64, u64) {
    let a_lo = a & 0xFFFF_FFFF;
    let a_hi = a >> 32;
    let b_lo = b & 0xFFFF_FFFF;
    let b_hi = b >> 32;

    let t0 = a_lo * b_lo;
    let lo0 = t0 & 0xFFFF_FFFF;
    let carry = t0 >> 32;

    let t1 = a_hi * b_lo + carry;
    let mid0 = t1 & 0xFFFF_FFFF;
    let carry1 = t1 >> 32;

    let t2 = a_lo * b_hi + mid0;
    let lo1 = t2 & 0xFFFF_FFFF;
    let carry2 = t2 >> 32;

    let hi = a_hi * b_hi + carry1 + carry2;
    let lo = lo0 | (lo1 << 32);
    (lo, hi)
}

#[cfg(target_arch = "bpf")]
#[inline]
fn normalize_f64(significand: u64) -> (i32, u64) {
    let implicit_bit: u64 = 1u64 << 52;
    let shift = significand
        .leading_zeros()
        .wrapping_sub(implicit_bit.leading_zeros());
    (1i32.wrapping_sub(shift as i32), significand << shift)
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
pub extern "C" fn __adddf3(a: f64, b: f64) -> f64 {
    let one: u64 = 1;
    let zero: u64 = 0;
    let bits: u64 = 64;
    let significand_bits: u32 = 52;
    let max_exponent: u64 = 0x7ff;

    let implicit_bit: u64 = 1u64 << 52;
    let significand_mask: u64 = implicit_bit - 1;
    let sign_bit: u64 = 1u64 << 63;
    let abs_mask: u64 = sign_bit - one;
    let exponent_mask: u64 = max_exponent << significand_bits;
    let inf_rep: u64 = exponent_mask;
    let quiet_bit: u64 = implicit_bit >> 1;
    let qnan_rep: u64 = exponent_mask | quiet_bit;

    let mut a_rep = a.to_bits();
    let mut b_rep = b.to_bits();
    let a_abs = a_rep & abs_mask;
    let b_abs = b_rep & abs_mask;

    if a_abs.wrapping_sub(one) >= inf_rep - one || b_abs.wrapping_sub(one) >= inf_rep - one {
        if a_abs > inf_rep {
            return f64::from_bits(a_abs | quiet_bit);
        }
        if b_abs > inf_rep {
            return f64::from_bits(b_abs | quiet_bit);
        }
        if a_abs == inf_rep {
            if (a.to_bits() ^ b.to_bits()) == sign_bit {
                return f64::from_bits(qnan_rep);
            } else {
                return a;
            }
        }
        if b_abs == inf_rep {
            return b;
        }
        if a_abs == zero {
            if b_abs == zero {
                return f64::from_bits(a.to_bits() & b.to_bits());
            } else {
                return b;
            }
        }
        if b_abs == zero {
            return a;
        }
    }

    if b_abs > a_abs {
        let tmp = a_rep;
        a_rep = b_rep;
        b_rep = tmp;
    }

    let mut a_exponent: i32 = ((a_rep & exponent_mask) >> significand_bits) as i32;
    let mut b_exponent: i32 = ((b_rep & exponent_mask) >> significand_bits) as i32;
    let mut a_significand = a_rep & significand_mask;
    let mut b_significand = b_rep & significand_mask;

    if a_exponent == 0 {
        let (e, s) = normalize_f64(a_significand);
        a_exponent = e;
        a_significand = s;
    }
    if b_exponent == 0 {
        let (e, s) = normalize_f64(b_significand);
        b_exponent = e;
        b_significand = s;
    }

    let result_sign = a_rep & sign_bit;
    let subtraction = ((a_rep ^ b_rep) & sign_bit) != zero;

    a_significand = (a_significand | implicit_bit) << 3;
    b_significand = (b_significand | implicit_bit) << 3;

    let align: u64 = a_exponent.wrapping_sub(b_exponent) as u64;
    if align != 0 {
        if align < bits {
            let sticky = ((b_significand << (bits - align) as u32) != 0) as u64;
            b_significand = (b_significand >> align as u32) | sticky;
        } else {
            b_significand = one;
        }
    }
    if subtraction {
        a_significand = a_significand.wrapping_sub(b_significand);
        if a_significand == 0 {
            return f64::from_bits(0);
        }
        if a_significand < implicit_bit << 3 {
            let shift =
                a_significand.leading_zeros() as i32 - (implicit_bit << 3).leading_zeros() as i32;
            a_significand <<= shift;
            a_exponent -= shift;
        }
    } else {
        a_significand += b_significand;
        if a_significand & (implicit_bit << 4) != 0 {
            let sticky = (a_significand & one != 0) as u64;
            a_significand = (a_significand >> 1) | sticky;
            a_exponent += 1;
        }
    }

    if a_exponent >= max_exponent as i32 {
        return f64::from_bits(inf_rep | result_sign);
    }

    if a_exponent <= 0 {
        let shift = (1 - a_exponent) as u64;
        let sticky = ((a_significand << (bits - shift) as u32) != 0) as u64;
        a_significand = (a_significand >> shift as u32) | sticky;
        a_exponent = 0;
    }

    let round_guard_sticky: u64 = a_significand & 0x7;
    let mut result = (a_significand >> 3) & significand_mask;
    result |= (a_exponent as u64) << significand_bits;
    result |= result_sign;

    if round_guard_sticky > 0x4 {
        result += one;
    }
    if round_guard_sticky == 0x4 {
        result += result & one;
    }

    f64::from_bits(result)
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
pub extern "C" fn __muldf3(a: f64, b: f64) -> f64 {
    let one: u64 = 1;
    let zero: u64 = 0;
    let bits: u32 = 64;
    let significand_bits: u32 = 52;
    let max_exponent: u64 = 0x7ff;
    let exponent_bias: u64 = 1023;

    let implicit_bit: u64 = 1u64 << 52;
    let significand_mask: u64 = implicit_bit - 1;
    let sign_bit: u64 = 1u64 << 63;
    let abs_mask: u64 = sign_bit - one;
    let exponent_mask: u64 = max_exponent << significand_bits;
    let inf_rep: u64 = exponent_mask;
    let quiet_bit: u64 = implicit_bit >> 1;
    let qnan_rep: u64 = exponent_mask | quiet_bit;
    let exponent_bits: u32 = 11;

    let a_rep = a.to_bits();
    let b_rep = b.to_bits();

    let a_exponent = (a_rep >> significand_bits) & max_exponent;
    let b_exponent = (b_rep >> significand_bits) & max_exponent;
    let product_sign = (a_rep ^ b_rep) & sign_bit;

    let mut a_significand = a_rep & significand_mask;
    let mut b_significand = b_rep & significand_mask;
    let mut scale: i32 = 0;

    if a_exponent.wrapping_sub(one) >= max_exponent - 1
        || b_exponent.wrapping_sub(one) >= max_exponent - 1
    {
        let a_abs = a_rep & abs_mask;
        let b_abs = b_rep & abs_mask;

        if a_abs > inf_rep {
            return f64::from_bits(a_rep | quiet_bit);
        }
        if b_abs > inf_rep {
            return f64::from_bits(b_rep | quiet_bit);
        }
        if a_abs == inf_rep {
            if b_abs != zero {
                return f64::from_bits(a_abs | product_sign);
            } else {
                return f64::from_bits(qnan_rep);
            }
        }
        if b_abs == inf_rep {
            if a_abs != zero {
                return f64::from_bits(b_abs | product_sign);
            } else {
                return f64::from_bits(qnan_rep);
            }
        }
        if a_abs == zero {
            return f64::from_bits(product_sign);
        }
        if b_abs == zero {
            return f64::from_bits(product_sign);
        }
        if a_abs < implicit_bit {
            let (e, s) = normalize_f64(a_significand);
            scale += e;
            a_significand = s;
        }
        if b_abs < implicit_bit {
            let (e, s) = normalize_f64(b_significand);
            scale += e;
            b_significand = s;
        }
    }

    a_significand |= implicit_bit;
    b_significand |= implicit_bit;

    let (mut product_low, mut product_high) =
        widen_mul_u64(a_significand, b_significand << exponent_bits);

    let a_exponent_i32 = a_exponent as i32;
    let b_exponent_i32 = b_exponent as i32;
    let mut product_exponent: i32 = a_exponent_i32
        .wrapping_add(b_exponent_i32)
        .wrapping_add(scale)
        .wrapping_sub(exponent_bias as i32);

    if (product_high & implicit_bit) != zero {
        product_exponent = product_exponent.wrapping_add(1);
    } else {
        product_high = (product_high << 1) | (product_low >> (bits - 1));
        product_low <<= 1;
    }

    if product_exponent >= max_exponent as i32 {
        return f64::from_bits(inf_rep | product_sign);
    }

    if product_exponent <= 0 {
        let shift = (1 - product_exponent) as u32;
        if shift >= bits {
            return f64::from_bits(product_sign);
        }
        let sticky = (product_low << (bits - shift)) != 0;
        product_low = (product_high << (bits - shift)) | (product_low >> shift) | (sticky as u64);
        product_high >>= shift;
    } else {
        product_high &= significand_mask;
        product_high |= (product_exponent as u64) << significand_bits;
    }

    product_high |= product_sign;

    if product_low > sign_bit {
        product_high += one;
    }
    if product_low == sign_bit {
        product_high += product_high & one;
    }

    f64::from_bits(product_high)
}
