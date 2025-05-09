mod permute;
mod key_gen;
mod s_tables;

use key_gen::KeyGenerator;
use s_tables::{S_TABLE, S_BIT_MASK};

const E_BIT_TABLE: [usize; 48] = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];

/// E Generates the 48 bits from 32 bit rhs
fn e_bit_selection(in_block: u64) -> u64 {
    let mut out_block = 0_u64;
    for (i, x) in E_BIT_TABLE.iter().enumerate() {
        let mask = 1_u64 << (x - 1);
        if in_block & mask != 0 {
            out_block |= 1_u64 << i;
        }
    }
    out_block
}

const P_TABLE: [usize; 32] = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];

const RIGHT_MASK: u64 = 0x00000000FFFFFFFF;
const LEFT_MASK:  u64 = 0xFFFFFFFF00000000;

/// Feistel round function
/// Runs E bit selection on rhs
/// Xor result with key
/// Run result through S Table & permute the result with P
fn round_fn(rhs: u64, key: u64) -> u64 {
    // create 48 bits from 32 bit rhs
    let e = e_bit_selection(rhs);
    let k_x_er = e ^ key;

    let mut out_bits = 0_u64;
    for i in 0..8 {
        let in_bits = (k_x_er & S_BIT_MASK << i * 6) >> i * 6;
        // first & last bits concatenated
        let x = (((in_bits & 0b100000) >> 4) + (in_bits & 0b1)) as usize;
        // middle four bits
        let y = (in_bits & 0b011110 >> 1) as usize;
        out_bits |= S_TABLE[i][x][y] << i * 4;
    }
    let mut out_block = 0_u64;
    for (i, x) in P_TABLE.iter().enumerate() {
        let mask = 1_u64 << (x - 1);
        if out_bits & mask != 0 {
            out_block |= 1_u64 << i;
        }
    }
    out_block
}

/// Denoted enciphering or deciphering
/// Used to determine the key ordering to use
enum FeistelMode {
    Encipher,
    Decipher,
}

fn feistel(in_data: u64, key_gen: &mut KeyGenerator, mode: FeistelMode) -> u64 {
    let permuted_input = permute::initial_permutation(in_data);

    let (mut lhs, mut rhs) = ((permuted_input & LEFT_MASK) >> 32, permuted_input & RIGHT_MASK);

    let keys = key_gen.collect::<Vec<u64>>();

    let key_idx_fn = match mode {
        FeistelMode::Encipher => {
            |i: usize| { i }
        },
        FeistelMode::Decipher => {
            |i: usize| { 15 - i }
        },
    };

    for i in 0..16 {
        let fkr = round_fn(rhs, keys[key_idx_fn(i)]);

        let r_1 = lhs ^ fkr;
        let l_1 = rhs;

        rhs = r_1;
        lhs = l_1;
    }
    let out = (rhs << 32) | lhs;

    permute::final_permutation(out)
}

/// Encipher the 64 bit plain_block with the 64 bit secret
pub fn encipher(plain_block: u64, secret: u64) -> u64 {
    let mut key_gen = KeyGenerator::new(secret);
    feistel(plain_block, &mut key_gen, FeistelMode::Encipher)
}

/// Decipher the 64 bit cipher_block with the 64 bit secret
pub fn decipher(cipher_block: u64, secret: u64) -> u64 {
    let mut key_gen = KeyGenerator::new(secret);
    feistel(cipher_block, &mut key_gen, FeistelMode::Decipher)
}

#[cfg(test)]
mod core_tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let secret_key = 0xFAF0F2FAFD84B5F4;
        let plain_text = 0xDCA30AF7FDB9F152;
        let cipher_text = encipher(plain_text, secret_key);
        let deciphered_text = decipher(cipher_text, secret_key);
        assert_eq!(plain_text, deciphered_text);
    }

    #[test]
    fn test_feistel() {
        let secret_key = 0xFAF0F2FAFDB9F152;
        let mut key_gen = key_gen::KeyGenerator::new(secret_key);
        let plain_text = 0xFAF0F2FAFDB9F152;
        println!("--------------------------");
        println!("plain_text: {:016x}", plain_text);
        println!("--------------------------");
        let cipher_text = feistel(plain_text, &mut key_gen, FeistelMode::Encipher);
        println!("--------------------------");
        println!("cipher_text: {:016x}", cipher_text);
        println!("--------------------------");
        let mut key_gen = key_gen::KeyGenerator::new(secret_key);
        let deciphered = feistel(cipher_text, &mut key_gen, FeistelMode::Decipher);
        println!("--------------------------");
        println!("deciphered: {:016x}", deciphered);
        println!("--------------------------");
        assert!(plain_text == deciphered);
    }
}
