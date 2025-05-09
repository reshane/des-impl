const PC_1_C_TABLE: [usize; 28] = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36];
const PC_1_D_TABLE: [usize; 28] = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];

const PC_2_TABLE: [usize; 48] = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32, ];

enum Shift {
    One,
    Two,
}

const SHIFTS: [Shift; 16] = [Shift::One, Shift::One, Shift::Two, Shift::Two, Shift::Two, Shift::Two, Shift::Two, Shift::Two, Shift::One, Shift::Two, Shift::Two, Shift::Two, Shift::Two, Shift::Two, Shift::Two, Shift::One];

/// Rotate the lowest 28 bits to the left by one
#[inline]
fn left_shift_1(in_block: u64) -> u64 {
    let mut out_block = (in_block << 1) & 0xFFFFFFF;
    out_block |= (in_block & (0b1_u64 << 27)) >> 27;
    out_block
}

/// Rotate the lowest 28 bits to the left by two
#[inline]
fn left_shift_2(in_block: u64) -> u64 {
    let mut out_block = (in_block << 2) & 0xFFFFFFF;
    out_block |= (in_block & (0b11_u64 << 26)) >> 26;
    out_block
}

// Permute choice 1
// Generates C and D blocks into the lower 28 bits of the two returned variables
// returns (C, D)
fn permuted_choice_1(in_block: u64) -> (u64, u64) {
    let (mut c_block, mut d_block) = (0_u64, 0_u64);
    for (i, x) in PC_1_C_TABLE.iter().enumerate() {
        let mask = 1_u64 << (x - 1);
        if in_block & mask != 0 {
            c_block |= 1_u64 << i;
        }
    }
    for (i, x) in PC_1_D_TABLE.iter().enumerate() {
        let mask = 1_u64 << (x - 1);
        if in_block & mask != 0 {
            d_block |= 1_u64 << i;
        }
    }
    (c_block, d_block)
}

/// Permute choice 2
/// Generates the key returned in the lower 48 bits of returned value
fn permuted_choice_2(c_block: u64, d_block: u64) -> u64 {
    let in_block = (c_block << 28) | d_block;
    let mut out_block = 0_u64;
    for (i, x) in PC_2_TABLE.iter().enumerate() {
        let mask = 1_u64 << (x - 1);
        if in_block & mask != 0 {
            out_block |= 1_u64 << i;
        }
    }
    out_block
}


/// KeyGenerator struct used to generate round keys from a secret key
pub(crate) struct KeyGenerator {
    c_block: u64,
    d_block: u64,
    round: usize,
}

impl KeyGenerator {
    pub fn new(key: u64) -> Self {
        let (c_block, d_block) = permuted_choice_1(key);
        Self { c_block, d_block, round: 0, }
    }
}

impl Iterator for KeyGenerator {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.round > 15 {
            return None;
        }
        match SHIFTS[self.round] {
            Shift::One => {
                self.c_block = left_shift_1(self.c_block);
                self.d_block = left_shift_1(self.d_block);
            }
            Shift::Two => {
                self.c_block = left_shift_2(self.c_block);
                self.d_block = left_shift_2(self.d_block);
            }
        }
        self.round += 1;
        Some(permuted_choice_2(self.c_block, self.d_block))
    }
}

#[cfg(test)]
mod key_gen_tests {
    use super::*;

    #[test]
    fn test_left_shift_2() {
        let mut result = 3_u64;
        println!("{:028b}", result);
        for _ in 0..14 {
            result = left_shift_2(result);
            println!("{:028b}", result);
        }
        assert!(result == 3_u64);
    }

    #[test]
    fn test_left_shift_1() {
        let mut result = 3_u64;
        println!("{:028b}", result);
        for _ in 0..28 {
            result = left_shift_1(result);
            println!("{:028b}", result);
        }
        assert!(result == 3_u64);
    }

    #[test]
    fn test_perm_choice_1() {
        // set parity bits in the key and ensure both c & d blocks are 0
        // 0b1000_0000 -> 0x80
        let key = 0x8080808080808080;
        let (c_block, d_block) = permuted_choice_1(key);
        println!("{:028b}", c_block);
        println!("{:028b}", d_block);
        assert!(c_block == 0);
        assert!(d_block == 0);
    }
}
