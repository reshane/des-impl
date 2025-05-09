use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    input: String,

    #[arg(short, long)]
    secret: String,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt,
    Decrypt,
}

fn string_to_blocks(plain_text: &String) -> Vec<u64> {
    let mut bytes: Vec<u8> = plain_text.bytes().collect();
    let pad = 8 - bytes.len() % 8;
    for _ in 0..pad {
        bytes.push(pad as u8);
    }
    let mut blocks = Vec::with_capacity(bytes.len());
    bytes.chunks(8).for_each(|chunk| {
        let mut block = 0_u64;
        for i in 0..chunk.len() {
            // chunk [[0],[1],[2],[3],[4],[5],[6],[7]]
            // block bits [63..63-8,63-8..63-16...]
            block |= (chunk[i] as u64) << (7 - i) * 8;
        }
        blocks.push(block);
    });
    blocks
}

fn blocks_to_bytes(blocks: &Vec<u64>) -> Vec<u8> {
    blocks.iter().map(|b| {
        let mut bytes = vec![];
        for i in 0..8 {
            let byte = ((b & (0xFF << (8 * (7-i)))) >> (8 * (7-i))) as u8;
            bytes.push(byte);
        }
        bytes.into_iter()
    }).flatten().collect::<Vec<u8>>()
}

fn unpad(blocks: &mut Vec<u8>) {
    let pad = blocks[blocks.len()-1];
    if pad < 8 {
        let (mut n, mut idx) = (0, blocks.len()-1);
        let mut valid = true;
        loop {
            if blocks[idx] != pad {
                valid = false;
                break;
            }
            if idx == pad as usize {
                break;
            }
            idx -= 1;
            n += 1;
        }
        if n == pad && valid {
            let _ = blocks.split_off(idx);
        }
    }
}

fn main() {
    let args = Args::parse();
    println!("{}", args.input);
    let blocks = string_to_blocks(&args.input);
    println!("---------------");
    for block in &blocks {
        println!("{:016x}", block);
    }
    println!("---------------");
    let secret = 0xb4b568ab61e07150;
    let cipher_text: Vec<u64> = blocks.iter().map(|b| {
        core::encipher(*b, secret)
    }).collect();
    println!("---------------");
    for block in &cipher_text {
        println!("{:016x}", block);
    }
    println!("---------------");
    let deciphered: Vec<u64> = cipher_text.iter().map(|b| {
        core::decipher(*b, secret)
    }).collect();
    println!("---------------");
    for block in &deciphered {
        println!("{:016x}", block);
    }
    println!("---------------");
    let mut bytes = blocks_to_bytes(&deciphered);
    unpad(&mut bytes);
    println!("{}", String::from_utf8(bytes).unwrap());
}

