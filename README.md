# DES implementation (kind of)

Does not encipher things properly (work in progress).
Does encipher and decipher things in its own special little way.

## About

Decided to try implementing the DES algorithm because I did a lot of reading about fiestel networks & wanted to give it a go.
This is a toy and very much for educational purposes - there are definitely parts of the DES algorithm that are not up to spec.
`core` library crate contains the algorithm implementation.
`des` binary crate will convert strings to `Vec<u64>` and pass them to the algorithm - enciphering, deciphering & printing all the blocks to stdout.

## Sources

[NIST Spec](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf)
