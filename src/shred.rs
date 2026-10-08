use crate::error::{Error, Result};
use crate::wire;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Kind {
    Data,
    Code,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Variant {
    pub kind: Kind,
    pub proof_size: u8,
    pub resigned: bool,
}

pub fn parse_variant(v: u8) -> Result<Variant> {
    // Parse the variant byte into a Variant struct.
    match v >> 4 {
        0x6 => Ok(Variant {
            kind: Kind::Code,
            proof_size: v & 0x0F,
            resigned: false,
        }),
        0x7 => Ok(Variant {
            kind: Kind::Code,
            proof_size: v & 0x0F,
            resigned: true,
        }),
        0x9 => Ok(Variant {
            kind: Kind::Data,
            proof_size: v & 0x0F,
            resigned: false,
        }),
        0xB => Ok(Variant {
            kind: Kind::Data,
            proof_size: v & 0x0F,
            resigned: true,
        }),
        _ => Err(Error::UnknownVariant(v)),
    }
}

pub fn shard_index(b: &[u8]) -> Result<usize> {
    // Data shreds sit at 0..num_data in the FEC set, coding shreds right after them.
    match parse_variant(wire::variant(b)?)?.kind {
        Kind::Data => {
            let index = wire::index(b)?;
            let fec_set_index = wire::fec_set_index(b)?;
            let offset = index
                .checked_sub(fec_set_index)
                .ok_or(Error::IndexBelowFecSet {
                    index,
                    fec_set_index,
                })?;
            Ok(offset as usize)
        }
        Kind::Code => {
            let num_data = wire::num_data(b)?;
            let position = wire::position(b)?;
            Ok(usize::from(num_data) + usize::from(position))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::wire::tests::{REAL_CODE, REAL_DATA};

    // Variant byte: high 4 bits are the type, low 4 bits the Merkle proof size.
    // From Agave shred.rs: 0x60 code, 0x70 code resigned, 0x90 data, 0xB0 data resigned.
    #[test]
    fn test_variant_data() {
        let v = parse_variant(0x96).unwrap();
        assert_eq!(v.kind, Kind::Data);
        assert_eq!(v.proof_size, 6);
        assert!(!v.resigned);
    }

    #[test]
    fn test_variant_data_resigned() {
        let v = parse_variant(0xB6).unwrap();
        assert_eq!(v.kind, Kind::Data);
        assert_eq!(v.proof_size, 6);
        assert!(v.resigned);
    }

    #[test]
    fn test_variant_code() {
        let v = parse_variant(0x66).unwrap();
        assert_eq!(v.kind, Kind::Code);
        assert_eq!(v.proof_size, 6);
        assert!(!v.resigned);
    }

    #[test]
    fn test_variant_code_resigned() {
        let v = parse_variant(0x76).unwrap();
        assert_eq!(v.kind, Kind::Code);
        assert_eq!(v.proof_size, 6);
        assert!(v.resigned);
    }

    #[test]
    fn test_variant_unknown() {
        // the stray packet from the first capture
        assert!(matches!(
            parse_variant(0x19),
            Err(Error::UnknownVariant(0x19))
        ));
        // legacy shred variants, no longer in use
        assert!(matches!(
            parse_variant(0xA5),
            Err(Error::UnknownVariant(0xA5))
        ));
        assert!(matches!(
            parse_variant(0x5A),
            Err(Error::UnknownVariant(0x5A))
        ));
        // unchained Merkle variants, no longer in use
        assert!(matches!(
            parse_variant(0x86),
            Err(Error::UnknownVariant(0x86))
        ));
        assert!(matches!(
            parse_variant(0x46),
            Err(Error::UnknownVariant(0x46))
        ));
    }

    #[test]
    fn test_variant_other_proof_size() {
        // a smaller FEC set has a shorter proof, the type is still read from the high bits
        let v = parse_variant(0x93).unwrap();
        assert_eq!(v.kind, Kind::Data);
        assert_eq!(v.proof_size, 3);
    }

    // Shard index: the shred's slot inside its FEC set, 0..64.
    // Data shreds fill 0..num_data, coding shreds come after them.

    #[test]
    fn test_shard_index_real_data() {
        // index 74, fec_set_index 64
        assert_eq!(shard_index(&REAL_DATA).unwrap(), 10);
    }

    #[test]
    fn test_shard_index_real_code() {
        // index 87, fec_set_index 64, num_data 32, position 23
        assert_eq!(shard_index(&REAL_CODE).unwrap(), 55);
    }

    #[test]
    fn test_shard_index_unknown_variant() {
        let mut bytes = REAL_DATA;
        bytes[64] = 0x19;
        assert!(matches!(
            shard_index(&bytes),
            Err(Error::UnknownVariant(0x19))
        ));
    }

    #[test]
    fn test_shard_index_code_too_short() {
        // a coding shred cut before its coding header ends
        assert!(matches!(
            shard_index(&REAL_CODE[..88]),
            Err(Error::TooShort {
                expected: 89,
                actual: 88
            })
        ));
    }

    #[test]
    fn test_shard_index_bad_data_shred() {
        // junk data shred whose index is below its fec_set_index, must not panic
        let mut bytes = REAL_DATA;
        bytes[73..77].copy_from_slice(&10u32.to_le_bytes());
        assert!(shard_index(&bytes).is_err());
    }
}
