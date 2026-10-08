//! Turns raw shred bytes into a checked Shred: what kind it is and where it sits in its FEC set.

use crate::error::{Error, Result};
use crate::wire;

/// Data shreds carry block bytes, coding shreds carry Reed-Solomon parity.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Kind {
    Data,
    Code,
}

/// What the variant byte at offset 64 says about a shred.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Variant {
    pub kind: Kind,
    /// Number of 20 byte Merkle proof entries in the tail, 6 for a 32:32 set.
    pub proof_size: u8,
    /// Last FEC set of a slot: the tail has an extra 64 byte retransmitter signature.
    pub resigned: bool,
}

/// Splits the variant byte: high 4 bits are the type, low 4 bits the proof size.
pub fn parse_variant(v: u8) -> Result<Variant> {
    // >> 4 drops the proof size so every 0x9_ byte matches 0x9, and so on.
    // Agave builds the byte as proof_size | 0x60, 0x70, 0x90 or 0xB0.
    match v >> 4 {
        0x6 => Ok(Variant {
            kind: Kind::Code,
            // & 0x0F keeps only the low 4 bits
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
        // legacy, unchained or not a shred at all
        _ => Err(Error::UnknownVariant(v)),
    }
}

/// Slot of this shred's shard in the Reed-Solomon batch: data at 0..num_data, coding right after.
pub fn shard_index(b: &[u8]) -> Result<usize> {
    match parse_variant(wire::variant(b)?)?.kind {
        Kind::Data => {
            let index = wire::index(b)?;
            let fec_set_index = wire::fec_set_index(b)?;
            // checked_sub gives None instead of panicking when a junk packet has index < fec_set_index
            let offset = index
                .checked_sub(fec_set_index)
                .ok_or(Error::IndexBelowFecSet {
                    index,
                    fec_set_index,
                })?;
            // u32 always fits in usize on 32 and 64 bit targets
            Ok(offset as usize)
        }
        Kind::Code => {
            let num_data = wire::num_data(b)?;
            let position = wire::position(b)?;
            // widen to usize before adding so two u16 values can't overflow
            Ok(usize::from(num_data) + usize::from(position))
        }
    }
}

/// One shred checked once at the door, so later stages can trust every field.
pub struct Shred {
    pub slot: u64,
    /// Position within the slot.
    pub index: u32,
    /// Index of the first data shred in this shred's FEC set.
    pub fec_set_index: u32,
    pub variant: Variant,
    /// Position within the FEC set, 0..64.
    pub shard_index: usize,
    /// Capture timestamp in nanoseconds, used for the latency numbers.
    pub recv_ns: u64,
    /// The whole packet, kept for Reed-Solomon recovery.
    pub bytes: Vec<u8>,
}

impl Shred {
    /// Checks the variant and header length, then reads the fields every stage needs.
    pub fn parse(b: &[u8], recv_ns: u64) -> Result<Self> {
        let variant = parse_variant(wire::variant(b)?)?;

        // Getting the header size based on the variant
        // data shreds have a longer header 88 bytes than coding shreds 89 bytes
        let header_size = match variant.kind {
            Kind::Data => wire::DATA_HEADER_SIZE,
            Kind::Code => wire::CODING_HEADER_SIZE,
        };

        if b.len() < header_size {
            return Err(Error::TooShort {
                expected: header_size,
                actual: b.len(),
            });
        }

        let slot = wire::slot(b)?;
        let index = wire::index(b)?;
        let fec_set_index = wire::fec_set_index(b)?;
        let shard_index = shard_index(b)?;

        Ok(Self {
            slot,
            index,
            fec_set_index,
            variant,
            shard_index,
            recv_ns,
            bytes: b.to_vec(),
        })
    }

    /// Key that groups shreds into FEC sets: every shred of one set shares it.
    pub fn fec_key(&self) -> (u64, u32) {
        (self.slot, self.fec_set_index)
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

    // Shred::parse: check a packet once and keep the fields the FEC stage needs.
    #[test]
    fn test_parse_real_data() {
        let s = Shred::parse(&REAL_DATA, 1_000).unwrap();
        assert_eq!(s.slot, 449_661_761);
        assert_eq!(s.index, 74);
        assert_eq!(s.fec_set_index, 64);
        assert_eq!(s.variant, parse_variant(0x96).unwrap());
        assert_eq!(s.shard_index, 10);
        assert_eq!(s.recv_ns, 1_000);
        assert_eq!(s.bytes, REAL_DATA.to_vec());
    }

    #[test]
    fn test_parse_real_code() {
        let s = Shred::parse(&REAL_CODE, 2_000).unwrap();
        assert_eq!(s.slot, 449_661_761);
        assert_eq!(s.index, 87);
        assert_eq!(s.fec_set_index, 64);
        assert_eq!(s.variant.kind, Kind::Code);
        assert_eq!(s.shard_index, 55);
        assert_eq!(s.recv_ns, 2_000);
        assert_eq!(s.bytes.len(), 89);
    }

    #[test]
    fn test_parse_same_set() {
        // a data and a coding shred of one FEC set must land on the same key
        let d = Shred::parse(&REAL_DATA, 0).unwrap();
        let c = Shred::parse(&REAL_CODE, 0).unwrap();
        assert_eq!(d.fec_key(), c.fec_key());
        assert_eq!(d.fec_key(), (449_661_761, 64));
    }

    #[test]
    fn test_parse_unknown_variant() {
        let mut bytes = REAL_DATA;
        bytes[64] = 0x19;
        assert!(matches!(
            Shred::parse(&bytes, 0),
            Err(Error::UnknownVariant(0x19))
        ));
    }

    #[test]
    fn test_parse_data_too_short() {
        // a data shred needs its full 88 byte header
        assert!(matches!(
            Shred::parse(&REAL_DATA[..87], 0),
            Err(Error::TooShort {
                expected: 88,
                actual: 87
            })
        ));
    }

    #[test]
    fn test_parse_code_too_short() {
        // a coding shred needs its full 89 byte header
        assert!(matches!(
            Shred::parse(&REAL_CODE[..88], 0),
            Err(Error::TooShort {
                expected: 89,
                actual: 88
            })
        ));
    }

    #[test]
    fn test_parse_empty() {
        assert!(matches!(
            Shred::parse(&[], 0),
            Err(Error::TooShort {
                expected: 65,
                actual: 0
            })
        ));
    }

    #[test]
    fn test_parse_bad_data_index() {
        let mut bytes = REAL_DATA;
        bytes[73..77].copy_from_slice(&10u32.to_le_bytes());
        assert!(matches!(
            Shred::parse(&bytes, 0),
            Err(Error::IndexBelowFecSet {
                index: 10,
                fec_set_index: 64
            })
        ));
    }
}
