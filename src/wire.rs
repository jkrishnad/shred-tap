use crate::error::{Error, Result};
use std::ops::Range;

// Common header
pub const SIGNATURE: Range<usize> = 0..64;
pub const VARIANT: usize = 64;
pub const SLOT: Range<usize> = 65..73;
pub const INDEX: Range<usize> = 73..77;
pub const VERSION: Range<usize> = 77..79;
pub const FEC_SET_INDEX: Range<usize> = 79..83;
pub const COMMON_HEADER_SIZE: usize = 83;

// Data header
pub const PARENT_OFFSET: Range<usize> = 83..85;
pub const FLAGS: usize = 85;
pub const DATA_SIZE: Range<usize> = 86..88;

// Coding header
pub const NUM_DATA: Range<usize> = 83..85;
pub const NUM_CODING: Range<usize> = 85..87;
pub const POSITION: Range<usize> = 87..89;

fn read_bytes(bytes: &[u8], range: Range<usize>) -> Result<&[u8]> {
    let expected = range.end;
    bytes.get(range).ok_or(Error::TooShort {
        expected,
        actual: bytes.len(),
    })
}

pub fn slot(bytes: &[u8]) -> Result<u64> {
    let bytes = read_bytes(bytes, SLOT)?;

    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    let slot = u64::from_le_bytes(arr);

    Ok(slot)
}

pub fn variant(bytes: &[u8]) -> Result<u8> {
    let variant = bytes.get(VARIANT).copied().ok_or(Error::TooShort {
        expected: VARIANT + 1,
        actual: bytes.len(),
    })?;

    Ok(variant)
}

pub fn version(bytes: &[u8]) -> Result<u16> {
    let bytes = read_bytes(bytes, VERSION)?;
    let mut arr = [0u8; 2];
    arr.copy_from_slice(bytes);

    let version = u16::from_le_bytes(arr);
    Ok(version)
}

pub fn index(bytes: &[u8]) -> Result<u32> {
    let bytes = read_bytes(bytes, INDEX)?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    let index = u32::from_le_bytes(arr);
    Ok(index)
}

pub fn fec_set_index(bytes: &[u8]) -> Result<u32> {
    let bytes = read_bytes(bytes, FEC_SET_INDEX)?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    let index = u32::from_le_bytes(arr);
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_range() {
        let bytes = [0u8; 10];
        let range = 0..5;
        assert_eq!(read_bytes(&bytes, range).unwrap(), &bytes[0..5]);

        let range = 5..10;
        assert_eq!(read_bytes(&bytes, range).unwrap(), &bytes[5..10]);
    }

    #[test]
    fn test_fail_byte_range() {
        let bytes = [0u8; 5];
        let range = 0..10;
        assert!(read_bytes(&bytes, range).is_err());
    }

    #[test]
    fn test_slot() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        bytes[SLOT].copy_from_slice(&444_700_123u64.to_le_bytes());
        assert_eq!(slot(&bytes).unwrap(), 444_700_123);
    }

    #[test]
    fn test_slot_fail() {
        let bytes = [0u8; 72];
        assert!(matches!(
            slot(&bytes),
            Err(Error::TooShort {
                expected: 73,
                actual: 72
            })
        ));
    }

    #[test]
    fn test_variant() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        // literal 64, not VARIANT, so a wrong const fails here
        bytes[64] = 0x96;
        assert_eq!(variant(&bytes).unwrap(), 0x96);
    }

    #[test]
    fn test_variant_fail() {
        // 64 bytes is only the signature, the variant byte is missing
        let bytes = [0u8; 64];
        assert!(matches!(
            variant(&bytes),
            Err(Error::TooShort {
                expected: 65,
                actual: 64
            })
        ));
    }

    #[test]
    fn test_index() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        bytes[INDEX].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        assert_eq!(index(&bytes).unwrap(), 0x0102_0304);
    }

    #[test]
    fn test_index_fail() {
        let bytes = [0u8; 76];
        assert!(matches!(
            index(&bytes),
            Err(Error::TooShort {
                expected: 77,
                actual: 76
            })
        ));
    }

    #[test]
    fn test_version() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        bytes[VERSION].copy_from_slice(&200u16.to_le_bytes());
        assert_eq!(version(&bytes).unwrap(), 200);
    }

    #[test]
    fn test_version_fail() {
        let bytes = [0u8; 78];
        assert!(matches!(
            version(&bytes),
            Err(Error::TooShort {
                expected: 79,
                actual: 78
            })
        ));
    }

    #[test]
    fn test_fec_set_index() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        bytes[FEC_SET_INDEX].copy_from_slice(&96u32.to_le_bytes());
        assert_eq!(fec_set_index(&bytes).unwrap(), 96);
    }

    #[test]
    fn test_fec_set_index_fail() {
        let bytes = [0u8; 82];
        assert!(matches!(
            fec_set_index(&bytes),
            Err(Error::TooShort {
                expected: 83,
                actual: 82
            })
        ));
    }
}
