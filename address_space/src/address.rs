// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::ops::{BitAnd, BitOr};

use util::num_ops::{round_down, round_up};

/// Represent the address in given address space.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct GuestAddress(pub u64);

impl GuestAddress {
    /// Get the raw value of `GuestAddress`.
    pub fn raw_value(self) -> u64 {
        self.0
    }

    /// Get the offset of this address from the given address.
    /// The caller has to guarantee no underflow occurs.
    ///
    /// # Arguments
    ///
    /// * `other` -Other `GuestAddress`.
    pub fn offset_from(self, other: Self) -> u64 {
        self.raw_value() - other.raw_value()
    }

    /// Return address of this address plus the given offset, return None if overflows.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset address.
    pub fn checked_add(self, offset: u64) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    /// Return address of this address minus the given offset, return None if overflows.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset address.
    pub fn checked_sub(self, offset: u64) -> Option<Self> {
        self.0.checked_sub(offset).map(Self)
    }

    /// Return address of this address plus the given offset.
    /// The caller has to guarantee no overflow occurs.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset address.
    pub fn unchecked_add(self, offset: u64) -> Self {
        Self(self.0 + offset)
    }

    /// Return address of this address minus the given offset.
    /// The caller has to guarantee no underflow occurs.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset address.
    pub fn unchecked_sub(self, offset: u64) -> Self {
        Self(self.0 - offset)
    }

    /// Return aligned-up address of Self, according to the given alignment.
    /// Return None if overflow occurs.
    ///
    /// # Arguments
    ///
    /// * `alignment` - Alignment base.
    pub fn align_up(self, alignment: u64) -> Option<Self> {
        round_up(self.0, alignment).map(Self)
    }

    /// Return aligned-down address of Self, according to the given alignment.
    /// Return None if underflow occurs.
    ///
    /// # Arguments
    ///
    /// * `alignment` - Alignment base.
    pub fn align_down(self, alignment: u64) -> Option<Self> {
        round_down(self.0, alignment).map(Self)
    }
}

/// Implement BitAnd trait for GuestAddress.
impl BitAnd<u64> for GuestAddress {
    type Output = GuestAddress;
    fn bitand(self, other: u64) -> GuestAddress {
        GuestAddress(self.0 & other)
    }
}

/// Implement BitOr trait for GuestAddress.
impl BitOr<u64> for GuestAddress {
    type Output = GuestAddress;
    fn bitor(self, other: u64) -> GuestAddress {
        GuestAddress(self.0 | other)
    }
}

/// Represent an address range.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct AddressRange {
    /// Base address.
    pub base: GuestAddress,
    /// Size of memory segment.
    pub size: u64,
}

/// Implement From trait for AddressRange.
impl From<(u64, u64)> for AddressRange {
    fn from(range: (u64, u64)) -> AddressRange {
        AddressRange {
            base: GuestAddress(range.0),
            size: range.1,
        }
    }
}

/// Implement PartialOrd trait for AddressRange.
impl PartialOrd for AddressRange {
    fn partial_cmp(&self, other: &AddressRange) -> Option<Ordering> {
        if self.base != other.base {
            self.base.partial_cmp(&other.base)
        } else {
            self.size.partial_cmp(&other.size)
        }
    }
}

/// Implement Ord trait for AddressRange.
impl Ord for AddressRange {
    fn cmp(&self, other: &AddressRange) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl AddressRange {
    /// Create a new `AddressRange`.
    ///
    /// # Arguments
    ///
    /// * `base` - The base address of a AddressRange.
    /// * `size` - The size of a AddressRange.
    pub fn new(base: GuestAddress, size: u64) -> AddressRange {
        AddressRange { base, size }
    }

    /// Find the intersection with other `AddressRange`.
    /// Return the intersection of Self and the given address range.
    /// Return None if not overlaps.
    ///
    /// # Arguments
    ///
    /// * `other` - Other AddressRange.
    pub fn find_intersection(&self, other: AddressRange) -> Option<AddressRange> {
        let begin = self.base.raw_value() as u128;
        let end = self.size as u128 + begin;
        let other_begin = other.base.raw_value() as u128;
        let other_end = other.size as u128 + other_begin;

        if end <= other_begin || other_end <= begin {
            return None;
        }
        let start = std::cmp::max(self.base, other.base);
        let size_inter = (std::cmp::min(end, other_end) - start.0 as u128) as u64;

        Some(AddressRange {
            base: start,
            size: size_inter,
        })
    }

    /// Return the end address of this address range.
    #[inline]
    pub fn end_addr(&self) -> GuestAddress {
        self.base.unchecked_add(self.size)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_address_add() {
        let addr1 = GuestAddress(0xAE);
        let offset: u64 = 0x01;

        let max_addr = GuestAddress(u64::max_value());
        let min_addr = GuestAddress(u64::min_value());

        assert_eq!(Some(GuestAddress(0xAF)), addr1.checked_add(offset));
        assert_eq!(None, max_addr.checked_add(offset));
        assert_eq!(None, min_addr.checked_sub(offset));
    }

    #[test]
    fn test_addr_offset() {
        let addr1 = GuestAddress(0xAE);
        let addr2 = GuestAddress(0xA0);
        let addr3 = GuestAddress(0xE);

        assert_eq!(addr3.raw_value(), addr1.offset_from(addr2));
    }

    #[test]
    fn test_address_cmp() {
        let addr1 = GuestAddress(0xAE);
        let addr2 = GuestAddress(0x63);
        let addr3 = GuestAddress(0xAE);

        assert!(addr1 == addr3);
        assert!(addr1 > addr2);
        assert!(addr2 < addr3);
        assert!(addr1 >= addr3);
        assert!(addr1 <= addr3);
        assert!(addr1 >= addr2);
        assert!(addr2 <= addr3);
    }
    #[test]
    fn test_address_equal() {
        let addr1 = GuestAddress(0x111);
        let addr2 = GuestAddress(0x123);
        let addr3 = GuestAddress(0x123);

        assert_eq!(addr2, addr3);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_address_mask() {
        let addr = GuestAddress(0xAEAE);

        assert_eq!(GuestAddress(0xAE00), addr & 0xffff00);
        assert_eq!(GuestAddress(0xAEAE), addr & 0xFFFFFF);
        assert_eq!(GuestAddress(0xFFFF), addr | 0xFFFF);
        assert_eq!(GuestAddress(0xFFAE), addr | 0xFF00);
    }

    #[test]
    fn test_address_align() {
        let addr1 = GuestAddress(0x1001);
        let addr2 = GuestAddress(0x1009);

        assert_eq!(Some(GuestAddress(0x1010)), addr1.align_up(0x10));
        assert_eq!(Some(GuestAddress(0x1000)), addr2.align_down(0x10));
    }

    #[test]
    fn test_address_range_intersects() {
        let range1 = AddressRange {
            base: GuestAddress(0_u64),
            size: 8_u64,
        };
        let range2 = AddressRange {
            base: GuestAddress(0_u64),
            size: 0_u64,
        };
        let range3 = AddressRange {
            base: GuestAddress(5_u64),
            size: 9_u64,
        };
        let range4 = AddressRange {
            base: GuestAddress(8_u64),
            size: 1u64,
        };

        assert!(range1.find_intersection(range2).is_none());
        assert_eq!(
            range1.find_intersection(range3),
            Some(AddressRange {
                base: GuestAddress(5_u64),
                size: 3_u64
            })
        );
        assert!(range1.find_intersection(range4).is_none());
    }

    #[test]
    fn test_address_range_end_addr() {
        let range = AddressRange {
            base: GuestAddress(55_u64),
            size: 10_u64,
        };

        assert_eq!(range.end_addr(), GuestAddress(65_u64));
    }

    #[test]
    fn test_address_range_compare() {
        let range1 = AddressRange {
            base: GuestAddress(0x1000),
            size: 0x1000,
        };
        let mut range2 = AddressRange {
            base: GuestAddress(0x500),
            size: 0x500,
        };

        assert!(range2 != range1);
        assert!(range2 < range1);

        range2.base = GuestAddress(0x1000);
        assert!(range2 != range1);
        assert!(range2 < range1);

        range2.size = 0x1200;
        assert!(range2 != range1);
        assert!(range2 > range1);
    }
}
