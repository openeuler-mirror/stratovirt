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

use std::cmp::Ord;
use std::mem::size_of;

use crate::UtilError;
use anyhow::{anyhow, Context, Result};

/// This struct is used to offer bitmap.
pub struct Bitmap<T: BitOps> {
    /// The data to restore bit information.
    data: Vec<T>,
}

impl<T: BitOps> Bitmap<T> {
    /// Initialize a Bitmap structure with a size.
    ///
    /// # Arguments
    ///
    /// * `size` - The size of bitmap is the number of bit unit. If you want
    /// to restore a `length` with bitmap. The `size` would be `length/bit_unit_size+1`.
    pub fn new(size: usize) -> Self {
        Bitmap::<T> {
            data: [T::zero()].repeat(size),
        }
    }

    /// Return the size of bitmap.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Return the Volume of bitmap.
    pub fn vol(&self) -> usize {
        self.size() * T::len()
    }

    /// Set the bit of bitmap.
    ///
    /// # Arguments
    ///
    /// * `num` - the input number.
    pub fn set(&mut self, num: usize) -> Result<()> {
        let index = self.bit_index(num);
        if index >= self.size() {
            return Err(anyhow!(UtilError::OutOfBound(
                index as u64,
                self.vol() as u64
            )));
        }
        self.data[index] = T::bit_or(self.data[index], T::one().rhs(self.bit_pos(num)));
        Ok(())
    }

    /// Clear the bit of bitmap.
    ///
    /// # Arguments
    ///
    /// * `num` - the input number
    pub fn clear(&mut self, num: usize) -> Result<()> {
        let index = self.bit_index(num);
        if index >= self.size() {
            return Err(anyhow!(UtilError::OutOfBound(
                index as u64,
                self.vol() as u64
            )));
        }
        self.data[index] = T::bit_and(
            self.data[index],
            T::bit_not(T::one().rhs(self.bit_pos(num))),
        );
        Ok(())
    }

    /// Query bitmap if contains input number or not.
    ///
    /// # Arguments
    ///
    /// * `num` - the input number.
    pub fn contain(&self, num: usize) -> Result<bool> {
        if num > self.vol() {
            return Err(anyhow!(UtilError::OutOfBound(
                num as u64,
                (self.size() as u64 * T::len() as u64) as u64,
            )));
        }
        Ok(T::bit_and(
            self.data[self.bit_index(num)],
            T::one().rhs(self.bit_pos(num)),
        )
        .bool())
    }

    /// Count the number of bits before the input offset.
    ///
    /// # Arguments
    ///
    /// * `offset` - the input offset as the query's start.
    pub fn count_front_bits(&self, offset: usize) -> Result<usize> {
        if offset > self.vol() {
            return Err(anyhow!(UtilError::OutOfBound(
                offset as u64,
                self.size() as u64
            )));
        }
        let mut num = 0;
        for i in 0..self.bit_index(offset) + 1 {
            if i == self.bit_index(offset) {
                for j in i * T::len()..offset {
                    let ret = self.contain(j).with_context(|| "count front bits failed")?;
                    if ret {
                        num += 1;
                    }
                }
                break;
            }
            if self.data[i] != T::zero() {
                for j in 0..T::len() {
                    if T::bit_and(self.data[i], T::one().rhs(j)).bool() {
                        num += 1;
                    };
                }
            }
        }
        Ok(num)
    }

    /// Return a new offset to get a zero bit from input offset.
    ///
    /// # Arguments
    ///
    /// * `offset` - the input offset as the query's start.
    pub fn find_next_zero(&self, offset: usize) -> Result<usize> {
        let size = self.size();
        let idx = offset / T::len();
        let mut offset = offset % T::len();
        for i in idx..size {
            if self.data[i] == T::full() {
                continue;
            }
            for j in offset..T::len() {
                if !self.contain(i * T::len() + j)? {
                    return Ok(i * T::len() + j);
                }
            }
            offset = 0;
        }
        Ok(self.vol())
    }

    /// Return a new offset to get next nonzero bit from input offset.
    ///
    /// # Arguments
    ///
    /// * `offset` - the input offset as the query's start.
    pub fn find_next_bit(&self, offset: usize) -> Result<usize> {
        let size = self.size();
        let idx = offset / T::len();
        let mut offset = offset % T::len();
        for i in idx..size {
            if self.data[i] == T::zero() {
                continue;
            }
            for j in offset..T::len() {
                if self.contain(i * T::len() + j)? {
                    return Ok(i * T::len() + j);
                }
            }
            offset = 0;
        }

        Ok(self.vol())
    }

    /// Get the inner data from bitmap.
    ///
    /// # Arguments
    ///
    /// * `buf` - the cache to receive the data.
    pub fn get_data(&mut self, buf: &mut Vec<T>) {
        buf.clear();
        buf.append(&mut self.data);
    }

    /// clear all the data in bitmap
    pub fn clear_all(&mut self) {
        for i in 0..self.size() {
            self.data[i] = T::zero();
        }
    }

    fn bit_index(&self, num: usize) -> usize {
        num / T::len()
    }

    fn bit_pos(&self, num: usize) -> usize {
        num % T::len()
    }
}

/// This trait is used to bind some basic operations of bit.
pub trait BitOps: Copy + Ord {
    fn bool(self) -> bool;
    fn len() -> usize;
    fn zero() -> Self;
    fn one() -> Self;
    fn full() -> Self;
    fn value(self) -> usize;
    fn bit_not(bit: Self) -> Self;
    fn bit_and(bit: Self, other_bit: Self) -> Self;
    fn bit_or(bit: Self, other_bit: Self) -> Self;
    fn bit_xor(bit: Self, other_bit: Self) -> Self;
    fn rhs(&self, rhs: usize) -> Self;
    fn lhs(&self, lhs: usize) -> Self;
}

macro_rules! bitops {
    ($type:ident) => {
        impl BitOps for $type {
            fn bool(self) -> bool {
                !(self == 0)
            }

            fn len() -> usize {
                size_of::<Self>() / size_of::<u8>() * 8
            }

            fn zero() -> Self {
                0 as Self
            }

            fn one() -> Self {
                1 as Self
            }

            fn full() -> Self {
                !0 as Self
            }

            fn value(self) -> usize {
                (self / Self::one()) as usize
            }

            fn bit_not(bit: Self) -> Self {
                !bit
            }

            fn bit_and(bit: Self, other_bit: Self) -> Self {
                bit & other_bit
            }

            fn bit_or(bit: Self, other_bit: Self) -> Self {
                bit | other_bit
            }

            fn bit_xor(bit: Self, other_bit: Self) -> Self {
                bit ^ other_bit
            }

            fn rhs(&self, rhs: usize) -> Self {
                self << rhs
            }

            fn lhs(&self, lhs: usize) -> Self {
                self >> lhs
            }
        }
    };
}

bitops!(u8);
bitops!(u16);
bitops!(u32);
bitops!(u64);

#[cfg(test)]
mod tests {
    use super::Bitmap;

    #[test]
    fn test_bitmap_basic() {
        let mut bitmap = Bitmap::<u16>::new(1);
        assert!(bitmap.set(15).is_ok());
        assert!(bitmap.set(16).is_err());
        assert_eq!(bitmap.count_front_bits(16).unwrap(), 1);
        assert_eq!(bitmap.count_front_bits(15).unwrap(), 0);
    }
}
