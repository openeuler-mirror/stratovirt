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

use std::cmp::Ordering;
use std::io::{Read, Result};

const DEFAULT_BUFFER_SIZE: usize = 8192;

pub struct BufferReader<R> {
    reader: R,
    buffer: Vec<u8>,
    pos: usize,
    end: usize,
}

impl<R: Read> BufferReader<R> {
    /// Create a new buffer_reader instance from `Read`.
    pub fn new(reader: R) -> Self {
        let mut buffer = Vec::<u8>::new();
        buffer.resize(DEFAULT_BUFFER_SIZE, 0);

        BufferReader {
            reader,
            buffer,
            pos: 0,
            end: 0,
        }
    }

    pub fn with_capacity(reader: R, capacity: usize) -> Self {
        let mut buffer = Vec::<u8>::new();
        buffer.resize(capacity, 0_u8);

        BufferReader {
            reader,
            buffer,
            pos: 0,
            end: 0,
        }
    }

    /// Returns the number of bytes the internal buffer can hold at once.
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Read data from `reader` to fill `buffer`, update `pos` and `end`.
    pub fn read_buffer(&mut self) -> Result<()> {
        let length = self.reader.read(&mut self.buffer)?;
        self.pos = 0;
        self.end = length;

        Ok(())
    }

    /// Read assigned length bytes from `file` to come out with `Vec<u8>`.
    ///
    /// # Arguments
    ///
    /// * `bytes_num` - length wanted to read from `file`.
    pub fn read_vectored(&mut self, bytes_num: usize) -> Option<Vec<u8>> {
        let mut slice_vec = Vec::<u8>::new();
        let mut read_len = bytes_num;

        // Judge the file is read over or not.
        while self.end != 0 {
            match read_len.cmp(&(self.end - self.pos)) {
                Ordering::Greater => {
                    slice_vec.extend(&self.buffer[self.pos..self.end]);
                    read_len -= self.end - self.pos;
                    self.read_buffer().unwrap();
                }
                Ordering::Equal => {
                    slice_vec.extend(&self.buffer[self.pos..self.end]);
                    self.read_buffer().unwrap();
                    break;
                }
                Ordering::Less => {
                    slice_vec.extend(&self.buffer[self.pos..self.pos + read_len]);
                    self.pos += read_len;
                    break;
                }
            }
        }

        if slice_vec.len() == bytes_num {
            Some(slice_vec)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Result, Write};

    use super::BufferReader;

    fn mk_tempfile() -> Result<()> {
        let module_dir = option_env!("CARGO_MANIFEST_DIR").unwrap();
        let tempfile_path = module_dir.to_string() + "/tempfile";
        let mut file = File::create(tempfile_path)?;
        write_test_data(&mut file)
    }

    fn open_tempfile() -> Result<File> {
        let module_dir = option_env!("CARGO_MANIFEST_DIR").unwrap();
        let tempfile_path = module_dir.to_string() + "/tempfile";
        File::open(tempfile_path)
    }

    fn del_tempfile() -> Result<()> {
        let module_dir = option_env!("CARGO_MANIFEST_DIR").unwrap();
        let tempfile_path = module_dir.to_string() + "/tempfile";
        std::fs::remove_file(tempfile_path)
    }

    fn write_test_data(file: &mut File) -> Result<()> {
        let mut test_buffer_vec_01 = [0_u8; 16384];
        for i in 0..16384 {
            test_buffer_vec_01[i] = (i % 256) as u8;
        }
        file.write(&mut test_buffer_vec_01)?;

        let mut test_buffer_vec_02 = [8_u8; 16384];
        file.write(&mut test_buffer_vec_02)?;

        Ok(())
    }

    #[test]
    fn test_buffer_reader() -> Result<()> {
        assert!(mk_tempfile().is_ok());

        let file = open_tempfile()?;
        let mut buffer_reader = BufferReader::new(&file);

        assert_eq!(buffer_reader.capacity(), 8_192);
        assert!(buffer_reader.read_buffer().is_ok());
        assert_eq!(buffer_reader.read_vectored(4), Some(vec![0, 1, 2, 3]));
        assert_eq!(
            buffer_reader.read_vectored(8),
            Some(vec![4, 5, 6, 7, 8, 9, 10, 11])
        );
        assert_eq!(
            buffer_reader.read_vectored(243),
            Some((12..255).into_iter().collect::<Vec<u8>>())
        );
        assert!(buffer_reader.read_vectored(16125).is_some());
        assert_eq!(
            buffer_reader.read_vectored(8),
            Some(vec![252, 253, 254, 255, 8, 8, 8, 8])
        );
        assert!(buffer_reader.read_vectored(16380).is_some());
        assert!(buffer_reader.read_vectored(1).is_none());

        assert!(del_tempfile().is_ok());
        Ok(())
    }
}
