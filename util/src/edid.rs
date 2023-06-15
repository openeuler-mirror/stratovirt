// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

/// We use Leaky Bucket Algorithm to limit iops of block device and qmp.
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use log::warn;

#[derive(Debug, Default)]
struct EdidMode {
    xres: u32,
    yres: u32,
    byte: u32,
    xtra3: u32,
    bit: u32,
    dta: u32,
}

#[derive(Debug, Default)]
pub struct EdidInfo {
    vendor: Vec<char>,
    name: Vec<char>,
    serial: u32,
    dpi: u32,
    prefx: u32,
    prefy: u32,
    maxx: u32,
    maxy: u32,
}

impl EdidInfo {
    pub fn new(vendor: &str, name: &str, dpi: u32, x: u32, y: u32) -> Self {
        EdidInfo {
            vendor: vendor.chars().collect(),
            name: name.chars().collect(),
            serial: 0,
            dpi,
            prefx: x,
            prefy: y,
            maxx: x,
            maxy: y,
        }
    }

    pub fn edid_array_fulfill(&mut self, edid_array: &mut [u8; 1024]) {
        // The format follows VESA ENHANCED EXTENDED DISPLAY IDENTIFICATION DATA STANDARD
        if self.vendor.len() != 3 {
            // HWV for 'HUAWEI TECHNOLOGIES CO., INC.'
            self.vendor = "HWV".chars().collect();
        }
        if self.name.is_empty() {
            self.name = "STRA Monitor".chars().collect();
        }
        if self.dpi == 0 {
            self.dpi = 100;
        }
        if self.prefx == 0 {
            self.prefx = 1024;
        }
        if self.prefy == 0 {
            self.prefy = 768;
        }

        let mut offset: usize = 54;
        let mut xtra3_offset: usize = 0;
        let mut dta_offset: usize = 0;
        if edid_array.len() >= 256 {
            dta_offset = 128;
            edid_array[126] += 1;
            self.fullfill_ext_dta(edid_array, dta_offset);
        }

        // Fixed header
        let header: u64 = 0x00FF_FFFF_FFFF_FF00;
        LittleEndian::write_u64(&mut edid_array[0..8], header);
        // ID Manufacturer Name
        let vendor_id: u16 = (((self.vendor[0] as u16 - '@' as u16) & 0x1f) << 10)
            | (((self.vendor[1] as u16 - '@' as u16) & 0x1f) << 5)
            | ((self.vendor[2] as u16 - '@' as u16) & 0x1f);
        BigEndian::write_u16(&mut edid_array[8..10], vendor_id);
        // ID Product Code
        LittleEndian::write_u16(&mut edid_array[10..12], 0x1234);
        // ID Serial Number
        LittleEndian::write_u32(&mut edid_array[12..16], self.serial);
        // Week of Manufacture
        edid_array[16] = 42;
        // Year of Manufacture or Model Year
        edid_array[17] = (2022 - 1990) as u8;
        // Version Number: defines EDID Structure Version 1, Revision 4.
        edid_array[18] = 0x01;
        // Revision Number
        edid_array[19] = 0x04;

        // Video Input Definition: digital, 8bpc, displayport
        edid_array[20] = 0xa5;
        // Horizontal Screen Size or Aspect Ratio
        edid_array[21] = (self.prefx * self.dpi / 2540) as u8;
        // Vertical Screen Size or Aspect Ratio
        edid_array[22] = (self.prefy * self.dpi / 2540) as u8;
        // Display Transfer Characteristic: display gamma is 2.2
        edid_array[23] = 220 - 100;
        // Feature Support: std sRGB, preferred timing
        edid_array[24] = 0x06;

        let temp: [f32; 8] = [
            0.6400, 0.3300, 0.3000, 0.6000, 0.1500, 0.0600, 0.3127, 0.3290,
        ];
        // Color Characteristics: 10 bytes
        self.fullfill_color_space(edid_array, temp);

        // 18 Byte Data Blocks: 72 bytes
        self.fullfill_desc_timing(edid_array, offset);
        offset += 18;

        self.fullfill_desc_range(edid_array, offset, 0xfd);
        offset += 18;

        if !self.name.is_empty() {
            self.fullfill_desc_text(edid_array, offset, 0xfc);
            offset += 18;
        }

        if self.serial != 0 {
            self.fullfill_desc_text(edid_array, offset, 0xff);
            offset += 18;
        }

        if offset < 126 {
            xtra3_offset = offset;
            self.fullfill_desc_xtra3_std(edid_array, xtra3_offset);
            offset += 18;
        }

        while offset < 126 {
            self.fullfill_desc_dummy(edid_array, offset);
            offset += 18;
        }

        // Established Timings: 3 bytes
        // Standard Timings: 16 bytes
        self.fullfill_modes(edid_array, xtra3_offset, dta_offset);

        // EXTENSION Flag and Checksum
        self.fullfill_checksum(edid_array)
    }

    fn fullfill_ext_dta(&mut self, edid_array: &mut [u8], offset: usize) {
        edid_array[offset] = 0x02;
        edid_array[offset + 1] = 0x03;
        edid_array[offset + 2] = 0x05;
        edid_array[offset + 3] = 0x00;
        // video data block
        edid_array[offset + 4] = 0x40;
    }

    fn fullfill_color_space(&mut self, edid_array: &mut [u8], arr: [f32; 8]) {
        let red_x: u32 = (arr[0] * 1024_f32 + 0.5) as u32;
        let red_y: u32 = (arr[0] * 1024_f32 + 0.5) as u32;
        let green_x: u32 = (arr[0] * 1024_f32 + 0.5) as u32;
        let green_y: u32 = (arr[0] * 1024_f32 + 0.5) as u32;
        let blue_x: u32 = (arr[0] * 1024_f32 + 0.5) as u32;
        let blue_y: u32 = (arr[0] * 1024_f32 + 0.5) as u32;
        let white_x: u32 = (arr[0] * 1024_f32 + 0.5) as u32;
        let white_y: u32 = (arr[0] * 1024_f32 + 0.5) as u32;

        edid_array[25] = (((red_x & 0x03) << 6)
            | ((red_y & 0x03) << 4)
            | ((green_x & 0x03) << 2)
            | (green_y & 0x03)) as u8;
        edid_array[26] = (((blue_x & 0x03) << 6)
            | ((blue_y & 0x03) << 4)
            | ((white_x & 0x03) << 2)
            | (white_y & 0x03)) as u8;
        edid_array[27] = (red_x >> 2) as u8;
        edid_array[28] = (red_y >> 2) as u8;
        edid_array[29] = (green_x >> 2) as u8;
        edid_array[30] = (green_y >> 2) as u8;
        edid_array[31] = (blue_x >> 2) as u8;
        edid_array[32] = (blue_y >> 2) as u8;
        edid_array[33] = (white_x >> 2) as u8;
        edid_array[34] = (white_y >> 2) as u8;
    }

    fn fullfill_desc_timing(&mut self, edid_array: &mut [u8], offset: usize) {
        // physical display size
        let xmm: u32 = self.prefx * self.dpi / 254;
        let ymm: u32 = self.prefy * self.dpi / 254;
        let xfront: u32 = self.prefx * 25 / 100;
        let xsync: u32 = self.prefx * 3 / 100;
        let xblank: u32 = self.prefx * 35 / 100;
        let yfront: u32 = self.prefy * 5 / 1000;
        let ysync: u32 = self.prefy * 5 / 1000;
        let yblank: u32 = self.prefy * 35 / 1000;
        let clock: u32 = 75 * (self.prefx + xblank) * (self.prefy + yblank);

        LittleEndian::write_u16(&mut edid_array[offset..offset + 2], clock as u16);
        edid_array[offset + 2] = (self.prefx & 0xff) as u8;
        edid_array[offset + 3] = (xblank & 0xff) as u8;
        edid_array[offset + 4] = (((self.prefx & 0xf00) >> 4) | ((xblank & 0xf00) >> 8)) as u8;
        edid_array[offset + 5] = (self.prefy & 0xff) as u8;
        edid_array[offset + 6] = (yblank & 0xff) as u8;
        edid_array[offset + 7] = (((self.prefy & 0xf00) >> 4) | ((yblank & 0xf00) >> 8)) as u8;
        edid_array[offset + 8] = (xfront & 0xff) as u8;
        edid_array[offset + 9] = (xsync & 0xff) as u8;
        edid_array[offset + 10] = (((yfront & 0x00f) << 4) | (ysync & 0x00f)) as u8;
        edid_array[offset + 11] = (((xfront & 0x300) >> 2)
            | ((xsync & 0x300) >> 4)
            | ((yfront & 0x030) >> 2)
            | ((ysync & 0x030) >> 4)) as u8;
        edid_array[offset + 12] = (xmm & 0xff) as u8;
        edid_array[offset + 13] = (ymm & 0xff) as u8;
        edid_array[offset + 14] = (((xmm & 0xf00) >> 4) | ((ymm & 0xf00) >> 8)) as u8;
        edid_array[offset + 17] = 0x18;
    }

    fn fullfill_desc_range(&mut self, edid_array: &mut [u8], offset: usize, desc_type: u8) {
        self.fullfill_desc_type(edid_array, offset, desc_type);
        // vertical (50 -> 125 Hz)
        edid_array[offset + 5] = 50;
        edid_array[offset + 6] = 125;
        // horizontal (30 -> 160 kHz)
        edid_array[offset + 7] = 30;
        edid_array[offset + 8] = 160;
        // max dot clock (1200 MHz)
        edid_array[offset + 9] = (1200 / 10) as u8;
        // no extended timing information
        edid_array[offset + 10] = 0x01;
        // padding
        edid_array[offset + 11] = b'\n';
        for i in 12..18 {
            edid_array[offset + i] = b' ';
        }
    }

    fn fullfill_desc_text(&mut self, edid_array: &mut [u8], offset: usize, desc_type: u8) {
        self.fullfill_desc_type(edid_array, offset, desc_type);
        for i in 5..18 {
            edid_array[offset + i] = b' ';
        }
        if desc_type == 0xfc {
            // name
            for (index, c) in self.name.iter().enumerate() {
                edid_array[offset + 5 + index] = (*c) as u8;
            }
        } else if desc_type == 0xff {
            // serial
            LittleEndian::write_u32(&mut edid_array[offset + 5..offset + 9], self.serial);
        } else {
            warn!("Unexpected desc type");
        }
    }

    fn fullfill_desc_xtra3_std(&mut self, edid_array: &mut [u8], offset: usize) {
        // additional standard timings 3
        self.fullfill_desc_type(edid_array, offset, 0xf7);
        edid_array[offset + 4] = 10;
    }

    fn fullfill_desc_dummy(&mut self, edid_array: &mut [u8], offset: usize) {
        self.fullfill_desc_type(edid_array, offset, 0x10);
    }

    fn fullfill_desc_type(&mut self, edid_array: &mut [u8], offset: usize, desc_type: u8) {
        edid_array[offset] = 0;
        edid_array[offset + 1] = 0;
        edid_array[offset + 2] = 0;
        edid_array[offset + 3] = desc_type;
        edid_array[offset + 4] = 0;
    }

    fn fullfill_modes(&mut self, edid_array: &mut [u8], xtra3_offset: usize, dta_offset: usize) {
        let edid_modes = vec![
            // dea/dta extension timings (all @ 50 Hz)
            EdidMode {
                xres: 5120,
                yres: 2160,
                dta: 125,
                ..Default::default()
            },
            EdidMode {
                xres: 4096,
                yres: 2160,
                dta: 101,
                ..Default::default()
            },
            EdidMode {
                xres: 3840,
                yres: 2160,
                dta: 96,
                ..Default::default()
            },
            EdidMode {
                xres: 2560,
                yres: 1080,
                dta: 89,
                ..Default::default()
            },
            EdidMode {
                xres: 2048,
                yres: 1152,
                ..Default::default()
            },
            EdidMode {
                xres: 1920,
                yres: 1080,
                dta: 31,
                ..Default::default()
            },
            // additional standard timings 3 (all @ 60Hz)
            EdidMode {
                xres: 1920,
                yres: 1440,
                xtra3: 11,
                bit: 5,
                ..Default::default()
            },
            EdidMode {
                xres: 1920,
                yres: 1200,
                xtra3: 10,
                bit: 0,
                ..Default::default()
            },
            EdidMode {
                xres: 1856,
                yres: 1392,
                xtra3: 10,
                bit: 3,
                ..Default::default()
            },
            EdidMode {
                xres: 1792,
                yres: 1344,
                xtra3: 10,
                bit: 5,
                ..Default::default()
            },
            EdidMode {
                xres: 1600,
                yres: 1200,
                xtra3: 9,
                bit: 2,
                ..Default::default()
            },
            EdidMode {
                xres: 1680,
                yres: 1050,
                xtra3: 9,
                bit: 5,
                ..Default::default()
            },
            EdidMode {
                xres: 1440,
                yres: 1050,
                xtra3: 8,
                bit: 1,
                ..Default::default()
            },
            EdidMode {
                xres: 1440,
                yres: 900,
                xtra3: 8,
                bit: 5,
                ..Default::default()
            },
            EdidMode {
                xres: 1360,
                yres: 768,
                xtra3: 8,
                bit: 7,
                ..Default::default()
            },
            EdidMode {
                xres: 1280,
                yres: 1024,
                xtra3: 7,
                bit: 1,
                ..Default::default()
            },
            EdidMode {
                xres: 1280,
                yres: 960,
                xtra3: 7,
                bit: 3,
                ..Default::default()
            },
            EdidMode {
                xres: 1280,
                yres: 768,
                xtra3: 7,
                bit: 6,
                ..Default::default()
            },
            // established timings (all @ 60Hz)
            EdidMode {
                xres: 1024,
                yres: 768,
                byte: 36,
                bit: 3,
                ..Default::default()
            },
            EdidMode {
                xres: 800,
                yres: 600,
                byte: 35,
                bit: 0,
                ..Default::default()
            },
            EdidMode {
                xres: 640,
                yres: 480,
                byte: 35,
                bit: 5,
                ..Default::default()
            },
        ];
        let mut std_offset: usize = 38;

        for mode in edid_modes {
            if (self.maxx != 0 && mode.xres > self.maxx)
                || (self.maxy != 0 && mode.yres > self.maxy)
            {
                continue;
            }

            if mode.byte != 0 {
                edid_array[mode.byte as usize] |= (1 << mode.bit) as u8;
            } else if mode.xtra3 != 0 && xtra3_offset != 0 {
                edid_array[xtra3_offset] |= (1 << mode.bit) as u8;
            } else if std_offset < 54
                && self.fullfill_std_mode(edid_array, std_offset, mode.xres, mode.yres) == 0
            {
                std_offset += 2;
            }

            if dta_offset != 0 && mode.dta != 0 {
                self.fullfill_ext_dta_mode(edid_array, dta_offset, mode.dta);
            }
        }

        while std_offset < 54 {
            self.fullfill_std_mode(edid_array, std_offset, 0, 0);
            std_offset += 2;
        }
    }

    fn fullfill_std_mode(
        &mut self,
        edid_array: &mut [u8],
        std_offset: usize,
        xres: u32,
        yres: u32,
    ) -> i32 {
        let aspect: u32;

        if xres == 0 || yres == 0 {
            edid_array[std_offset] = 0x01;
            edid_array[std_offset + 1] = 0x01;
            return 0;
        } else if xres * 10 == yres * 16 {
            aspect = 0;
        } else if xres * 3 == yres * 4 {
            aspect = 1;
        } else if xres * 4 == yres * 5 {
            aspect = 2;
        } else if xres * 9 == yres * 16 {
            aspect = 3;
        } else {
            return -1;
        }

        if (xres / 8) - 31 > 255 {
            return -1;
        }
        edid_array[std_offset] = ((xres / 8) - 31) as u8;
        edid_array[std_offset + 1] = (aspect << 6) as u8;
        0
    }

    fn fullfill_ext_dta_mode(&mut self, edid_array: &mut [u8], dta_offset: usize, dta: u32) {
        let index = edid_array[dta_offset + 2] as usize;
        edid_array[index] = dta as u8;
        edid_array[dta_offset + 2] += 1;
        edid_array[dta_offset + 4] += 1;
    }

    fn fullfill_checksum(&mut self, edid_array: &mut [u8]) {
        let mut sum: u32 = 0;
        for elem in edid_array.iter() {
            sum += *elem as u32;
        }
        sum &= 0xff;
        if sum != 0 {
            edid_array[127] = (0x100 - sum) as u8;
        }
    }
}
