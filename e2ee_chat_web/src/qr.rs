//! Pure-Rust ISO/IEC 18004 (Model 2) QR code encoder with SVG path and crisp PNG rendering.
//!
//! Used to share invitation links without any external JavaScript or canvas readback (which
//! anti-fingerprinting browsers can distort).

use std::io::Write;

use flate2::{Compression, write::ZlibEncoder};

/// Standard quiet zone width in modules around all four sides of a QR code (ISO/IEC 18004).
pub const QUIET_ZONE: usize = 4;

/// Target pixel width for exported PNG QR codes so they remain sharp when shared or printed.
const EXPORT_TARGET_PX: u32 = 512;

/// QR error correction level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Quartile and High are exercised by unit tests against the full ISO tables.
pub enum Ecc {
    Low = 0,
    Medium = 1,
    Quartile = 2,
    High = 3,
}

impl Ecc {
    /// Two-bit format indicator defined by ISO/IEC 18004 Table 12.
    const fn format_bits(self) -> u32 {
        match self {
            Self::Low => 1,
            Self::Medium => 0,
            Self::Quartile => 3,
            Self::High => 2,
        }
    }
}

/// Error returned when input data cannot fit into any QR code version (1..=40).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataTooLong;

/// A generated QR code symbol: a square grid of `size x size` dark/light modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrCode {
    size: usize,
    /// Row-major (`y * size + x`) module matrix (`true` = dark, `false` = light).
    modules: Vec<bool>,
}

impl QrCode {
    /// Encode `data` in Byte mode at error correction level `ecc`, selecting the smallest QR
    /// version (1..=40) that fits and the mask pattern with the lowest ISO/IEC 18004 penalty.
    pub fn encode(data: &[u8], ecc: Ecc) -> Result<Self, DataTooLong> {
        let version = (1u8..=40)
            .find(|&v| data_bits_fit(v, ecc, data.len()))
            .ok_or(DataTooLong)?;

        let data_codewords = encode_byte_mode(data, version, ecc);
        let all_codewords = add_ecc_and_interleave(&data_codewords, version, ecc);

        let size = usize::from(version) * 4 + 17;
        let mut base = Grid::new(size);
        base.draw_function_patterns(version, ecc);
        base.draw_codewords(&all_codewords);

        let mut best_modules = Vec::new();
        let mut best_penalty = u32::MAX;
        for mask in 0u8..8 {
            let mut candidate = base.clone();
            candidate.apply_mask(mask);
            candidate.draw_format_bits(ecc, mask);
            let penalty = candidate.penalty_score();
            if penalty < best_penalty {
                best_penalty = penalty;
                best_modules = candidate.modules;
            }
        }

        Ok(Self {
            size,
            modules: best_modules,
        })
    }

    /// Encode UTF-8 text using Medium (15%) error correction, falling back to Low (7%) if the
    /// payload exceeds Version 40 Medium capacity (2,331 bytes).
    pub fn encode_text(text: &str) -> Result<Self, DataTooLong> {
        Self::encode(text.as_bytes(), Ecc::Medium)
            .or_else(|_| Self::encode(text.as_bytes(), Ecc::Low))
    }

    /// QR symbol version (1..=40).
    #[cfg(test)]
    pub fn version(&self) -> u8 {
        ((self.size - 17) / 4) as u8
    }

    /// Width and height of the QR symbol in modules (excluding quiet zone).
    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Total width and height in modules, including `border` quiet-zone modules on each side.
    pub fn total_size(&self, border: usize) -> usize {
        self.size + border * 2
    }

    /// Whether the module at `(x, y)` is dark (`false` outside bounds).
    #[cfg(test)]
    pub fn get(&self, x: usize, y: usize) -> bool {
        x < self.size && y < self.size && self.modules[y * self.size + x]
    }

    /// Compact SVG `<path d="...">` data covering every dark module, shifted by `border` quiet-zone
    /// modules on each side, with horizontally adjacent dark modules merged into single runs.
    pub fn svg_path(&self, border: usize) -> String {
        use std::fmt::Write as _;

        let mut path = String::with_capacity(self.size * self.size * 2);
        for y in 0..self.size {
            let row = y * self.size;
            let mut x = 0;
            while x < self.size {
                if !self.modules[row + x] {
                    x += 1;
                    continue;
                }
                let start = x;
                while x < self.size && self.modules[row + x] {
                    x += 1;
                }
                let run = x - start;
                let _ = write!(path, "M{} {}h{run}v1h-{run}z", start + border, y + border);
            }
        }
        path
    }

    /// Render the QR code as a crisp, lossless 1-bit grayscale PNG with `border` quiet-zone modules
    /// and `module_px` pixels per module (`0` = black modules, `1` = white background), streaming
    /// one packed scanline at a time to keep peak WASM heap allocation minimal.
    fn to_png(&self, module_px: u32, border: usize) -> Vec<u8> {
        let scale = module_px.max(1) as usize;
        let total_modules = self.total_size(border);
        let img_dim = total_modules
            .checked_mul(scale)
            .expect("QR PNG dimension fits usize");
        let img_dim_u32 = u32::try_from(img_dim).expect("QR PNG dimension fits u32");

        let row_bytes = 1 + img_dim.div_ceil(8);
        let mut white_row = vec![0xFFu8; row_bytes];
        white_row[0] = 0; // PNG filter type 0 (None)

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        for _ in 0..(border * scale) {
            encoder.write_all(&white_row).expect("in-memory zlib write");
        }

        let mut row_buf = vec![0xFFu8; row_bytes];
        row_buf[0] = 0;
        for my in 0..self.size {
            row_buf[1..].fill(0xFF);
            let row = my * self.size;
            for mx in 0..self.size {
                if self.modules[row + mx] {
                    let px_start = (mx + border) * scale;
                    for px in px_start..px_start + scale {
                        let byte = 1 + (px >> 3);
                        let bit = 7 - (px & 7);
                        row_buf[byte] &= !(1u8 << bit);
                    }
                }
            }
            for _ in 0..scale {
                encoder.write_all(&row_buf).expect("in-memory zlib write");
            }
        }

        for _ in 0..(border * scale) {
            encoder.write_all(&white_row).expect("in-memory zlib write");
        }

        let idat = encoder.finish().expect("in-memory zlib finish");
        encode_gray1_png_from_idat(img_dim_u32, img_dim_u32, &idat)
    }

    /// Render a share-ready PNG scaled to roughly 512 px wide with the standard 4-module quiet zone.
    pub fn to_export_png(&self) -> Vec<u8> {
        let total = self.total_size(QUIET_ZONE) as u32;
        let module_px = (EXPORT_TARGET_PX / total).max(4);
        self.to_png(module_px, QUIET_ZONE)
    }
}

/// Number of raw data/ECC bits available in `version` (excluding function patterns).
const fn raw_module_count(version: u8) -> usize {
    let v = version as usize;
    let mut result = (16 * v + 128) * v + 64;
    if v >= 2 {
        let num_align = v / 7 + 2;
        result -= (25 * num_align - 10) * num_align - 55;
        if v >= 7 {
            result -= 36;
        }
    }
    result
}

/// Number of data codewords available for payload bits in `(version, ecc)`.
const fn num_data_codewords(version: u8, ecc: Ecc) -> usize {
    let v = version as usize;
    let e = ecc as usize;
    raw_module_count(version) / 8
        - (ECC_CODEWORDS_PER_BLOCK[e][v] as usize) * (NUM_ERROR_CORRECTION_BLOCKS[e][v] as usize)
}

/// Bit width of the Byte-mode character count indicator for `version`.
const fn byte_count_bits(version: u8) -> usize {
    if version <= 9 { 8 } else { 16 }
}

/// Whether `byte_len` bytes in Byte mode fit in `(version, ecc)`.
const fn data_bits_fit(version: u8, ecc: Ecc, byte_len: usize) -> bool {
    let count_bits = byte_count_bits(version);
    if byte_len >= (1usize << count_bits) {
        return false;
    }
    let needed_bits = 4 + count_bits + byte_len * 8;
    needed_bits <= num_data_codewords(version, ecc) * 8
}

/// Encode `data` in Byte mode (`0100`) and pad with terminator and alternating `0xEC`/`0x11` bytes.
fn encode_byte_mode(data: &[u8], version: u8, ecc: Ecc) -> Vec<u8> {
    let capacity_bytes = num_data_codewords(version, ecc);
    let capacity_bits = capacity_bytes * 8;
    let mut bits = BitBuffer::with_capacity(capacity_bits);

    bits.append(0b0100, 4);
    bits.append(data.len() as u32, byte_count_bits(version));
    for &byte in data {
        bits.append(u32::from(byte), 8);
    }

    // Terminator: up to 4 zero bits, then zero-pad to an 8-bit boundary.
    let terminator = (capacity_bits - bits.bit_len).min(4);
    bits.append(0, terminator);
    let pad_bits = (8 - (bits.bit_len % 8)) % 8;
    bits.append(0, pad_bits);

    let mut bytes = bits.into_bytes();
    let mut pad = 0xECu8;
    while bytes.len() < capacity_bytes {
        bytes.push(pad);
        pad = if pad == 0xEC { 0x11 } else { 0xEC };
    }
    bytes
}

struct BitBuffer {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl BitBuffer {
    fn with_capacity(bits: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(bits.div_ceil(8)),
            bit_len: 0,
        }
    }

    fn append(&mut self, value: u32, len: usize) {
        for shift in (0..len).rev() {
            if self.bit_len.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if ((value >> shift) & 1) != 0 {
                let last = self.bytes.last_mut().expect("pushed on byte boundary");
                *last |= 1 << (7 - (self.bit_len % 8));
            }
            self.bit_len += 1;
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Split `data` into ISO/IEC 18004 blocks, compute Reed-Solomon ECC bytes per block, and
/// interleave data and ECC codewords into the final codeword stream.
fn add_ecc_and_interleave(data: &[u8], version: u8, ecc: Ecc) -> Vec<u8> {
    let v = version as usize;
    let e = ecc as usize;
    let num_blocks = NUM_ERROR_CORRECTION_BLOCKS[e][v] as usize;
    let block_ecc_len = ECC_CODEWORDS_PER_BLOCK[e][v] as usize;
    let raw_codewords = raw_module_count(version) / 8;
    let num_short_blocks = num_blocks - (raw_codewords % num_blocks);
    let short_block_len = raw_codewords / num_blocks;
    let short_data_len = short_block_len - block_ecc_len;

    let divisor = rs_generator(block_ecc_len);
    let mut data_blocks: Vec<&[u8]> = Vec::with_capacity(num_blocks);
    let mut ecc_blocks: Vec<Vec<u8>> = Vec::with_capacity(num_blocks);

    let mut offset = 0;
    for i in 0..num_blocks {
        let len = short_data_len + usize::from(i >= num_short_blocks);
        let block = &data[offset..offset + len];
        offset += len;
        ecc_blocks.push(rs_remainder(block, &divisor));
        data_blocks.push(block);
    }

    let mut result = Vec::with_capacity(raw_codewords);
    for i in 0..=short_data_len {
        for (block_idx, block) in data_blocks.iter().enumerate() {
            if i < short_data_len || block_idx >= num_short_blocks {
                result.push(block[i]);
            }
        }
    }
    for i in 0..block_ecc_len {
        for block in &ecc_blocks {
            result.push(block[i]);
        }
    }
    result
}

/// Multiply two elements in GF(2^8) modulo `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`).
const fn gf_mul(x: u8, y: u8) -> u8 {
    let mut z = 0u8;
    let mut i = 7;
    loop {
        z = (z << 1) ^ ((z >> 7) * 0x1D);
        z ^= ((y >> i) & 1) * x;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    z
}

/// Compute Reed-Solomon generator polynomial `(x - a^0)(x - a^1)...(x - a^(degree-1))`, omitting
/// the implicit leading `x^degree` coefficient of `1`.
fn rs_generator(degree: usize) -> Vec<u8> {
    let mut coeffs = vec![0u8; degree];
    coeffs[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            coeffs[j] = gf_mul(coeffs[j], root);
            if j + 1 < degree {
                coeffs[j] ^= coeffs[j + 1];
            }
        }
        root = gf_mul(root, 0x02);
    }
    coeffs
}

/// Compute Reed-Solomon remainder of `data * x^degree` divided by `divisor`.
fn rs_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut rem = vec![0u8; divisor.len()];
    for &byte in data {
        let factor = byte ^ rem[0];
        rem.rotate_left(1);
        *rem.last_mut().expect("non-empty divisor") = 0;
        for (r, &d) in rem.iter_mut().zip(divisor.iter()) {
            *r ^= gf_mul(d, factor);
        }
    }
    rem
}

/// Compute center coordinates of alignment patterns along one axis for `version`.
fn alignment_pattern_positions(version: u8) -> Vec<usize> {
    if version == 1 {
        return Vec::new();
    }
    let num_align = usize::from(version / 7 + 2);
    let step = if version == 32 {
        26
    } else {
        ((usize::from(version) * 4 + num_align * 2 + 1) / (num_align * 2 - 2)) * 2
    };
    let mut result = Vec::with_capacity(num_align);
    result.push(6);
    let last = usize::from(version) * 4 + 10;
    let mut tail = Vec::with_capacity(num_align - 1);
    for k in 0..(num_align - 1) {
        tail.push(last - k * step);
    }
    tail.reverse();
    result.extend(tail);
    result
}

#[derive(Clone)]
struct Grid {
    size: usize,
    modules: Vec<bool>,
    is_function: Vec<bool>,
}

impl Grid {
    fn new(size: usize) -> Self {
        Self {
            size,
            modules: vec![false; size * size],
            is_function: vec![false; size * size],
        }
    }

    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        let idx = y * self.size + x;
        self.modules[idx] = dark;
        self.is_function[idx] = true;
    }

    fn draw_function_patterns(&mut self, version: u8, ecc: Ecc) {
        // Timing patterns along row 6 and column 6.
        for i in 0..self.size {
            self.set_function(6, i, i % 2 == 0);
            self.set_function(i, 6, i % 2 == 0);
        }

        // Three 7x7 finder patterns with 1-module light separators.
        let s = self.size;
        self.draw_finder(3, 3);
        self.draw_finder(s - 4, 3);
        self.draw_finder(3, s - 4);

        // Alignment patterns (versions 2..=40).
        let positions = alignment_pattern_positions(version);
        let n = positions.len();
        for (i, &cx) in positions.iter().enumerate() {
            for (j, &cy) in positions.iter().enumerate() {
                if (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0) {
                    continue;
                }
                self.draw_alignment(cx, cy);
            }
        }

        // Reserve format info modules (with dummy mask 0) and version info modules.
        self.draw_format_bits(ecc, 0);
        if version >= 7 {
            self.draw_version_bits(version);
        }
    }

    fn draw_finder(&mut self, cx: usize, cy: usize) {
        let size = self.size as isize;
        let cx = cx as isize;
        let cy = cy as isize;
        for dy in -4isize..=4 {
            for dx in -4isize..=4 {
                let x = cx + dx;
                let y = cy + dy;
                if (0..size).contains(&x) && (0..size).contains(&y) {
                    let dist = dx.abs().max(dy.abs());
                    self.set_function(x as usize, y as usize, dist != 2 && dist != 4);
                }
            }
        }
    }

    fn draw_alignment(&mut self, cx: usize, cy: usize) {
        let cx = cx as isize;
        let cy = cy as isize;
        for dy in -2isize..=2 {
            for dx in -2isize..=2 {
                let dist = dx.abs().max(dy.abs());
                self.set_function((cx + dx) as usize, (cy + dy) as usize, dist != 1);
            }
        }
    }

    fn draw_format_bits(&mut self, ecc: Ecc, mask: u8) {
        let data = (ecc.format_bits() << 3) | u32::from(mask);
        let mut rem = data;
        for _ in 0..10 {
            rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        }
        let bits = ((data << 10) | rem) ^ 0x5412;

        // First copy around the top-left finder.
        for i in 0..=5 {
            self.set_function(8, i, ((bits >> i) & 1) != 0);
        }
        self.set_function(8, 7, ((bits >> 6) & 1) != 0);
        self.set_function(8, 8, ((bits >> 7) & 1) != 0);
        self.set_function(7, 8, ((bits >> 8) & 1) != 0);
        for i in 9..15 {
            self.set_function(14 - i, 8, ((bits >> i) & 1) != 0);
        }

        // Second copy beside the top-right and bottom-left finders, plus fixed dark module.
        let s = self.size;
        for i in 0..8 {
            self.set_function(s - 1 - i, 8, ((bits >> i) & 1) != 0);
        }
        for i in 8..15 {
            self.set_function(8, s - 15 + i, ((bits >> i) & 1) != 0);
        }
        self.set_function(8, s - 8, true);
    }

    fn draw_version_bits(&mut self, version: u8) {
        let mut rem = u32::from(version);
        for _ in 0..12 {
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        }
        let bits = (u32::from(version) << 12) | rem;
        let s = self.size;
        for i in 0..18 {
            let dark = ((bits >> i) & 1) != 0;
            let a = s - 11 + (i % 3);
            let b = i / 3;
            self.set_function(a, b, dark);
            self.set_function(b, a, dark);
        }
    }

    fn draw_codewords(&mut self, codewords: &[u8]) {
        let total_bits = codewords.len() * 8;
        let mut bit_idx = 0usize;
        let mut right = self.size - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            let upward = ((right + 1) & 2) == 0;
            for vert in 0..self.size {
                let y = if upward { self.size - 1 - vert } else { vert };
                for j in 0..2 {
                    let x = right - j;
                    let idx = y * self.size + x;
                    if !self.is_function[idx] {
                        let dark = if bit_idx < total_bits {
                            ((codewords[bit_idx >> 3] >> (7 - (bit_idx & 7))) & 1) != 0
                        } else {
                            false
                        };
                        self.modules[idx] = dark;
                        bit_idx += 1;
                    }
                }
            }
            if right < 2 {
                break;
            }
            right -= 2;
        }
    }

    fn apply_mask(&mut self, mask: u8) {
        for y in 0..self.size {
            for x in 0..self.size {
                let idx = y * self.size + x;
                if self.is_function[idx] {
                    continue;
                }
                let invert = match mask {
                    0 => (x + y).is_multiple_of(2),
                    1 => y.is_multiple_of(2),
                    2 => x.is_multiple_of(3),
                    3 => (x + y).is_multiple_of(3),
                    4 => (x / 3 + y / 2).is_multiple_of(2),
                    5 => (x * y) % 2 + (x * y) % 3 == 0,
                    6 => ((x * y) % 2 + (x * y) % 3).is_multiple_of(2),
                    7 => ((x + y) % 2 + (x * y) % 3).is_multiple_of(2),
                    _ => unreachable!("mask is in 0..8"),
                };
                if invert {
                    self.modules[idx] = !self.modules[idx];
                }
            }
        }
    }

    /// ISO/IEC 18004 Section 7.8.3.1 mask evaluation penalty score.
    fn penalty_score(&self) -> u32 {
        let s = self.size;
        let mut penalty = 0u32;

        // Rule 1 & Rule 3 across rows.
        for y in 0..s {
            let row = y * s;
            let mut run_color = false;
            let mut run_len = 0u32;
            let mut window = 0u16;
            for x in 0..s {
                let dark = self.modules[row + x];
                if x == 0 || dark != run_color {
                    if run_len >= 5 {
                        penalty += run_len - 2;
                    }
                    run_color = dark;
                    run_len = 1;
                } else {
                    run_len += 1;
                }
                window = ((window << 1) | u16::from(dark)) & 0x07FF;
                if x >= 10 && (window == 0b10111010000 || window == 0b00001011101) {
                    penalty += 40;
                }
            }
            if run_len >= 5 {
                penalty += run_len - 2;
            }
        }

        // Rule 1 & Rule 3 across columns.
        for x in 0..s {
            let mut run_color = false;
            let mut run_len = 0u32;
            let mut window = 0u16;
            for y in 0..s {
                let dark = self.modules[y * s + x];
                if y == 0 || dark != run_color {
                    if run_len >= 5 {
                        penalty += run_len - 2;
                    }
                    run_color = dark;
                    run_len = 1;
                } else {
                    run_len += 1;
                }
                window = ((window << 1) | u16::from(dark)) & 0x07FF;
                if y >= 10 && (window == 0b10111010000 || window == 0b00001011101) {
                    penalty += 40;
                }
            }
            if run_len >= 5 {
                penalty += run_len - 2;
            }
        }

        // Rule 2: 2x2 blocks of identical color.
        for y in 0..s - 1 {
            let r0 = y * s;
            let r1 = (y + 1) * s;
            for x in 0..s - 1 {
                let c = self.modules[r0 + x];
                if c == self.modules[r0 + x + 1]
                    && c == self.modules[r1 + x]
                    && c == self.modules[r1 + x + 1]
                {
                    penalty += 3;
                }
            }
        }

        // Rule 4: balance of dark and light modules.
        let dark = self.modules.iter().filter(|&&m| m).count();
        let total = s * s;
        let diff = (dark * 20).abs_diff(total * 10);
        let k = diff.saturating_sub(1) / total;
        penalty += (k as u32) * 10;

        penalty
    }
}

/// Assemble a valid 1-bit grayscale PNG image from zlib-compressed `IDAT` payload bytes.
fn encode_gray1_png_from_idat(width: u32, height: u32, idat: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + idat.len());
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n']);

    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 1; // 1-bit depth
    ihdr[9] = 0; // grayscale
    write_png_chunk(&mut out, *b"IHDR", &ihdr);
    write_png_chunk(&mut out, *b"IDAT", idat);
    write_png_chunk(&mut out, *b"IEND", &[]);
    out
}

fn write_png_chunk(out: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&kind);
    out.extend_from_slice(data);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&kind);
    hasher.update(data);
    out.extend_from_slice(&hasher.finalize().to_be_bytes());
}

// ISO/IEC 18004 Table 9: ECC codewords per block, indexed by [ecc][version] (version 0 unused).
const ECC_CODEWORDS_PER_BLOCK: [[u8; 41]; 4] = [
    // Low
    [
        0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28,
        30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    // Medium
    [
        0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ],
    // Quartile
    [
        0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30,
        30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    // High
    [
        0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
];

// ISO/IEC 18004 Table 9: Number of error-correction blocks, indexed by [ecc][version].
const NUM_ERROR_CORRECTION_BLOCKS: [[u8; 41]; 4] = [
    // Low
    [
        0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13,
        14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
    ],
    // Medium
    [
        0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21,
        23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ],
    // Quartile
    [
        0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29,
        34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68,
    ],
    // High
    [
        0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32,
        35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_typical_invitation_link_with_valid_structure() {
        let link = "https://chat.example.com/#chat=OjpcOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo&name=Alice&pq=1";
        let qr = QrCode::encode_text(link).expect("fits in QR");
        assert_eq!(qr.version(), 6);
        assert_eq!(qr.size(), 41);
        assert_eq!(qr.total_size(QUIET_ZONE), 49);

        // Finder pattern centers (top-left, top-right, bottom-left) are dark.
        assert!(qr.get(3, 3));
        assert!(qr.get(qr.size() - 4, 3));
        assert!(qr.get(3, qr.size() - 4));
        // Fixed dark module at (8, size - 8).
        assert!(qr.get(8, qr.size() - 8));

        let path = qr.svg_path(QUIET_ZONE);
        assert!(path.starts_with('M'));
        assert!(path.ends_with('z'));

        let png = qr.to_export_png();
        assert_eq!(
            &png[..8],
            &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n']
        );
        assert_eq!(&png[12..16], b"IHDR");
        let width = u32::from_be_bytes(png[16..20].try_into().unwrap());
        let height = u32::from_be_bytes(png[20..24].try_into().unwrap());
        assert_eq!(width, height);
        assert!((450..=540).contains(&width));
    }

    #[test]
    fn rejects_payload_exceeding_version_40_capacity() {
        let medium_overflow = "a".repeat(2_500);
        assert_eq!(
            QrCode::encode(medium_overflow.as_bytes(), Ecc::Medium),
            Err(DataTooLong)
        );
        // `encode_text` falls back to Low ECC (max 2,953 bytes) for oversized payloads.
        let qr = QrCode::encode_text(&medium_overflow).expect("fits at Low ECC");
        assert_eq!(qr.version(), 37);

        let low_overflow = "a".repeat(2_954);
        assert_eq!(QrCode::encode_text(&low_overflow), Err(DataTooLong));
    }

    #[test]
    fn encodes_empty_payload_as_version_1() {
        let qr = QrCode::encode_text("").expect("empty fits in V1");
        assert_eq!(qr.version(), 1);
        assert_eq!(qr.size(), 21);
        assert!(!qr.svg_path(QUIET_ZONE).is_empty());
        assert!(!qr.to_export_png().is_empty());
    }

    #[test]
    fn svg_path_covers_exact_dark_module_count() {
        let qr = QrCode::encode_text("https://chat.example.com/#chat=abc").expect("fits");
        let dark_count = qr.modules.iter().filter(|&&m| m).count();
        let path = qr.svg_path(QUIET_ZONE);
        let covered: usize = path
            .split('M')
            .skip(1)
            .map(|seg| {
                let after_h = seg.split_once('h').unwrap().1;
                let run_str = after_h.split_once('v').unwrap().0;
                run_str.parse::<usize>().unwrap()
            })
            .sum();
        assert_eq!(covered, dark_count);
    }

    #[test]
    fn alignment_positions_match_iso_spec_edge_versions() {
        assert_eq!(alignment_pattern_positions(1), Vec::<usize>::new());
        assert_eq!(alignment_pattern_positions(2), vec![6, 18]);
        assert_eq!(alignment_pattern_positions(7), vec![6, 22, 38]);
        assert_eq!(alignment_pattern_positions(14), vec![6, 26, 46, 66]);
        assert_eq!(
            alignment_pattern_positions(32),
            vec![6, 34, 60, 86, 112, 138]
        );
        assert_eq!(
            alignment_pattern_positions(40),
            vec![6, 30, 58, 86, 114, 142, 170]
        );
    }

    #[test]
    fn capacities_match_iso_table_for_boundary_versions() {
        // ISO/IEC 18004 Table 7 byte-mode capacities:
        // V1: L=17, M=14, Q=11, H=7
        assert!(data_bits_fit(1, Ecc::Low, 17));
        assert!(!data_bits_fit(1, Ecc::Low, 18));
        assert!(data_bits_fit(1, Ecc::Medium, 14));
        assert!(!data_bits_fit(1, Ecc::Medium, 15));
        assert!(data_bits_fit(1, Ecc::Quartile, 11));
        assert!(!data_bits_fit(1, Ecc::Quartile, 12));
        assert!(data_bits_fit(1, Ecc::High, 7));
        assert!(!data_bits_fit(1, Ecc::High, 8));

        // V9 (8-bit count) -> V10 (16-bit count) transition:
        // V9-M = 180 bytes, V10-M = 213 bytes
        assert!(data_bits_fit(9, Ecc::Medium, 180));
        assert!(!data_bits_fit(9, Ecc::Medium, 181));
        assert!(data_bits_fit(10, Ecc::Medium, 213));
        assert!(!data_bits_fit(10, Ecc::Medium, 214));

        // V40: L=2953, M=2331, Q=1663, H=1273
        assert!(data_bits_fit(40, Ecc::Low, 2953));
        assert!(!data_bits_fit(40, Ecc::Low, 2954));
        assert!(data_bits_fit(40, Ecc::Medium, 2331));
        assert!(!data_bits_fit(40, Ecc::Medium, 2332));
        assert!(data_bits_fit(40, Ecc::Quartile, 1663));
        assert!(!data_bits_fit(40, Ecc::Quartile, 1664));
        assert!(data_bits_fit(40, Ecc::High, 1273));
        assert!(!data_bits_fit(40, Ecc::High, 1274));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn decode_png_qr(png_bytes: &[u8], expected_border_px: usize) -> (rqrr::MetaData, Vec<u8>) {
        let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
        let mut reader = decoder.read_info().expect("valid PNG header");
        let buf_len = reader.output_buffer_size().expect("PNG output buffer size");
        let mut raw = vec![0u8; buf_len];
        let info = reader.next_frame(&mut raw).expect("decode PNG frame");
        reader.finish().expect("valid PNG trailer");
        assert_eq!(info.color_type, png::ColorType::Grayscale);
        assert_eq!(info.bit_depth, png::BitDepth::One);
        assert_eq!(info.width, info.height, "QR PNG must be square");

        let dim = info.width as usize;
        let stride = info.line_size;
        let mut luma = Vec::with_capacity(dim * dim);
        for y in 0..dim {
            let row = &raw[y * stride..(y + 1) * stride];
            for x in 0..dim {
                let bit = (row[x >> 3] >> (7 - (x & 7))) & 1;
                luma.push(if bit == 0 { 0u8 } else { 255u8 });
            }
        }

        // Verify the entire quiet zone border is white on all four sides.
        for y in 0..dim {
            for x in 0..dim {
                if y < expected_border_px
                    || y >= dim - expected_border_px
                    || x < expected_border_px
                    || x >= dim - expected_border_px
                {
                    assert_eq!(
                        luma[y * dim + x],
                        255,
                        "quiet zone pixel ({x}, {y}) must be white"
                    );
                }
            }
        }

        let mut prepared =
            rqrr::PreparedImage::prepare_from_greyscale(dim, dim, |x, y| luma[y * dim + x]);
        let grids = prepared.detect_grids();
        assert_eq!(
            grids.len(),
            1,
            "expected exactly 1 QR grid in {dim}x{dim} PNG"
        );
        let mut out = Vec::new();
        let meta = grids[0].decode_to(&mut out).expect("decode QR payload");
        (meta, out)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn export_scale(qr: &QrCode) -> usize {
        let total = qr.total_size(QUIET_ZONE) as u32;
        (EXPORT_TARGET_PX / total).max(4) as usize
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn max_byte_payload(version: u8, ecc: Ecc) -> String {
        let overhead_bits = 4 + byte_count_bits(version);
        let max_bytes = (num_data_codewords(version, ecc) * 8 - overhead_bits) / 8;
        let tag = format!("v{version:02}-{ecc:?}-");
        let mut payload = String::with_capacity(max_bytes);
        while payload.len() < max_bytes {
            let rem = max_bytes - payload.len();
            payload.push_str(&tag[..rem.min(tag.len())]);
        }
        payload
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn pure_rust_decodes_invitation_links_and_export_pngs() {
        use session::PqConfig;

        use crate::{
            engine::{build_invitation_link, parse_invitation_hash},
            state::{Dialog, Me, ServerPqStatus},
            util::key_to_url,
        };

        // 1. Full end-to-end invitation links (default server, custom server, Unicode name, PQ on/off).
        let key = [0x5Au8; 32];
        let me_default = Me {
            name: "Alice & 爱丽丝".to_string(),
            key,
            server: "https://chat.example.com".to_string(),
            pq_config: PqConfig::default(),
            server_pq: ServerPqStatus::Unknown,
        };
        let me_custom = Me {
            name: "Bob".to_string(),
            key,
            server: "https://relay.example.org".to_string(),
            pq_config: PqConfig::default(),
            server_pq: ServerPqStatus::Disabled,
        };
        let invite_default = build_invitation_link("https://chat.example.com", &me_default);
        let invite_custom = build_invitation_link("https://chat.example.com", &me_custom);

        let qr_default = QrCode::encode_text(&invite_default).expect("encode default invite");
        let (meta_default, raw_default) = decode_png_qr(
            &qr_default.to_export_png(),
            QUIET_ZONE * export_scale(&qr_default),
        );
        let decoded_default = String::from_utf8(raw_default).expect("valid utf-8 invite");
        assert_eq!(decoded_default, invite_default);
        assert_eq!(meta_default.version.0, usize::from(qr_default.version()));
        assert_eq!(meta_default.ecc_level, Ecc::Medium.format_bits() as u16);

        let (_, hash_default) = decoded_default.split_once('#').expect("fragment");
        assert_eq!(
            parse_invitation_hash(hash_default),
            Some(Dialog::NewChat {
                key: key_to_url(&key),
                name: "Alice & 爱丽丝".to_string(),
                server: None,
                pq_pinned: me_default.pq_config.pq_enabled
                    && !me_default.pq_config.offered_suites().is_empty(),
            })
        );

        let qr_custom = QrCode::encode_text(&invite_custom).expect("encode custom invite");
        let (meta_custom, raw_custom) = decode_png_qr(
            &qr_custom.to_export_png(),
            QUIET_ZONE * export_scale(&qr_custom),
        );
        let decoded_custom = String::from_utf8(raw_custom).expect("valid utf-8 invite");
        assert_eq!(decoded_custom, invite_custom);
        assert_eq!(meta_custom.version.0, usize::from(qr_custom.version()));
        assert_eq!(meta_custom.ecc_level, Ecc::Medium.format_bits() as u16);

        let (_, hash_custom) = decoded_custom.split_once('#').expect("fragment");
        assert_eq!(
            parse_invitation_hash(hash_custom),
            Some(Dialog::NewChat {
                key: key_to_url(&key),
                name: "Bob".to_string(),
                server: Some("https://relay.example.org".to_string()),
                pq_pinned: false,
            })
        );

        // 2. Oversized text exceeding V40 Medium (2,331 bytes) falls back to Low ECC.
        let long_payload = "inv=".to_string() + &"x".repeat(2_496);
        let qr_fallback = QrCode::encode_text(&long_payload).expect("fits at Low ECC");
        let (meta_fallback, raw_fallback) = decode_png_qr(
            &qr_fallback.to_export_png(),
            QUIET_ZONE * export_scale(&qr_fallback),
        );
        assert_eq!(raw_fallback, long_payload.as_bytes());
        assert_eq!(meta_fallback.version.0, usize::from(qr_fallback.version()));
        assert_eq!(meta_fallback.ecc_level, Ecc::Low.format_bits() as u16);

        // 3. Raw arbitrary binary payload (all 256 byte values) via `QrCode::encode`.
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let qr_binary = QrCode::encode(&all_bytes, Ecc::Medium).expect("encode binary");
        let (meta_binary, raw_binary) = decode_png_qr(
            &qr_binary.to_export_png(),
            QUIET_ZONE * export_scale(&qr_binary),
        );
        assert_eq!(raw_binary, all_bytes);
        assert_eq!(meta_binary.version.0, usize::from(qr_binary.version()));
        assert_eq!(meta_binary.ecc_level, Ecc::Medium.format_bits() as u16);

        // 4. Empty payload across all 4 ECC levels via `to_export_png()`.
        for ecc in [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High] {
            let qr = QrCode::encode(b"", ecc).expect("encode empty");
            assert_eq!(qr.version(), 1);
            let (meta, raw) = decode_png_qr(&qr.to_export_png(), QUIET_ZONE * export_scale(&qr));
            assert!(raw.is_empty(), "expected empty payload for {ecc:?}");
            assert_eq!(meta.version.0, 1);
            assert_eq!(meta.ecc_level, ecc.format_bits() as u16);
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn pure_rust_decodes_to_png_across_scale_factors() {
        let payloads = [
            (
                "https://chat.example.com/#chat=OjpcOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo&name=Alice&pq=1"
                    .to_string(),
                Ecc::Medium,
            ),
            (max_byte_payload(10, Ecc::Quartile), Ecc::Quartile),
        ];

        for (payload, ecc) in payloads {
            let qr = QrCode::encode(payload.as_bytes(), ecc).expect("encode");
            for module_px in [2u32, 3, 4, 6, 8] {
                let png = qr.to_png(module_px, QUIET_ZONE);
                let (meta, raw) = decode_png_qr(&png, QUIET_ZONE * module_px as usize);
                assert_eq!(
                    raw,
                    payload.as_bytes(),
                    "round-trip mismatch for v{} {ecc:?} at scale {module_px}",
                    qr.version()
                );
                assert_eq!(meta.version.0, usize::from(qr.version()));
                assert_eq!(meta.ecc_level, ecc.format_bits() as u16);
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_all_versions_decode_for_ecc(ecc: Ecc) {
        // Cover every ISO/IEC 18004 version 1..=40 at exact max byte capacity, using
        // `to_export_png()` on key structural boundaries (V1, V7, V10, V32, V40) and
        // `to_png(2, QUIET_ZONE)` across all other versions.
        let export_boundaries = [1u8, 7, 10, 32, 40];
        for version in 1u8..=40 {
            let payload = max_byte_payload(version, ecc);
            let qr = QrCode::encode(payload.as_bytes(), ecc).expect("encode");
            assert_eq!(qr.version(), version);

            let (png, border_px) = if export_boundaries.contains(&version) {
                (qr.to_export_png(), QUIET_ZONE * export_scale(&qr))
            } else {
                (qr.to_png(2, QUIET_ZONE), QUIET_ZONE * 2)
            };

            let (meta, raw) = decode_png_qr(&png, border_px);
            assert_eq!(
                raw,
                payload.as_bytes(),
                "round-trip mismatch for v{version} {ecc:?}"
            );
            assert_eq!(meta.version.0, usize::from(version));
            assert_eq!(meta.ecc_level, ecc.format_bits() as u16);
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn pure_rust_decodes_all_versions_ecc_low() {
        assert_all_versions_decode_for_ecc(Ecc::Low);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn pure_rust_decodes_all_versions_ecc_medium() {
        assert_all_versions_decode_for_ecc(Ecc::Medium);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn pure_rust_decodes_all_versions_ecc_quartile() {
        assert_all_versions_decode_for_ecc(Ecc::Quartile);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn pure_rust_decodes_all_versions_ecc_high() {
        assert_all_versions_decode_for_ecc(Ecc::High);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    #[ignore = "requires system zbarimg binary; pure-Rust decode tests run unconditionally"]
    fn zbarimg_decodes_generated_pngs_interop() {
        use std::process::Command;

        use session::PqConfig;

        use crate::{
            engine::{build_invitation_link, parse_invitation_hash},
            state::{Dialog, Me, ServerPqStatus},
            util::key_to_url,
        };

        let dir = std::env::temp_dir().join(format!("ratchetx2-qr-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let mut expected: Vec<(String, u8, Ecc)> = Vec::new();
        let mut paths = Vec::new();

        let key = [0x5Au8; 32];
        let me_default = Me {
            name: "Alice & 爱丽丝".to_string(),
            key,
            server: "https://chat.example.com".to_string(),
            pq_config: PqConfig::default(),
            server_pq: ServerPqStatus::Unknown,
        };
        let me_custom = Me {
            name: "Bob".to_string(),
            key,
            server: "https://relay.example.org".to_string(),
            pq_config: PqConfig::default(),
            server_pq: ServerPqStatus::Disabled,
        };
        let invite_default = build_invitation_link("https://chat.example.com", &me_default);
        let invite_custom = build_invitation_link("https://chat.example.com", &me_custom);
        for (idx, link) in [&invite_default, &invite_custom].iter().enumerate() {
            let qr = QrCode::encode_text(link).expect("encode invitation link");
            let path = dir.join(format!("invite-{idx}.png"));
            std::fs::write(&path, qr.to_export_png()).expect("write export png");
            expected.push(((*link).clone(), qr.version(), Ecc::Medium));
            paths.push(path);
        }

        let eccs = [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High];
        for version in [1u8, 7, 10, 32, 36, 40] {
            for ecc in eccs {
                let payload = max_byte_payload(version, ecc);
                let qr = QrCode::encode(payload.as_bytes(), ecc).expect("encode");
                assert_eq!(qr.version(), version);
                let path = dir.join(format!("v{version:02}-{}.png", ecc as u8));
                std::fs::write(&path, qr.to_png(3, QUIET_ZONE)).expect("write png");
                expected.push((payload, version, ecc));
                paths.push(path);
            }
        }

        let out = Command::new("zbarimg")
            .args(["--quiet", "--raw", "-Sdisable", "-Sqrcode.enable"])
            .args(&paths)
            .output()
            .expect("zbarimg must be installed to run this ignored interop test");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            out.status.success(),
            "zbarimg failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).expect("utf8");
        let decoded: Vec<&str> = stdout.lines().collect();
        assert_eq!(decoded.len(), expected.len());
        for ((want, version, ecc), got) in expected.iter().zip(decoded.iter()) {
            assert_eq!(got, want, "round-trip mismatch for v{version} {ecc:?}");
        }

        let (_, hash_default) = decoded[0].split_once('#').expect("fragment");
        assert_eq!(
            parse_invitation_hash(hash_default),
            Some(Dialog::NewChat {
                key: key_to_url(&key),
                name: "Alice & 爱丽丝".to_string(),
                server: None,
                pq_pinned: me_default.pq_config.pq_enabled
                    && !me_default.pq_config.offered_suites().is_empty(),
            })
        );
        let (_, hash_custom) = decoded[1].split_once('#').expect("fragment");
        assert_eq!(
            parse_invitation_hash(hash_custom),
            Some(Dialog::NewChat {
                key: key_to_url(&key),
                name: "Bob".to_string(),
                server: Some("https://relay.example.org".to_string()),
                pq_pinned: false,
            })
        );
    }
}
