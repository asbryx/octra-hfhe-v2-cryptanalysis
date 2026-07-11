// ponytail: boundary report only; reuses original decoder logic
use std::{env, fs, process::Command};

struct Decoder<'a> {
    src: &'a [u8],
    pos: usize,
    lo: u32,
    hi: u32,
    code: u32,
    prev: usize,
    order: [u8; 256],
    ctx: Vec<u32>,
    rate: [u32; 256],
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        assert!(data.len() >= 5 && data[0] == 0xec);
        let mut d = Self {
            src: &data[5..],
            pos: 0,
            lo: 0,
            hi: u32::MAX,
            code: 0,
            prev: 0,
            order: [0x66; 256],
            ctx: vec![0; 1 << 16],
            rate: [0; 256],
        };
        for i in 0..(1 << 16) {
            let w = (i & 1) * 2
                + (i & 2)
                + ((i >> 2) & 1)
                + ((i >> 3) & 1)
                + ((i >> 4) & 1)
                + ((i >> 5) & 1)
                + ((i >> 6) & 1)
                + ((i >> 7) & 1)
                + 3;
            d.ctx[i] = ((w as u32) << 28) | 6;
        }
        for i in 0..256 {
            d.rate[i] = 32768 / (i as u32 * 2 + 3);
        }
        for _ in 0..4 {
            let b = d.next_src();
            d.code = d.code.wrapping_shl(8).wrapping_add(b as u32);
        }
        d
    }

    fn next_src(&mut self) -> u8 {
        if self.pos >= self.src.len() {
            return 0;
        }
        let b = self.src[self.pos];
        self.pos += 1;
        b
    }

    fn bit(&mut self) -> u8 {
        let state = (self.prev << 8) | self.order[self.prev] as usize;
        let value = self.ctx[state];
        let probability = value >> 16;
        let span = self.hi.wrapping_sub(self.lo);
        let mid = self
            .lo
            .wrapping_add((span >> 16).wrapping_mul(probability))
            .wrapping_add(((span & 0xffff).wrapping_mul(probability)) >> 16);
        let bit;
        if self.code <= mid {
            bit = 1;
            self.hi = mid;
        } else {
            bit = 0;
            self.lo = mid.wrapping_add(1);
        }

        let count = (value & 255) as usize;
        let p = (value >> 14) as i64;
        if count < 90 {
            let delta =
                (((bit as i64 * (1 << 18) - p) * self.rate[count] as i64) as u32) & 0xffffff00;
            self.ctx[state] = value.wrapping_add(1).wrapping_add(delta);
        }
        let old = self.order[self.prev];
        self.order[self.prev] = old.wrapping_add(old).wrapping_add(bit);
        self.prev = self.prev * 2 + bit as usize;
        if self.prev >= 256 {
            self.prev = 0;
        }

        while ((self.lo ^ self.hi) & 0xff000000) == 0 {
            self.lo = self.lo.wrapping_shl(8);
            self.hi = self.hi.wrapping_shl(8).wrapping_add(255);
            let b = self.next_src();
            self.code = self.code.wrapping_shl(8).wrapping_add(b as u32);
        }
        bit
    }

    fn byte(&mut self) -> Option<u8> {
        if self.bit() == 0 {
            return None;
        }
        let mut v: u16 = 1;
        while v < 256 {
            v = v * 2 + self.bit() as u16;
        }
        Some((v - 256) as u8)
    }
}

fn sha256_hex(path: &str) -> String {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

fn decode_report(packed: &[u8], label: &str) -> Result<(), String> {
    if packed.len() < 5 || packed[0] != 0xec {
        return Err("bad header".into());
    }
    let declared = u32::from_be_bytes(packed[1..5].try_into().unwrap()) as usize;
    let payload_len = packed.len() - 5;
    let mut decoder = Decoder::new(packed);
    let mut raw = Vec::with_capacity(declared);
    let mut after_raw_pos = 0usize;
    for i in 0..declared {
        match decoder.byte() {
            Some(b) => raw.push(b),
            None => return Err(format!("early eof at byte {}", i)),
        }
        if i + 1 == declared {
            after_raw_pos = decoder.pos;
        }
    }
    let eof = decoder.byte();
    let after_eof_pos = decoder.pos;
    let remaining = payload_len.saturating_sub(after_eof_pos);
    let suffix = if after_eof_pos < payload_len {
        &packed[5 + after_eof_pos..]
    } else {
        &[][..]
    };
    let raw_path = format!("local-temp/hfhe_boundary_{}.raw", label);
    fs::write(&raw_path, &raw).map_err(|e| e.to_string())?;
    let raw_sha = sha256_hex(&raw_path);
    println!("label={}", label);
    println!("packed_file_length={}", packed.len());
    println!("compressed_payload_length={}", payload_len);
    println!("declared_raw_length={}", declared);
    println!("decoder_src_pos_after_expected_raw={}", after_raw_pos);
    println!("decoder_src_pos_after_eof={}", after_eof_pos);
    println!("eof_is_none={}", eof.is_none());
    println!("physical_bytes_remaining_after_logical_eof={}", remaining);
    println!("remaining_suffix_len={}", suffix.len());
    print!("remaining_suffix_hex=");
    for b in suffix.iter().take(64) {
        print!("{:02x}", b);
    }
    println!();
    println!("raw_sha256={}", raw_sha);
    println!("raw_path={}", raw_path);
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(
        args.len() >= 2,
        "usage: hfhe_unpack_boundary packed.bin"
    );
    let path = &args[1];
    let packed = fs::read(path).unwrap();
    decode_report(&packed, "original").unwrap();

    // mutate last byte of packed file
    let mut m = packed.clone();
    let last = m.len() - 1;
    m[last] ^= 0x01;
    let mut_path = "local-temp/pk.bin.mut_last";
    fs::write(mut_path, &m).unwrap();
    match decode_report(&m, "mutated_last_byte") {
        Ok(()) => {}
        Err(e) => println!("label=mutated_last_byte error={}", e),
    }

    // if remaining is 0, also mutate a mid payload byte near end-1..end-8
    let mut m2 = packed.clone();
    let idx = m2.len().saturating_sub(8);
    m2[idx] ^= 0x01;
    fs::write("local-temp/pk.bin.mut_near_end", &m2).unwrap();
    match decode_report(&m2, "mutated_near_end") {
        Ok(()) => {}
        Err(e) => println!("label=mutated_near_end error={}", e),
    }
}
