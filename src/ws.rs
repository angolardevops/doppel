//! WebSocket mínimo (RFC 6455) — só o necessário para o terminal: handshake,
//! leitura/escrita de frames. Sem dependências: SHA-1 e base64 implementados
//! aqui (são pequenos e ficam cobertos por testes com vetores conhecidos).

use std::io::{Read, Write};

/// GUID do RFC 6455 usado no cálculo de `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

// ---- SHA-1 (FIPS 180-1) ---------------------------------------------------

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ---- base64 ---------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18 & 63) as usize] as char);
        out.push(B64[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 { B64[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// `Sec-WebSocket-Accept` a partir do `Sec-WebSocket-Key` do cliente.
pub fn accept_key(client_key: &str) -> String {
    base64(&sha1(format!("{}{}", client_key.trim(), WS_GUID).as_bytes()))
}

// ---- frames ---------------------------------------------------------------

/// Lê um frame. `Ok(None)` = ligação terminada. Frames do cliente vêm mascarados.
pub fn read_frame(r: &mut impl Read) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut h = [0u8; 2];
    if r.read_exact(&mut h).is_err() {
        return Ok(None);
    }
    let opcode = h[0] & 0x0F;
    let masked = h[1] & 0x80 != 0;
    let mut len = (h[1] & 0x7F) as u64;
    if len == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b)?;
        len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8];
        r.read_exact(&mut b)?;
        len = u64::from_be_bytes(b);
    }
    // guarda contra frames absurdos (um teclado não envia 8 MB)
    if len > 8 * 1024 * 1024 {
        return Ok(None);
    }
    let mut mask = [0u8; 4];
    if masked {
        r.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        r.read_exact(&mut payload)?;
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(Some((opcode, payload)))
}

/// Escreve um frame (servidor → cliente: nunca mascarado).
pub fn write_frame(w: &mut impl Write, opcode: u8, data: &[u8]) -> std::io::Result<()> {
    let mut h = vec![0x80 | opcode];
    if data.len() < 126 {
        h.push(data.len() as u8);
    } else if data.len() <= 65535 {
        h.push(126);
        h.extend_from_slice(&(data.len() as u16).to_be_bytes());
    } else {
        h.push(127);
        h.extend_from_slice(&(data.len() as u64).to_be_bytes());
    }
    w.write_all(&h)?;
    w.write_all(data)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_vetores_conhecidos() {
        let hex = |b: [u8; 20]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        // vetores clássicos do FIPS 180-1
        assert_eq!(hex(sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // mensagem multi-bloco (exercita o padding)
        assert_eq!(hex(sha1(&[b'a'; 1000])), "291e9a6c66994949b57ba5e650361e98fc36b1ba");
    }

    #[test]
    fn base64_conhecido() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn handshake_do_rfc6455() {
        // exemplo textual do RFC 6455 §1.3
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn frames_ida_e_volta() {
        // escreve um frame e lê-o de volta (servidor→cliente, sem máscara)
        let mut buf = Vec::new();
        write_frame(&mut buf, OP_BINARY, b"ola mundo").unwrap();
        let (op, data) = read_frame(&mut buf.as_slice()).unwrap().unwrap();
        assert_eq!(op, OP_BINARY);
        assert_eq!(data, b"ola mundo");

        // payload médio (usa o campo de 16 bits)
        let big = vec![7u8; 5000];
        let mut buf = Vec::new();
        write_frame(&mut buf, OP_BINARY, &big).unwrap();
        let (_, data) = read_frame(&mut buf.as_slice()).unwrap().unwrap();
        assert_eq!(data.len(), 5000);
    }

    #[test]
    fn desmascara_frame_do_cliente() {
        // frame mascarado como o browser envia: "Hi" com máscara conhecida
        let mask = [0x37u8, 0xfa, 0x21, 0x3d];
        let payload = b"Hi";
        let masked: Vec<u8> = payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]).collect();
        let mut frame = vec![0x80 | OP_TEXT, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        frame.extend_from_slice(&masked);

        let (op, data) = read_frame(&mut frame.as_slice()).unwrap().unwrap();
        assert_eq!(op, OP_TEXT);
        assert_eq!(data, b"Hi", "o payload do cliente tem de ser desmascarado");
    }

    #[test]
    fn recusa_frame_absurdo() {
        // len de 64 bits gigante → recusado sem alocar
        let mut frame = vec![0x80 | OP_BINARY, 127];
        frame.extend_from_slice(&(u64::MAX).to_be_bytes());
        assert!(read_frame(&mut frame.as_slice()).unwrap().is_none());
    }
}
