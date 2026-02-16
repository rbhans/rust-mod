use crate::encoding::Writer;
use crate::{DecodeError, EncodeError};

const fn build_crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u16;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 0x0001) != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const CRC16_TABLE: [u16; 256] = build_crc16_table();

pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for byte in data {
        let idx = ((crc ^ (*byte as u16)) & 0x00FF) as usize;
        crc = (crc >> 8) ^ CRC16_TABLE[idx];
    }
    crc
}

pub fn encode_frame(w: &mut Writer<'_>, address: u8, pdu: &[u8]) -> Result<(), EncodeError> {
    if pdu.is_empty() {
        return Err(EncodeError::InvalidLength);
    }

    w.write_u8(address)?;
    w.write_all(pdu)?;

    let mut tmp = [0u8; 254];
    if pdu.len() > 253 {
        return Err(EncodeError::ValueOutOfRange);
    }
    tmp[0] = address;
    tmp[1..1 + pdu.len()].copy_from_slice(pdu);
    let crc = crc16(&tmp[..1 + pdu.len()]);
    w.write_all(&crc.to_le_bytes())?;
    Ok(())
}

pub fn decode_frame(data: &[u8]) -> Result<(u8, &[u8]), DecodeError> {
    if data.len() < 4 {
        return Err(DecodeError::InvalidLength);
    }

    let payload = &data[..data.len() - 2];
    let expected = crc16(payload);
    let got = u16::from_le_bytes([data[data.len() - 2], data[data.len() - 1]]);
    if expected != got {
        return Err(DecodeError::InvalidCrc);
    }

    let address = payload[0];
    let pdu = &payload[1..];
    if pdu.is_empty() {
        return Err(DecodeError::InvalidLength);
    }
    Ok((address, pdu))
}

#[cfg(test)]
mod tests {
    use super::{crc16, decode_frame, encode_frame};
    use crate::encoding::Writer;
    use crate::DecodeError;

    #[test]
    fn crc16_known_vector() {
        let frame_wo_crc = [0x01u8, 0x03, 0x00, 0x00, 0x00, 0x0A];
        assert_eq!(crc16(&frame_wo_crc), 0xCDC5);
    }

    #[test]
    fn rtu_roundtrip() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        encode_frame(&mut w, 0x11, &[0x03, 0x00, 0x6B, 0x00, 0x03]).unwrap();
        let written = w.as_written();

        let (address, pdu) = decode_frame(written).unwrap();
        assert_eq!(address, 0x11);
        assert_eq!(pdu, &[0x03, 0x00, 0x6B, 0x00, 0x03]);
    }

    #[test]
    fn detects_bad_crc() {
        let bad = [0x11u8, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x00, 0x00];
        assert_eq!(decode_frame(&bad).unwrap_err(), DecodeError::InvalidCrc);
    }
}
