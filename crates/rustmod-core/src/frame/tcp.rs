use crate::encoding::{Reader, Writer};
use crate::{DecodeError, EncodeError, UnitId};

/// Size of the MBAP header in bytes (transaction ID + protocol ID + length + unit ID).
pub const MBAP_HEADER_LEN: usize = 7;

/// Modbus Application Protocol (MBAP) header used in Modbus TCP framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbapHeader {
    pub transaction_id: u16,
    pub protocol_id: u16,
    /// Length includes unit-id byte + PDU length.
    pub length: u16,
    pub unit_id: UnitId,
}

impl MbapHeader {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.write_be_u16(self.transaction_id)?;
        w.write_be_u16(self.protocol_id)?;
        w.write_be_u16(self.length)?;
        w.write_u8(self.unit_id.as_u8())?;
        Ok(())
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let transaction_id = r.read_be_u16()?;
        let protocol_id = r.read_be_u16()?;
        let length = r.read_be_u16()?;
        let unit_id = UnitId::new(r.read_u8()?);

        if protocol_id != 0 {
            return Err(DecodeError::InvalidValue);
        }
        if length < 1 {
            return Err(DecodeError::InvalidLength);
        }

        Ok(Self {
            transaction_id,
            protocol_id,
            length,
            unit_id,
        })
    }
}

/// Encode a complete Modbus TCP frame (MBAP header + PDU) into the writer.
pub fn encode_frame(
    w: &mut Writer<'_>,
    transaction_id: u16,
    unit_id: UnitId,
    pdu: &[u8],
) -> Result<(), EncodeError> {
    let pdu_len_u16: u16 = pdu
        .len()
        .try_into()
        .map_err(|_| EncodeError::ValueOutOfRange)?;
    let length = pdu_len_u16
        .checked_add(1)
        .ok_or(EncodeError::ValueOutOfRange)?;

    let header = MbapHeader {
        transaction_id,
        protocol_id: 0,
        length,
        unit_id,
    };
    header.encode(w)?;
    w.write_all(pdu)?;
    Ok(())
}

/// Decode a complete Modbus TCP frame, returning the MBAP header and PDU slice.
pub fn decode_frame<'a>(r: &mut Reader<'a>) -> Result<(MbapHeader, &'a [u8]), DecodeError> {
    let header = MbapHeader::decode(r)?;
    let pdu_len = usize::from(header.length - 1);
    let pdu = r.read_exact(pdu_len)?;
    Ok((header, pdu))
}

#[cfg(test)]
mod tests {
    use super::{decode_frame, encode_frame, MbapHeader};
    use crate::encoding::{Reader, Writer};
    use crate::{DecodeError, UnitId};

    #[test]
    fn mbap_roundtrip() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        encode_frame(&mut w, 1, UnitId::new(2), &[0x03, 0x00, 0x6B, 0x00, 0x03]).unwrap();

        let mut r = Reader::new(w.as_written());
        let (header, pdu) = decode_frame(&mut r).unwrap();
        assert_eq!(
            header,
            MbapHeader {
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: UnitId::new(2),
            }
        );
        assert_eq!(pdu, &[0x03, 0x00, 0x6B, 0x00, 0x03]);
    }

    #[test]
    fn rejects_non_zero_protocol_id() {
        let bytes = [0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x01, 0x03];
        let mut r = Reader::new(&bytes);
        assert_eq!(decode_frame(&mut r).unwrap_err(), DecodeError::InvalidValue);
    }
}
