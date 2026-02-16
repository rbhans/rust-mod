use crate::DecodeError;

/// A zero-copy reader that advances through a byte slice.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub const fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn peek_u8(&self) -> Result<u8, DecodeError> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::UnexpectedEof)
    }

    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let byte = self.peek_u8()?;
        self.pos += 1;
        Ok(byte)
    }

    pub fn read_exact(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < len {
            return Err(DecodeError::UnexpectedEof);
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.buf[start..start + len])
    }

    pub fn read_be_u16(&mut self) -> Result<u16, DecodeError> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;
    use crate::DecodeError;

    #[test]
    fn reader_reads_values() {
        let mut r = Reader::new(&[1, 2, 3, 4]);
        assert_eq!(r.read_u8().unwrap(), 1);
        assert_eq!(r.read_exact(2).unwrap(), &[2, 3]);
        assert_eq!(r.read_be_u16().unwrap_err(), DecodeError::UnexpectedEof);
    }

    #[test]
    fn reader_position_and_remaining() {
        let mut r = Reader::new(&[0x12, 0x34, 0x56]);
        assert_eq!(r.position(), 0);
        assert_eq!(r.remaining(), 3);
        assert_eq!(r.peek_u8().unwrap(), 0x12);
        assert_eq!(r.read_u8().unwrap(), 0x12);
        assert_eq!(r.position(), 1);
        assert_eq!(r.read_be_u16().unwrap(), 0x3456);
        assert!(r.is_empty());
    }
}
