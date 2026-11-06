use bytes::Bytes;

use crate::error::ProtoError;

/// Maximum length of a length-prefixed string inside a payload.
pub const MAX_STRING: usize = 4096;

pub struct Put {
    buf: Vec<u8>,
}

impl Put {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn str(&mut self, value: &str) -> Result<(), ProtoError> {
        if value.len() > MAX_STRING {
            return Err(ProtoError::TooLarge(value.len() as u32, MAX_STRING as u32));
        }
        self.u16(value.len() as u16);
        self.buf.extend_from_slice(value.as_bytes());
        Ok(())
    }

    pub fn finish(self) -> Bytes {
        Bytes::from(self.buf)
    }
}

impl Default for Put {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Take<'a> {
    data: &'a [u8],
    index: usize,
}

impl<'a> Take<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, index: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.index)
    }

    pub fn u8(&mut self) -> Result<u8, ProtoError> {
        if self.index >= self.data.len() {
            return Err(ProtoError::Truncated);
        }
        let value = self.data[self.index];
        self.index += 1;
        Ok(value)
    }

    pub fn u16(&mut self) -> Result<u16, ProtoError> {
        let bytes = self.take_array::<2>()?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn u32(&mut self) -> Result<u32, ProtoError> {
        let bytes = self.take_array::<4>()?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn u64(&mut self) -> Result<u64, ProtoError> {
        let bytes = self.take_array::<8>()?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn str(&mut self) -> Result<String, ProtoError> {
        let len = self.u16()? as usize;
        if len > MAX_STRING || self.remaining() < len {
            return Err(ProtoError::Truncated);
        }
        let start = self.index;
        self.index += len;
        let bytes = &self.data[start..self.index];
        String::from_utf8(bytes.to_vec()).map_err(|_| ProtoError::Utf8)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let start = self.index;
        self.index = self.data.len();
        &self.data[start..]
    }

    pub fn expect_exhausted(&self) -> Result<(), ProtoError> {
        if self.index != self.data.len() {
            return Err(ProtoError::Message(
                "unexpected trailing bytes in payload".into(),
            ));
        }
        Ok(())
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        if self.remaining() < N {
            return Err(ProtoError::Truncated);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.index..self.index + N]);
        self.index += N;
        Ok(out)
    }
}
