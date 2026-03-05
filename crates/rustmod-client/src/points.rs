use crate::{ClientError, InvalidResponseKind};

/// A local cache of coil values mapped to their Modbus addresses.
///
/// Use [`apply_read`](CoilPoints::apply_read) to merge values returned by
/// [`ModbusClient::read_coils`](crate::ModbusClient::read_coils).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoilPoints {
    start_address: u16,
    values: Vec<bool>,
}

impl CoilPoints {
    /// Create a new coil cache with `count` coils starting at `start_address`, all initially `false`.
    #[must_use]
    pub fn new(start_address: u16, count: usize) -> Self {
        Self {
            start_address,
            values: vec![false; count],
        }
    }

    /// Create a coil cache from existing values.
    #[must_use]
    pub fn from_values(start_address: u16, values: Vec<bool>) -> Self {
        Self {
            start_address,
            values,
        }
    }

    /// The starting Modbus address of this cache.
    pub fn start_address(&self) -> u16 {
        self.start_address
    }

    /// The number of coils in this cache.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if the cache contains no coils.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// View the raw coil values as a slice.
    pub fn values(&self) -> &[bool] {
        &self.values
    }

    /// Get the coil value at the given Modbus address, or `None` if out of range.
    pub fn get(&self, address: u16) -> Option<bool> {
        let offset = usize::from(address.checked_sub(self.start_address)?);
        self.values.get(offset).copied()
    }

    /// Set the coil value at the given Modbus address.
    pub fn set(&mut self, address: u16, value: bool) -> Result<(), ClientError> {
        let offset = usize::from(
            address
                .checked_sub(self.start_address)
                .ok_or(ClientError::InvalidResponse(InvalidResponseKind::Other("coil address out of range")))?,
        );
        let slot = self
            .values
            .get_mut(offset)
            .ok_or(ClientError::InvalidResponse(InvalidResponseKind::Other("coil address out of range")))?;
        *slot = value;
        Ok(())
    }

    /// Merge a batch of read values into this cache at the given start address.
    pub fn apply_read(&mut self, start_address: u16, values: &[bool]) -> Result<(), ClientError> {
        for (i, value) in values.iter().copied().enumerate() {
            let offset = u16::try_from(i)
                .map_err(|_| ClientError::InvalidResponse(InvalidResponseKind::Other("coil address overflow")))?;
            let addr = start_address
                .checked_add(offset)
                .ok_or(ClientError::InvalidResponse(InvalidResponseKind::Other("coil address overflow")))?;
            self.set(addr, value)?;
        }
        Ok(())
    }
}

/// A local cache of 16-bit register values mapped to their Modbus addresses.
///
/// Use [`apply_read`](RegisterPoints::apply_read) to merge values returned by
/// [`ModbusClient::read_holding_registers`](crate::ModbusClient::read_holding_registers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterPoints {
    start_address: u16,
    values: Vec<u16>,
}

impl RegisterPoints {
    /// Create a new register cache with `count` registers starting at `start_address`, all initially `0`.
    #[must_use]
    pub fn new(start_address: u16, count: usize) -> Self {
        Self {
            start_address,
            values: vec![0; count],
        }
    }

    /// Create a register cache from existing values.
    #[must_use]
    pub fn from_values(start_address: u16, values: Vec<u16>) -> Self {
        Self {
            start_address,
            values,
        }
    }

    /// The starting Modbus address of this cache.
    pub fn start_address(&self) -> u16 {
        self.start_address
    }

    /// The number of registers in this cache.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if the cache contains no registers.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// View the raw register values as a slice.
    pub fn values(&self) -> &[u16] {
        &self.values
    }

    /// Get the register value at the given Modbus address, or `None` if out of range.
    pub fn get(&self, address: u16) -> Option<u16> {
        let offset = usize::from(address.checked_sub(self.start_address)?);
        self.values.get(offset).copied()
    }

    /// Set the register value at the given Modbus address.
    pub fn set(&mut self, address: u16, value: u16) -> Result<(), ClientError> {
        let offset = usize::from(
            address
                .checked_sub(self.start_address)
                .ok_or(ClientError::InvalidResponse(InvalidResponseKind::Other("register address out of range")))?,
        );
        let slot = self
            .values
            .get_mut(offset)
            .ok_or(ClientError::InvalidResponse(InvalidResponseKind::Other("register address out of range")))?;
        *slot = value;
        Ok(())
    }

    /// Merge a batch of read values into this cache at the given start address.
    pub fn apply_read(&mut self, start_address: u16, values: &[u16]) -> Result<(), ClientError> {
        for (i, value) in values.iter().copied().enumerate() {
            let offset = u16::try_from(i)
                .map_err(|_| ClientError::InvalidResponse(InvalidResponseKind::Other("register address overflow")))?;
            let addr = start_address
                .checked_add(offset)
                .ok_or(ClientError::InvalidResponse(InvalidResponseKind::Other("register address overflow")))?;
            self.set(addr, value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CoilPoints, RegisterPoints};

    #[test]
    fn coil_points_apply_read() {
        let mut points = CoilPoints::new(10, 4);
        points.apply_read(11, &[true, false]).unwrap();
        assert_eq!(points.get(10), Some(false));
        assert_eq!(points.get(11), Some(true));
        assert_eq!(points.get(12), Some(false));
    }

    #[test]
    fn register_points_apply_read() {
        let mut points = RegisterPoints::new(100, 3);
        points.apply_read(100, &[10, 20, 30]).unwrap();
        assert_eq!(points.get(101), Some(20));
        points.set(102, 42).unwrap();
        assert_eq!(points.get(102), Some(42));
    }
}
