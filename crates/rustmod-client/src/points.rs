use crate::ClientError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoilPoints {
    start_address: u16,
    values: Vec<bool>,
}

impl CoilPoints {
    pub fn new(start_address: u16, count: usize) -> Self {
        Self {
            start_address,
            values: vec![false; count],
        }
    }

    pub fn from_values(start_address: u16, values: Vec<bool>) -> Self {
        Self {
            start_address,
            values,
        }
    }

    pub fn start_address(&self) -> u16 {
        self.start_address
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn values(&self) -> &[bool] {
        &self.values
    }

    pub fn get(&self, address: u16) -> Option<bool> {
        let offset = usize::from(address.checked_sub(self.start_address)?);
        self.values.get(offset).copied()
    }

    pub fn set(&mut self, address: u16, value: bool) -> Result<(), ClientError> {
        let offset = usize::from(
            address
                .checked_sub(self.start_address)
                .ok_or(ClientError::InvalidResponse("coil address out of range"))?,
        );
        let slot = self
            .values
            .get_mut(offset)
            .ok_or(ClientError::InvalidResponse("coil address out of range"))?;
        *slot = value;
        Ok(())
    }

    pub fn apply_read(&mut self, start_address: u16, values: &[bool]) -> Result<(), ClientError> {
        for (i, value) in values.iter().copied().enumerate() {
            let addr = start_address
                .checked_add(i as u16)
                .ok_or(ClientError::InvalidResponse("coil address overflow"))?;
            self.set(addr, value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterPoints {
    start_address: u16,
    values: Vec<u16>,
}

impl RegisterPoints {
    pub fn new(start_address: u16, count: usize) -> Self {
        Self {
            start_address,
            values: vec![0; count],
        }
    }

    pub fn from_values(start_address: u16, values: Vec<u16>) -> Self {
        Self {
            start_address,
            values,
        }
    }

    pub fn start_address(&self) -> u16 {
        self.start_address
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn values(&self) -> &[u16] {
        &self.values
    }

    pub fn get(&self, address: u16) -> Option<u16> {
        let offset = usize::from(address.checked_sub(self.start_address)?);
        self.values.get(offset).copied()
    }

    pub fn set(&mut self, address: u16, value: u16) -> Result<(), ClientError> {
        let offset = usize::from(
            address
                .checked_sub(self.start_address)
                .ok_or(ClientError::InvalidResponse("register address out of range"))?,
        );
        let slot = self
            .values
            .get_mut(offset)
            .ok_or(ClientError::InvalidResponse("register address out of range"))?;
        *slot = value;
        Ok(())
    }

    pub fn apply_read(&mut self, start_address: u16, values: &[u16]) -> Result<(), ClientError> {
        for (i, value) in values.iter().copied().enumerate() {
            let addr = start_address
                .checked_add(i as u16)
                .ok_or(ClientError::InvalidResponse("register address overflow"))?;
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
