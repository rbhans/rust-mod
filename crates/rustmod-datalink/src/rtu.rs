use crate::{DataLink, DataLinkError};
use async_trait::async_trait;
use rustmod_core::encoding::Writer;
use rustmod_core::frame::rtu as rtu_frame;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::{Instant, timeout};
use tokio_serial::{
    DataBits, FlowControl, Parity, SerialPortBuilderExt, SerialStream, StopBits,
};
use tracing::trace;

fn decode_suffix_frame(buffer: &[u8]) -> Option<(usize, u8, &[u8])> {
    if buffer.len() < 4 {
        return None;
    }
    for start in 0..=buffer.len() - 4 {
        if let Ok((address, pdu)) = rtu_frame::decode_frame(&buffer[start..]) {
            return Some((start, address, pdu));
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct ModbusRtuConfig {
    pub response_timeout: Duration,
    pub max_frame_len: usize,
    pub parity: Parity,
    pub data_bits: DataBits,
    pub stop_bits: StopBits,
    pub flow_control: FlowControl,
}

impl Default for ModbusRtuConfig {
    fn default() -> Self {
        Self {
            response_timeout: Duration::from_millis(500),
            max_frame_len: 256,
            parity: Parity::None,
            data_bits: DataBits::Eight,
            stop_bits: StopBits::One,
            flow_control: FlowControl::None,
        }
    }
}

#[derive(Debug)]
pub struct ModbusRtuTransport {
    stream: Arc<Mutex<SerialStream>>,
    config: ModbusRtuConfig,
}

impl ModbusRtuTransport {
    pub fn open(path: &str, baud_rate: u32, config: ModbusRtuConfig) -> Result<Self, DataLinkError> {
        let builder = tokio_serial::new(path, baud_rate)
            .parity(config.parity)
            .data_bits(config.data_bits)
            .stop_bits(config.stop_bits)
            .flow_control(config.flow_control);
        let stream = builder.open_native_async().map_err(|err| {
            DataLinkError::Io(std::io::Error::other(format!(
                "failed to open serial port '{path}': {err}"
            )))
        })?;
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            config,
        })
    }

    pub fn from_stream(stream: SerialStream, config: ModbusRtuConfig) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            config,
        }
    }
}

#[async_trait]
impl DataLink for ModbusRtuTransport {
    async fn exchange(
        &self,
        unit_id: u8,
        request_pdu: &[u8],
        response_pdu: &mut [u8],
    ) -> Result<usize, DataLinkError> {
        if self.config.max_frame_len < 4 {
            return Err(DataLinkError::InvalidResponse(
                "rtu max frame length must be at least 4 bytes",
            ));
        }
        if request_pdu.is_empty() {
            return Err(DataLinkError::InvalidResponse("empty request pdu"));
        }

        let mut req_frame = vec![0u8; request_pdu.len() + 3];
        let mut req_writer = Writer::new(&mut req_frame);
        rtu_frame::encode_frame(&mut req_writer, unit_id, request_pdu)?;

        let mut stream = self.stream.lock().await;
        trace!(unit_id, pdu_len = request_pdu.len(), "sending modbus rtu request");
        stream.write_all(req_writer.as_written()).await?;
        stream.flush().await?;

        let deadline = Instant::now() + self.config.response_timeout;
        let mut frame = vec![0u8; self.config.max_frame_len];
        let mut len = 0usize;

        loop {
            if len == self.config.max_frame_len {
                // Keep scanning by dropping oldest byte. This allows resync from noise.
                frame.copy_within(1..self.config.max_frame_len, 0);
                len -= 1;
            }

            let now = Instant::now();
            let Some(remaining) = deadline.checked_duration_since(now) else {
                return Err(DataLinkError::Timeout);
            };

            let n = match timeout(remaining, stream.read(&mut frame[len..len + 1])).await {
                Ok(Ok(n)) => n,
                Ok(Err(err)) => return Err(DataLinkError::Io(err)),
                Err(_) => return Err(DataLinkError::Timeout),
            };

            if n == 0 {
                return Err(DataLinkError::ConnectionClosed);
            }
            len += n;

            if let Some((_, address, pdu)) = decode_suffix_frame(&frame[..len]) {
                if address == unit_id {
                    if pdu.len() > response_pdu.len() {
                        return Err(DataLinkError::ResponseBufferTooSmall {
                            needed: pdu.len(),
                            available: response_pdu.len(),
                        });
                    }
                    response_pdu[..pdu.len()].copy_from_slice(pdu);
                    trace!(unit_id, pdu_len = pdu.len(), "received modbus rtu response");
                    return Ok(pdu.len());
                }
                // Ignore frames for other units and continue waiting for our response.
                len = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode_suffix_frame;
    use rustmod_core::encoding::Writer;
    use rustmod_core::frame::rtu as rtu_frame;

    #[test]
    fn decode_suffix_skips_leading_noise() {
        let mut frame = [0u8; 16];
        let mut w = Writer::new(&mut frame);
        rtu_frame::encode_frame(&mut w, 1, &[0x03, 0x02, 0x00, 0x2A]).unwrap();

        let mut noisy = vec![0x55, 0xAA];
        noisy.extend_from_slice(w.as_written());
        let (_, address, pdu) = decode_suffix_frame(&noisy).expect("frame should decode");

        assert_eq!(address, 1);
        assert_eq!(pdu, &[0x03, 0x02, 0x00, 0x2A]);
    }

    #[test]
    fn decode_suffix_none_for_partial_frame() {
        let mut frame = [0u8; 16];
        let mut w = Writer::new(&mut frame);
        rtu_frame::encode_frame(&mut w, 1, &[0x03, 0x02, 0x00, 0x2A]).unwrap();
        let bytes = w.as_written();

        assert!(decode_suffix_frame(&bytes[..bytes.len() - 1]).is_none());
    }
}
