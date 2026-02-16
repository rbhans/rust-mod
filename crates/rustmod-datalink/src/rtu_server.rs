use crate::server::{ModbusService, ServiceError};
use crate::DataLinkError;
use rustmod_core::encoding::{Reader, Writer};
use rustmod_core::frame::rtu as rtu_frame;
use rustmod_core::pdu::{DecodedRequest, ExceptionCode, ExceptionResponse};
use rustmod_core::DecodeError;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_serial::{
    DataBits, FlowControl, Parity, SerialPortBuilderExt, SerialStream, StopBits,
};
use tracing::{debug, warn};

const DEFAULT_MAX_PDU_LEN: usize = 253;
const DEFAULT_MAX_FRAME_LEN: usize = 256;

#[derive(Debug, Clone)]
pub struct ModbusRtuServerConfig {
    pub max_pdu_len: usize,
    pub max_frame_len: usize,
    pub parity: Parity,
    pub data_bits: DataBits,
    pub stop_bits: StopBits,
    pub flow_control: FlowControl,
}

impl Default for ModbusRtuServerConfig {
    fn default() -> Self {
        Self {
            max_pdu_len: DEFAULT_MAX_PDU_LEN,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
            parity: Parity::None,
            data_bits: DataBits::Eight,
            stop_bits: StopBits::One,
            flow_control: FlowControl::None,
        }
    }
}

pub struct ModbusRtuServer<S> {
    stream: Arc<Mutex<SerialStream>>,
    service: Arc<S>,
    config: ModbusRtuServerConfig,
}

impl<S: ModbusService> ModbusRtuServer<S> {
    pub fn open(
        path: &str,
        baud_rate: u32,
        service: S,
        config: ModbusRtuServerConfig,
    ) -> Result<Self, DataLinkError> {
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

        Ok(Self::from_stream(stream, service, config))
    }

    pub fn from_stream(stream: SerialStream, service: S, config: ModbusRtuServerConfig) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            service: Arc::new(service),
            config,
        }
    }

    pub async fn run(self) -> Result<(), DataLinkError> {
        let mut stream = self.stream.lock().await;
        if let Err(err) = serve_rtu_io(
            &mut *stream,
            Arc::clone(&self.service),
            self.config.max_pdu_len,
            self.config.max_frame_len,
        )
        .await
        {
            warn!(error = %err, "modbus rtu server ended with error");
            return Err(err);
        }
        Ok(())
    }
}

fn decode_suffix_frame(buffer: &[u8]) -> Option<(usize, u8, &[u8])> {
    if buffer.len() < 4 {
        return None;
    }
    for start in 0..=buffer.len() - 4 {
        if let Ok((unit_id, pdu)) = rtu_frame::decode_frame(&buffer[start..]) {
            return Some((start, unit_id, pdu));
        }
    }
    None
}

async fn serve_rtu_io<S: ModbusService, IO: AsyncRead + AsyncWrite + Unpin>(
    io: &mut IO,
    service: Arc<S>,
    max_pdu_len: usize,
    max_frame_len: usize,
) -> Result<(), DataLinkError> {
    if max_frame_len < 4 {
        return Err(DataLinkError::InvalidResponse(
            "rtu frame length must be at least 4 bytes",
        ));
    }

    let mut frame = vec![0u8; max_frame_len];
    let mut len = 0usize;

    loop {
        if len == max_frame_len {
            frame.copy_within(1..max_frame_len, 0);
            len -= 1;
        }

        let n = io.read(&mut frame[len..len + 1]).await?;
        if n == 0 {
            return Ok(());
        }
        len += n;

        let Some((_, unit_id, request_pdu)) = decode_suffix_frame(&frame[..len]) else {
            continue;
        };
        len = 0;

        if request_pdu.is_empty() || request_pdu.len() > max_pdu_len {
            send_rtu_exception(io, unit_id, 0, ExceptionCode::IllegalDataValue).await?;
            continue;
        }

        let mut request_reader = Reader::new(request_pdu);
        let decoded = match DecodedRequest::decode(&mut request_reader) {
            Ok(req) if request_reader.is_empty() => req,
            Ok(_) => {
                let function = request_pdu[0] & 0x7F;
                send_rtu_exception(io, unit_id, function, ExceptionCode::IllegalDataValue).await?;
                continue;
            }
            Err(err) => {
                let function = request_pdu.first().copied().unwrap_or(0) & 0x7F;
                send_rtu_exception(io, unit_id, function, map_decode_error_to_exception(err)).await?;
                continue;
            }
        };

        debug!(
            unit_id,
            function = decoded.function_code().as_u8(),
            pdu_len = request_pdu.len(),
            "received modbus rtu request"
        );

        let mut response_pdu = vec![0u8; max_pdu_len];
        let result = service.handle(unit_id, decoded, &mut response_pdu);

        // Broadcast requests (unit id 0) are writes only and do not receive responses.
        if unit_id == 0 {
            continue;
        }

        match result {
            Ok(response_len) => {
                if response_len == 0 || response_len > max_pdu_len {
                    send_rtu_exception(
                        io,
                        unit_id,
                        decoded.function_code().as_u8(),
                        ExceptionCode::ServerDeviceFailure,
                    )
                    .await?;
                    continue;
                }
                send_rtu_pdu(io, unit_id, &response_pdu[..response_len]).await?;
            }
            Err(ServiceError::Exception(code)) => {
                send_rtu_exception(io, unit_id, decoded.function_code().as_u8(), code).await?;
            }
            Err(ServiceError::InvalidRequest(_)) => {
                send_rtu_exception(
                    io,
                    unit_id,
                    decoded.function_code().as_u8(),
                    ExceptionCode::IllegalDataValue,
                )
                .await?;
            }
            Err(ServiceError::Internal(_)) => {
                send_rtu_exception(
                    io,
                    unit_id,
                    decoded.function_code().as_u8(),
                    ExceptionCode::ServerDeviceFailure,
                )
                .await?;
            }
        }
    }
}

fn map_decode_error_to_exception(err: DecodeError) -> ExceptionCode {
    match err {
        DecodeError::InvalidFunctionCode => ExceptionCode::IllegalFunction,
        DecodeError::InvalidLength | DecodeError::InvalidValue | DecodeError::UnexpectedEof => {
            ExceptionCode::IllegalDataValue
        }
        DecodeError::InvalidCrc | DecodeError::Unsupported | DecodeError::Message(_) => {
            ExceptionCode::ServerDeviceFailure
        }
    }
}

async fn send_rtu_exception<IO: AsyncWrite + Unpin>(
    io: &mut IO,
    unit_id: u8,
    function_code: u8,
    exception_code: ExceptionCode,
) -> Result<(), DataLinkError> {
    let mut pdu = [0u8; 2];
    let mut writer = Writer::new(&mut pdu);
    ExceptionResponse {
        function_code,
        exception_code,
    }
    .encode(&mut writer)
    .map_err(DataLinkError::Encode)?;

    send_rtu_pdu(io, unit_id, writer.as_written()).await
}

async fn send_rtu_pdu<IO: AsyncWrite + Unpin>(
    io: &mut IO,
    unit_id: u8,
    pdu: &[u8],
) -> Result<(), DataLinkError> {
    let mut frame = vec![0u8; pdu.len() + 3];
    let mut writer = Writer::new(&mut frame);
    rtu_frame::encode_frame(&mut writer, unit_id, pdu)?;
    io.write_all(writer.as_written()).await?;
    io.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::serve_rtu_io;
    use crate::server::{ModbusService, ServiceError};
    use rustmod_core::encoding::Writer;
    use rustmod_core::frame::rtu as rtu_frame;
    use rustmod_core::pdu::{DecodedRequest, ExceptionCode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    struct EchoReadService;

    impl ModbusService for EchoReadService {
        fn handle(
            &self,
            _unit_id: u8,
            request: DecodedRequest<'_>,
            response_pdu: &mut [u8],
        ) -> Result<usize, ServiceError> {
            match request {
                DecodedRequest::ReadHoldingRegisters(_) => {
                    let bytes = [0x03u8, 0x02, 0x00, 0x2A];
                    response_pdu[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                _ => Err(ServiceError::Exception(ExceptionCode::IllegalFunction)),
            }
        }
    }

    #[tokio::test]
    async fn rtu_server_handles_read_request() {
        let (mut client, mut server_side) = duplex(256);
        let task = tokio::spawn(async move {
            serve_rtu_io(
                &mut server_side,
                std::sync::Arc::new(EchoReadService),
                253,
                256,
            )
            .await
            .unwrap();
        });

        let mut request = [0u8; 16];
        let mut writer = Writer::new(&mut request);
        rtu_frame::encode_frame(&mut writer, 1, &[0x03, 0x00, 0x00, 0x00, 0x01]).unwrap();
        client.write_all(writer.as_written()).await.unwrap();

        let mut response = [0u8; 7];
        client.read_exact(&mut response).await.unwrap();
        let (unit_id, pdu) = rtu_frame::decode_frame(&response).unwrap();
        assert_eq!(unit_id, 1);
        assert_eq!(pdu, &[0x03, 0x02, 0x00, 0x2A]);

        drop(client);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rtu_server_maps_decode_error_to_exception() {
        let (mut client, mut server_side) = duplex(256);
        let task = tokio::spawn(async move {
            serve_rtu_io(
                &mut server_side,
                std::sync::Arc::new(EchoReadService),
                253,
                256,
            )
            .await
            .unwrap();
        });

        let mut request = [0u8; 32];
        let mut writer = Writer::new(&mut request);
        rtu_frame::encode_frame(
            &mut writer,
            1,
            &[0x10, 0x00, 0x00, 0x00, 0x02, 0x03, 0x12, 0x34, 0x56],
        )
        .unwrap();
        client.write_all(writer.as_written()).await.unwrap();

        let mut response = [0u8; 5];
        client.read_exact(&mut response).await.unwrap();
        let (unit_id, pdu) = rtu_frame::decode_frame(&response).unwrap();
        assert_eq!(unit_id, 1);
        assert_eq!(pdu, &[0x90, 0x03]);

        drop(client);
        task.await.unwrap();
    }
}
