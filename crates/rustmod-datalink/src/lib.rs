//! Async Modbus transport abstraction layer.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use rustmod_core::encoding::{Reader, Writer};
use rustmod_core::frame::tcp;
use rustmod_core::{DecodeError, EncodeError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::Mutex;
use tracing::trace;

pub mod server;
pub mod sim;
pub use server::{ModbusRtuOverTcpServer, ModbusService, ModbusTcpServer, ServiceError};
pub use sim::{CoilBank, InMemoryModbusService, InMemoryPointModel, RegisterBank};
#[cfg(feature = "rtu")]
pub mod rtu;
#[cfg(feature = "rtu")]
pub use rtu::{ModbusRtuConfig, ModbusRtuTransport};
#[cfg(feature = "rtu")]
pub mod rtu_server;
#[cfg(feature = "rtu")]
pub use rtu_server::{ModbusRtuServer, ModbusRtuServerConfig};

const MAX_TCP_PDU_LEN: usize = 253;

#[derive(Debug, Error)]
pub enum DataLinkError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encode error: {0}")]
    Encode(#[from] EncodeError),
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("request timed out")]
    Timeout,
    #[error("invalid response: {0}")]
    InvalidResponse(&'static str),
    #[error("transaction id mismatch: expected {expected}, got {got}")]
    MismatchedTransactionId { expected: u16, got: u16 },
    #[error("response buffer too small (needed {needed}, available {available})")]
    ResponseBufferTooSmall { needed: usize, available: usize },
}

#[async_trait]
pub trait DataLink: Send + Sync {
    /// Send a request PDU to a unit and write the response PDU into `response_pdu`.
    ///
    /// Returns the number of response bytes written to `response_pdu`.
    async fn exchange(
        &self,
        unit_id: u8,
        request_pdu: &[u8],
        response_pdu: &mut [u8],
    ) -> Result<usize, DataLinkError>;
}

#[derive(Debug)]
pub struct ModbusTcpTransport {
    stream: Arc<Mutex<TcpStream>>,
    next_transaction_id: Arc<AtomicU16>,
}

impl ModbusTcpTransport {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, DataLinkError> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self::from_stream(stream))
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            next_transaction_id: Arc::new(AtomicU16::new(1)),
        }
    }

    fn next_tid(&self) -> u16 {
        self.next_transaction_id.fetch_add(1, Ordering::Relaxed)
    }
}

async fn read_exact_or_connection_closed(
    stream: &mut TcpStream,
    buf: &mut [u8],
) -> Result<(), DataLinkError> {
    if let Err(err) = stream.read_exact(buf).await {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            return Err(DataLinkError::ConnectionClosed);
        }
        return Err(DataLinkError::Io(err));
    }
    Ok(())
}

async fn drain_exact(stream: &mut TcpStream, mut len: usize) -> Result<(), DataLinkError> {
    let mut scratch = [0u8; 256];
    while len > 0 {
        let chunk = len.min(scratch.len());
        read_exact_or_connection_closed(stream, &mut scratch[..chunk]).await?;
        len -= chunk;
    }
    Ok(())
}

#[async_trait]
impl DataLink for ModbusTcpTransport {
    async fn exchange(
        &self,
        unit_id: u8,
        request_pdu: &[u8],
        response_pdu: &mut [u8],
    ) -> Result<usize, DataLinkError> {
        if request_pdu.is_empty() {
            return Err(DataLinkError::InvalidResponse("empty request pdu"));
        }

        let transaction_id = self.next_tid();
        let mut req_frame = vec![0u8; tcp::MBAP_HEADER_LEN + request_pdu.len()];
        let mut writer = Writer::new(&mut req_frame);
        tcp::encode_frame(&mut writer, transaction_id, unit_id, request_pdu)?;

        let mut stream = self.stream.lock().await;
        trace!(
            transaction_id,
            unit_id,
            pdu_len = request_pdu.len(),
            "sending modbus tcp request"
        );
        stream.write_all(writer.as_written()).await?;

        let mut mbap = [0u8; tcp::MBAP_HEADER_LEN];
        read_exact_or_connection_closed(&mut stream, &mut mbap).await?;

        let mut reader = Reader::new(&mbap);
        let header = tcp::MbapHeader::decode(&mut reader)?;

        let pdu_len = usize::from(header.length)
            .checked_sub(1)
            .ok_or(DataLinkError::InvalidResponse("invalid mbap length"))?;
        if pdu_len == 0 {
            return Err(DataLinkError::InvalidResponse("empty response pdu"));
        }
        let tid_mismatch = header.transaction_id != transaction_id;
        let unit_mismatch = header.unit_id != unit_id;

        if pdu_len > MAX_TCP_PDU_LEN {
            drain_exact(&mut stream, pdu_len).await?;
            if tid_mismatch {
                return Err(DataLinkError::MismatchedTransactionId {
                    expected: transaction_id,
                    got: header.transaction_id,
                });
            }
            if unit_mismatch {
                return Err(DataLinkError::InvalidResponse("unit id mismatch"));
            }
            return Err(DataLinkError::InvalidResponse("response pdu too large"));
        }

        if pdu_len > response_pdu.len() {
            drain_exact(&mut stream, pdu_len).await?;
            if tid_mismatch {
                return Err(DataLinkError::MismatchedTransactionId {
                    expected: transaction_id,
                    got: header.transaction_id,
                });
            }
            if unit_mismatch {
                return Err(DataLinkError::InvalidResponse("unit id mismatch"));
            }
            return Err(DataLinkError::ResponseBufferTooSmall {
                needed: pdu_len,
                available: response_pdu.len(),
            });
        }

        read_exact_or_connection_closed(&mut stream, &mut response_pdu[..pdu_len]).await?;
        if tid_mismatch {
            return Err(DataLinkError::MismatchedTransactionId {
                expected: transaction_id,
                got: header.transaction_id,
            });
        }
        if unit_mismatch {
            return Err(DataLinkError::InvalidResponse("unit id mismatch"));
        }
        trace!(
            transaction_id,
            unit_id,
            pdu_len,
            "received modbus tcp response"
        );
        Ok(pdu_len)
    }
}

#[cfg(test)]
mod tests {
    use super::{DataLink, DataLinkError, ModbusTcpTransport};
    use rustmod_core::encoding::Writer;
    use rustmod_core::frame::tcp;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn exchange_roundtrip_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut req = [0u8; 12];
            socket.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[7..], &[0x03, 0x00, 0x6B, 0x00, 0x03]);

            let mut frame = [0u8; 15];
            let mut w = Writer::new(&mut frame);
            tcp::encode_frame(
                &mut w,
                1,
                1,
                &[0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64],
            )
            .unwrap();
            socket.write_all(w.as_written()).await.unwrap();
        });

        let transport = ModbusTcpTransport::connect(addr).await.unwrap();
        let mut response = [0u8; 256];
        let len = transport
            .exchange(1, &[0x03, 0x00, 0x6B, 0x00, 0x03], &mut response)
            .await
            .unwrap();

        assert_eq!(
            &response[..len],
            &[0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64]
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_rejects_mismatched_transaction_id() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut req = [0u8; 12];
            socket.read_exact(&mut req).await.unwrap();

            let mut frame = [0u8; 9];
            let mut w = Writer::new(&mut frame);
            tcp::encode_frame(&mut w, 2, 1, &[0x83, 0x02]).unwrap();
            socket.write_all(w.as_written()).await.unwrap();
        });

        let transport = ModbusTcpTransport::connect(addr).await.unwrap();
        let mut response = [0u8; 16];
        let err = transport
            .exchange(1, &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
            .await
            .unwrap_err();

        match err {
            DataLinkError::MismatchedTransactionId { expected, got } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        server.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_drains_pdu_on_transaction_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut req = [0u8; 12];
            socket.read_exact(&mut req).await.unwrap();
            let mut mismatch = [0u8; 9];
            let mut mismatch_w = Writer::new(&mut mismatch);
            tcp::encode_frame(&mut mismatch_w, 2, 1, &[0x83, 0x02]).unwrap();
            socket.write_all(mismatch_w.as_written()).await.unwrap();

            let mut req2 = [0u8; 12];
            socket.read_exact(&mut req2).await.unwrap();
            let mut ok = [0u8; 11];
            let mut ok_w = Writer::new(&mut ok);
            tcp::encode_frame(&mut ok_w, 2, 1, &[0x03, 0x02, 0x00, 0x2A]).unwrap();
            socket.write_all(ok_w.as_written()).await.unwrap();
        });

        let transport = ModbusTcpTransport::connect(addr).await.unwrap();
        let mut response = [0u8; 16];
        let err = transport
            .exchange(1, &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
            .await
            .unwrap_err();
        assert!(matches!(err, DataLinkError::MismatchedTransactionId { .. }));

        let len = transport
            .exchange(1, &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
            .await
            .unwrap();
        assert_eq!(&response[..len], &[0x03, 0x02, 0x00, 0x2A]);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_rejects_and_drains_oversized_response_pdu() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut req = [0u8; 12];
            socket.read_exact(&mut req).await.unwrap();
            let mut oversized = vec![0u8; tcp::MBAP_HEADER_LEN + 254];
            oversized[0..2].copy_from_slice(&1u16.to_be_bytes());
            oversized[2..4].copy_from_slice(&0u16.to_be_bytes());
            oversized[4..6].copy_from_slice(&255u16.to_be_bytes());
            oversized[6] = 1;
            oversized[7] = 0x03;
            socket.write_all(&oversized).await.unwrap();

            let mut req2 = [0u8; 12];
            socket.read_exact(&mut req2).await.unwrap();
            let mut ok = [0u8; 11];
            let mut ok_w = Writer::new(&mut ok);
            tcp::encode_frame(&mut ok_w, 2, 1, &[0x03, 0x02, 0x00, 0x2A]).unwrap();
            socket.write_all(ok_w.as_written()).await.unwrap();
        });

        let transport = ModbusTcpTransport::connect(addr).await.unwrap();
        let mut response = [0u8; 260];
        let err = transport
            .exchange(1, &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            DataLinkError::InvalidResponse("response pdu too large")
        ));

        let len = transport
            .exchange(1, &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
            .await
            .unwrap();
        assert_eq!(&response[..len], &[0x03, 0x02, 0x00, 0x2A]);

        server.await.unwrap();
    }
}
