use crate::DataLinkError;
use rustmod_core::encoding::{Reader, Writer};
use rustmod_core::frame::{rtu as rtu_frame, tcp};
use rustmod_core::pdu::{DecodedRequest, ExceptionCode, ExceptionResponse};
use rustmod_core::{DecodeError, UnitId};
use std::future::Future;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

#[cfg(feature = "metrics")]
use std::sync::atomic::{AtomicU64, Ordering};

const DEFAULT_MAX_PDU_LEN: usize = 253;
const DEFAULT_MAX_RTU_FRAME_LEN: usize = 256;

/// Errors returned by a [`ModbusService`] handler.
///
/// The server maps these to Modbus exception responses on the wire.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServiceError {
    /// A standard Modbus exception (e.g. illegal address, illegal function).
    #[error("modbus exception: {0:?}")]
    Exception(ExceptionCode),
    /// The request was malformed or contained invalid parameters.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// An internal error (maps to Server Device Failure exception on the wire).
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// Application-level request handler for Modbus servers.
///
/// Implement this trait to define how your device responds to Modbus requests.
/// See [`InMemoryModbusService`](crate::InMemoryModbusService) for a ready-made
/// in-memory simulator implementation.
pub trait ModbusService: Send + Sync + 'static {
    /// Handle a decoded request and write a response PDU into `response_pdu`.
    ///
    /// Return the number of bytes written. The response must include function
    /// code and payload, but not MBAP header bytes.
    fn handle(
        &self,
        unit_id: UnitId,
        request: DecodedRequest<'_>,
        response_pdu: &mut [u8],
    ) -> Result<usize, ServiceError>;
}

impl<T> ModbusService for Arc<T>
where
    T: ModbusService + ?Sized,
{
    fn handle(
        &self,
        unit_id: UnitId,
        request: DecodedRequest<'_>,
        response_pdu: &mut [u8],
    ) -> Result<usize, ServiceError> {
        (**self).handle(unit_id, request, response_pdu)
    }
}

/// Atomic counters tracking server activity (available with the `metrics` feature).
#[cfg(feature = "metrics")]
#[derive(Debug, Default)]
pub struct ServerMetrics {
    requests_total: AtomicU64,
    responses_ok: AtomicU64,
    exceptions_sent: AtomicU64,
    decode_errors: AtomicU64,
    internal_errors: AtomicU64,
}

/// A point-in-time snapshot of [`ServerMetrics`] counters.
#[cfg(feature = "metrics")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerMetricsSnapshot {
    pub requests_total: u64,
    pub responses_ok: u64,
    pub exceptions_sent: u64,
    pub decode_errors: u64,
    pub internal_errors: u64,
}

#[cfg(feature = "metrics")]
impl ServerMetrics {
    fn snapshot(&self) -> ServerMetricsSnapshot {
        ServerMetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            responses_ok: self.responses_ok.load(Ordering::Relaxed),
            exceptions_sent: self.exceptions_sent.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            internal_errors: self.internal_errors.load(Ordering::Relaxed),
        }
    }
}

const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Modbus TCP server that accepts connections and dispatches requests to a [`ModbusService`].
///
/// Supports configurable connection limits, PDU size limits, and optional metrics.
/// Use [`run`](Self::run) to accept connections indefinitely, or
/// [`run_until`](Self::run_until) for graceful shutdown.
pub struct ModbusTcpServer<S> {
    listener: TcpListener,
    service: Arc<S>,
    max_pdu_len: usize,
    max_connections: usize,
    #[cfg(feature = "metrics")]
    metrics: Arc<ServerMetrics>,
}

impl<S: ModbusService> ModbusTcpServer<S> {
    /// Bind to a TCP address and create a new server.
    pub async fn bind<A: ToSocketAddrs>(addr: A, service: S) -> Result<Self, DataLinkError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self::from_listener(listener, service))
    }

    /// Create a server from an existing [`TcpListener`].
    #[must_use]
    pub fn from_listener(listener: TcpListener, service: S) -> Self {
        Self {
            listener,
            service: Arc::new(service),
            max_pdu_len: DEFAULT_MAX_PDU_LEN,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            #[cfg(feature = "metrics")]
            metrics: Arc::new(ServerMetrics::default()),
        }
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, DataLinkError> {
        Ok(self.listener.local_addr()?)
    }

    /// Set the maximum PDU length the server will accept (default: 253).
    #[must_use]
    pub fn with_max_pdu_len(mut self, max_pdu_len: usize) -> Self {
        self.max_pdu_len = max_pdu_len;
        self
    }

    /// Set the maximum number of concurrent client connections (default: 256).
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Get a cloneable handle to the server metrics.
    #[cfg(feature = "metrics")]
    pub fn metrics_handle(&self) -> Arc<ServerMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Take a snapshot of the current metrics counters.
    #[cfg(feature = "metrics")]
    pub fn metrics_snapshot(&self) -> ServerMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Accept connections and serve requests indefinitely.
    pub async fn run(self) -> Result<(), DataLinkError> {
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        loop {
            let (socket, peer) = self.listener.accept().await?;
            let service = Arc::clone(&self.service);
            let max_pdu_len = self.max_pdu_len;
            let permit = Arc::clone(&semaphore);
            #[cfg(feature = "metrics")]
            let metrics = Arc::clone(&self.metrics);

            tokio::spawn(async move {
                let _permit = permit.acquire().await;
                if let Err(err) = handle_connection(
                    socket,
                    service,
                    max_pdu_len,
                    #[cfg(feature = "metrics")]
                    metrics,
                )
                .await
                {
                    warn!(%peer, error = %err, "modbus tcp server connection ended with error");
                }
            });
        }
    }

    /// Run the server until the given shutdown future completes.
    pub async fn run_until(self, shutdown: impl Future<Output = ()> + Send) -> Result<(), DataLinkError> {
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    let (socket, peer) = result?;
                    let service = Arc::clone(&self.service);
                    let max_pdu_len = self.max_pdu_len;
                    let permit = Arc::clone(&semaphore);
                    #[cfg(feature = "metrics")]
                    let metrics = Arc::clone(&self.metrics);

                    tokio::spawn(async move {
                        let _permit = permit.acquire().await;
                        if let Err(err) = handle_connection(
                            socket,
                            service,
                            max_pdu_len,
                            #[cfg(feature = "metrics")]
                            metrics,
                        )
                        .await
                        {
                            warn!(%peer, error = %err, "modbus tcp server connection ended with error");
                        }
                    });
                }
                () = &mut shutdown => {
                    return Ok(());
                }
            }
        }
    }
}

/// Modbus RTU-over-TCP server that accepts TCP connections carrying RTU-framed requests.
///
/// This is useful for RTU gateways or testing environments where RTU framing
/// is tunnelled over a TCP socket.
pub struct ModbusRtuOverTcpServer<S> {
    listener: TcpListener,
    service: Arc<S>,
    max_pdu_len: usize,
    max_frame_len: usize,
    max_connections: usize,
    #[cfg(feature = "metrics")]
    metrics: Arc<ServerMetrics>,
}

impl<S: ModbusService> ModbusRtuOverTcpServer<S> {
    /// Bind to a TCP address and create a new RTU-over-TCP server.
    pub async fn bind<A: ToSocketAddrs>(addr: A, service: S) -> Result<Self, DataLinkError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self::from_listener(listener, service))
    }

    /// Create a server from an existing [`TcpListener`].
    #[must_use]
    pub fn from_listener(listener: TcpListener, service: S) -> Self {
        Self {
            listener,
            service: Arc::new(service),
            max_pdu_len: DEFAULT_MAX_PDU_LEN,
            max_frame_len: DEFAULT_MAX_RTU_FRAME_LEN,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            #[cfg(feature = "metrics")]
            metrics: Arc::new(ServerMetrics::default()),
        }
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, DataLinkError> {
        Ok(self.listener.local_addr()?)
    }

    /// Set the maximum PDU length (default: 253).
    #[must_use]
    pub fn with_max_pdu_len(mut self, max_pdu_len: usize) -> Self {
        self.max_pdu_len = max_pdu_len;
        self
    }

    /// Set the maximum RTU frame length including address + CRC (default: 256).
    #[must_use]
    pub fn with_max_frame_len(mut self, max_frame_len: usize) -> Self {
        self.max_frame_len = max_frame_len;
        self
    }

    /// Set the maximum number of concurrent client connections (default: 256).
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Get a cloneable handle to the server metrics.
    #[cfg(feature = "metrics")]
    pub fn metrics_handle(&self) -> Arc<ServerMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Take a snapshot of the current metrics counters.
    #[cfg(feature = "metrics")]
    pub fn metrics_snapshot(&self) -> ServerMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Accept connections and serve requests indefinitely.
    pub async fn run(self) -> Result<(), DataLinkError> {
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        loop {
            let (socket, peer) = self.listener.accept().await?;
            let service = Arc::clone(&self.service);
            let max_pdu_len = self.max_pdu_len;
            let max_frame_len = self.max_frame_len;
            let permit = Arc::clone(&semaphore);
            #[cfg(feature = "metrics")]
            let metrics = Arc::clone(&self.metrics);

            tokio::spawn(async move {
                let _permit = permit.acquire().await;
                if let Err(err) = handle_rtu_over_tcp_connection(
                    socket,
                    service,
                    max_pdu_len,
                    max_frame_len,
                    #[cfg(feature = "metrics")]
                    metrics,
                )
                .await
                {
                    warn!(
                        %peer,
                        error = %err,
                        "modbus rtu-over-tcp server connection ended with error"
                    );
                }
            });
        }
    }

    /// Run the server until the given shutdown future completes.
    pub async fn run_until(self, shutdown: impl Future<Output = ()> + Send) -> Result<(), DataLinkError> {
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    let (socket, peer) = result?;
                    let service = Arc::clone(&self.service);
                    let max_pdu_len = self.max_pdu_len;
                    let max_frame_len = self.max_frame_len;
                    let permit = Arc::clone(&semaphore);
                    #[cfg(feature = "metrics")]
                    let metrics = Arc::clone(&self.metrics);

                    tokio::spawn(async move {
                        let _permit = permit.acquire().await;
                        if let Err(err) = handle_rtu_over_tcp_connection(
                            socket,
                            service,
                            max_pdu_len,
                            max_frame_len,
                            #[cfg(feature = "metrics")]
                            metrics,
                        )
                        .await
                        {
                            warn!(
                                %peer,
                                error = %err,
                                "modbus rtu-over-tcp server connection ended with error"
                            );
                        }
                    });
                }
                () = &mut shutdown => {
                    return Ok(());
                }
            }
        }
    }
}

fn is_write_request(request: &DecodedRequest<'_>) -> bool {
    matches!(
        request,
        DecodedRequest::WriteSingleCoil(_)
            | DecodedRequest::WriteSingleRegister(_)
            | DecodedRequest::WriteMultipleCoils(_)
            | DecodedRequest::WriteMultipleRegisters(_)
            | DecodedRequest::MaskWriteRegister(_)
            | DecodedRequest::ReadWriteMultipleRegisters(_)
    )
}

async fn handle_connection<S: ModbusService>(
    mut socket: TcpStream,
    service: Arc<S>,
    max_pdu_len: usize,
    #[cfg(feature = "metrics")] metrics: Arc<ServerMetrics>,
) -> Result<(), DataLinkError> {
    let mut request_pdu_buf = [0u8; 253];
    let mut response_pdu = vec![0u8; max_pdu_len];

    loop {
        let mut mbap = [0u8; tcp::MBAP_HEADER_LEN];
        if let Err(err) = socket.read_exact(&mut mbap).await {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(());
            }
            return Err(DataLinkError::Io(err));
        }

        let mut mbap_reader = Reader::new(&mbap);
        let header = tcp::MbapHeader::decode(&mut mbap_reader)?;
        let pdu_len = usize::from(header.length)
            .checked_sub(1)
            .ok_or(DataLinkError::InvalidResponse("invalid mbap length"))?;

        if pdu_len == 0 || pdu_len > max_pdu_len {
            return Err(DataLinkError::InvalidResponse("invalid request pdu length"));
        }

        socket.read_exact(&mut request_pdu_buf[..pdu_len]).await?;
        let request_pdu = &request_pdu_buf[..pdu_len];

        #[cfg(feature = "metrics")]
        metrics.requests_total.fetch_add(1, Ordering::Relaxed);

        let mut request_reader = Reader::new(request_pdu);
        let decoded = match DecodedRequest::decode(&mut request_reader) {
            Ok(req) if request_reader.is_empty() => req,
            Ok(_) => {
                #[cfg(feature = "metrics")]
                {
                    metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                    metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);
                }
                let function = request_pdu[0] & 0x7F;
                send_exception(
                    &mut socket,
                    header.transaction_id,
                    header.unit_id,
                    function,
                    ExceptionCode::IllegalDataValue,
                )
                .await?;
                continue;
            }
            Err(err) => {
                #[cfg(feature = "metrics")]
                {
                    metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                    metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);
                }
                let function = request_pdu.first().copied().unwrap_or(0) & 0x7F;
                send_exception(
                    &mut socket,
                    header.transaction_id,
                    header.unit_id,
                    function,
                    map_decode_error_to_exception(err),
                )
                .await?;
                continue;
            }
        };

        debug!(
            correlation_id = header.transaction_id,
            unit_id = header.unit_id.as_u8(),
            function = decoded.function_code().as_u8(),
            pdu_len,
            "received modbus tcp request"
        );

        // Broadcast handling (unit_id == 0)
        if header.unit_id == UnitId::BROADCAST {
            if is_write_request(&decoded) {
                // Process write but don't send response
                let _ = service.handle(header.unit_id, decoded, &mut response_pdu);
                continue;
            } else {
                // Read on broadcast: send IllegalFunction exception
                send_exception(
                    &mut socket,
                    header.transaction_id,
                    header.unit_id,
                    decoded.function_code().as_u8(),
                    ExceptionCode::IllegalFunction,
                )
                .await?;
                continue;
            }
        }

        match service.handle(header.unit_id, decoded, &mut response_pdu) {
            Ok(response_len) => {
                if response_len == 0 || response_len > max_pdu_len {
                    #[cfg(feature = "metrics")]
                    {
                        metrics.internal_errors.fetch_add(1, Ordering::Relaxed);
                        metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);
                    }
                    send_exception(
                        &mut socket,
                        header.transaction_id,
                        header.unit_id,
                        decoded.function_code().as_u8(),
                        ExceptionCode::ServerDeviceFailure,
                    )
                    .await?;
                    continue;
                }

                #[cfg(feature = "metrics")]
                metrics.responses_ok.fetch_add(1, Ordering::Relaxed);

                send_pdu(
                    &mut socket,
                    header.transaction_id,
                    header.unit_id,
                    &response_pdu[..response_len],
                )
                .await?;
            }
            Err(ServiceError::Exception(code)) => {
                #[cfg(feature = "metrics")]
                metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);

                send_exception(
                    &mut socket,
                    header.transaction_id,
                    header.unit_id,
                    decoded.function_code().as_u8(),
                    code,
                )
                .await?;
            }
            Err(ServiceError::InvalidRequest(_)) => {
                #[cfg(feature = "metrics")]
                metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);

                send_exception(
                    &mut socket,
                    header.transaction_id,
                    header.unit_id,
                    decoded.function_code().as_u8(),
                    ExceptionCode::IllegalDataValue,
                )
                .await?;
            }
            Err(_) => {
                #[cfg(feature = "metrics")]
                {
                    metrics.internal_errors.fetch_add(1, Ordering::Relaxed);
                    metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);
                }

                send_exception(
                    &mut socket,
                    header.transaction_id,
                    header.unit_id,
                    decoded.function_code().as_u8(),
                    ExceptionCode::ServerDeviceFailure,
                )
                .await?;
            }
        }
    }
}

fn decode_rtu_suffix_frame(buffer: &[u8]) -> Option<(usize, UnitId, &[u8])> {
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

async fn handle_rtu_over_tcp_connection<S: ModbusService>(
    mut socket: TcpStream,
    service: Arc<S>,
    max_pdu_len: usize,
    max_frame_len: usize,
    #[cfg(feature = "metrics")] metrics: Arc<ServerMetrics>,
) -> Result<(), DataLinkError> {
    if max_frame_len < 4 {
        return Err(DataLinkError::InvalidResponse(
            "rtu frame length must be at least 4 bytes",
        ));
    }

    let mut frame = vec![0u8; max_frame_len];
    let mut len = 0usize;
    let mut response_pdu = vec![0u8; max_pdu_len];

    loop {
        if len == max_frame_len {
            // Drop oldest byte so we can continue scanning for a valid frame boundary.
            frame.copy_within(1..max_frame_len, 0);
            len -= 1;
        }

        let n = socket.read(&mut frame[len..len + 1]).await?;
        if n == 0 {
            return Ok(());
        }
        len += n;

        let Some((_, unit_id, request_pdu)) = decode_rtu_suffix_frame(&frame[..len]) else {
            continue;
        };
        len = 0;

        #[cfg(feature = "metrics")]
        metrics.requests_total.fetch_add(1, Ordering::Relaxed);

        if request_pdu.is_empty() || request_pdu.len() > max_pdu_len {
            #[cfg(feature = "metrics")]
            {
                metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);
            }
            send_rtu_exception(&mut socket, unit_id, 0, ExceptionCode::IllegalDataValue).await?;
            continue;
        }

        let mut request_reader = Reader::new(request_pdu);
        let decoded = match DecodedRequest::decode(&mut request_reader) {
            Ok(req) if request_reader.is_empty() => req,
            Ok(_) => {
                #[cfg(feature = "metrics")]
                {
                    metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                    metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);
                }
                let function = request_pdu[0] & 0x7F;
                send_rtu_exception(
                    &mut socket,
                    unit_id,
                    function,
                    ExceptionCode::IllegalDataValue,
                )
                .await?;
                continue;
            }
            Err(err) => {
                #[cfg(feature = "metrics")]
                {
                    metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                    metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);
                }
                let function = request_pdu.first().copied().unwrap_or(0) & 0x7F;
                send_rtu_exception(
                    &mut socket,
                    unit_id,
                    function,
                    map_decode_error_to_exception(err),
                )
                .await?;
                continue;
            }
        };

        debug!(
            unit_id = unit_id.as_u8(),
            function = decoded.function_code().as_u8(),
            pdu_len = request_pdu.len(),
            "received modbus rtu-over-tcp request"
        );

        match service.handle(unit_id, decoded, &mut response_pdu) {
            Ok(response_len) => {
                if response_len == 0 || response_len > max_pdu_len {
                    #[cfg(feature = "metrics")]
                    {
                        metrics.internal_errors.fetch_add(1, Ordering::Relaxed);
                        metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);
                    }
                    send_rtu_exception(
                        &mut socket,
                        unit_id,
                        decoded.function_code().as_u8(),
                        ExceptionCode::ServerDeviceFailure,
                    )
                    .await?;
                    continue;
                }

                #[cfg(feature = "metrics")]
                metrics.responses_ok.fetch_add(1, Ordering::Relaxed);

                send_rtu_pdu(&mut socket, unit_id, &response_pdu[..response_len]).await?;
            }
            Err(ServiceError::Exception(code)) => {
                #[cfg(feature = "metrics")]
                metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);

                send_rtu_exception(&mut socket, unit_id, decoded.function_code().as_u8(), code)
                    .await?;
            }
            Err(ServiceError::InvalidRequest(_)) => {
                #[cfg(feature = "metrics")]
                metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);

                send_rtu_exception(
                    &mut socket,
                    unit_id,
                    decoded.function_code().as_u8(),
                    ExceptionCode::IllegalDataValue,
                )
                .await?;
            }
            Err(ServiceError::Internal(_)) => {
                #[cfg(feature = "metrics")]
                {
                    metrics.internal_errors.fetch_add(1, Ordering::Relaxed);
                    metrics.exceptions_sent.fetch_add(1, Ordering::Relaxed);
                }

                send_rtu_exception(
                    &mut socket,
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
        _ => ExceptionCode::ServerDeviceFailure,
    }
}

async fn send_exception(
    socket: &mut TcpStream,
    transaction_id: u16,
    unit_id: UnitId,
    function_code: u8,
    exception_code: ExceptionCode,
) -> Result<(), DataLinkError> {
    let mut pdu = [0u8; 2];
    let mut pdu_writer = Writer::new(&mut pdu);
    ExceptionResponse {
        function_code,
        exception_code,
    }
    .encode(&mut pdu_writer)
    .map_err(DataLinkError::Encode)?;

    send_pdu(socket, transaction_id, unit_id, pdu_writer.as_written()).await
}

async fn send_pdu(
    socket: &mut TcpStream,
    transaction_id: u16,
    unit_id: UnitId,
    pdu: &[u8],
) -> Result<(), DataLinkError> {
    let mut frame = vec![0u8; tcp::MBAP_HEADER_LEN + pdu.len()];
    let mut frame_writer = Writer::new(&mut frame);
    tcp::encode_frame(&mut frame_writer, transaction_id, unit_id, pdu)?;

    debug!(
        correlation_id = transaction_id,
        unit_id = unit_id.as_u8(),
        pdu_len = pdu.len(),
        "sending modbus tcp server response"
    );
    socket.write_all(frame_writer.as_written()).await?;
    Ok(())
}

async fn send_rtu_exception(
    socket: &mut TcpStream,
    unit_id: UnitId,
    function_code: u8,
    exception_code: ExceptionCode,
) -> Result<(), DataLinkError> {
    let mut pdu = [0u8; 2];
    let mut pdu_writer = Writer::new(&mut pdu);
    ExceptionResponse {
        function_code,
        exception_code,
    }
    .encode(&mut pdu_writer)
    .map_err(DataLinkError::Encode)?;

    send_rtu_pdu(socket, unit_id, pdu_writer.as_written()).await
}

async fn send_rtu_pdu(socket: &mut TcpStream, unit_id: UnitId, pdu: &[u8]) -> Result<(), DataLinkError> {
    let mut frame = vec![0u8; pdu.len() + 3];
    let mut writer = Writer::new(&mut frame);
    rtu_frame::encode_frame(&mut writer, unit_id, pdu)?;
    socket.write_all(writer.as_written()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ModbusRtuOverTcpServer, ModbusService, ModbusTcpServer, ServiceError};
    use crate::{DataLink, ModbusTcpTransport};
    use rustmod_core::encoding::Writer;
    use rustmod_core::frame::rtu as rtu_frame;
    use rustmod_core::pdu::{DecodedRequest, ExceptionCode};
    use rustmod_core::UnitId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    struct EchoReadService;

    impl ModbusService for EchoReadService {
        fn handle(
            &self,
            _unit_id: UnitId,
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

    struct AlwaysExceptionService;

    impl ModbusService for AlwaysExceptionService {
        fn handle(
            &self,
            _unit_id: UnitId,
            _request: DecodedRequest<'_>,
            _response_pdu: &mut [u8],
        ) -> Result<usize, ServiceError> {
            Err(ServiceError::Exception(ExceptionCode::IllegalDataAddress))
        }
    }

    #[tokio::test]
    async fn tcp_server_handles_basic_read_request() {
        let server = ModbusTcpServer::bind("127.0.0.1:0", EchoReadService)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(server.run());

        let transport = ModbusTcpTransport::connect(addr).await.unwrap();
        let mut response = [0u8; 32];
        let len = transport
            .exchange(UnitId::new(1), &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
            .await
            .unwrap();
        assert_eq!(&response[..len], &[0x03, 0x02, 0x00, 0x2A]);

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn tcp_server_sends_exception_response() {
        let server = ModbusTcpServer::bind("127.0.0.1:0", AlwaysExceptionService)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(server.run());

        let transport = ModbusTcpTransport::connect(addr).await.unwrap();
        let mut response = [0u8; 32];
        let len = transport
            .exchange(UnitId::new(1), &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
            .await
            .unwrap();
        assert_eq!(&response[..len], &[0x83, 0x02]);

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn tcp_server_maps_decode_error_to_exception() {
        let server = ModbusTcpServer::bind("127.0.0.1:0", EchoReadService)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(server.run());

        let transport = ModbusTcpTransport::connect(addr).await.unwrap();
        let mut response = [0u8; 32];
        let len = transport
            .exchange(
                UnitId::new(1),
                &[0x10, 0x00, 0x00, 0x00, 0x02, 0x03, 0x12, 0x34, 0x56],
                &mut response,
            )
            .await
            .unwrap();
        assert_eq!(&response[..len], &[0x90, 0x03]);

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn rtu_over_tcp_server_handles_basic_read_request() {
        let server = ModbusRtuOverTcpServer::bind("127.0.0.1:0", EchoReadService)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(server.run());

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut request = [0u8; 16];
        let mut writer = Writer::new(&mut request);
        rtu_frame::encode_frame(&mut writer, UnitId::new(1), &[0x03, 0x00, 0x00, 0x00, 0x01]).unwrap();
        stream.write_all(writer.as_written()).await.unwrap();

        let mut response = [0u8; 7];
        stream.read_exact(&mut response).await.unwrap();
        let (unit_id, pdu) = rtu_frame::decode_frame(&response).unwrap();
        assert_eq!(unit_id, UnitId::new(1));
        assert_eq!(pdu, &[0x03, 0x02, 0x00, 0x2A]);

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn rtu_over_tcp_server_maps_decode_error_to_exception() {
        let server = ModbusRtuOverTcpServer::bind("127.0.0.1:0", EchoReadService)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(server.run());

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut request = [0u8; 32];
        let mut writer = Writer::new(&mut request);
        rtu_frame::encode_frame(
            &mut writer,
            UnitId::new(1),
            &[0x10, 0x00, 0x00, 0x00, 0x02, 0x03, 0x12, 0x34, 0x56],
        )
        .unwrap();
        stream.write_all(writer.as_written()).await.unwrap();

        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        let (unit_id, pdu) = rtu_frame::decode_frame(&response).unwrap();
        assert_eq!(unit_id, UnitId::new(1));
        assert_eq!(pdu, &[0x90, 0x03]);

        task.abort();
        let _ = task.await;
    }
}
