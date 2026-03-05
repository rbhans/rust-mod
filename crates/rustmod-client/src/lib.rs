//! High-level async Modbus client with automatic retries, timeouts, and throttling.
//!
//! This crate provides [`ModbusClient`], an ergonomic async client that wraps any
//! [`DataLink`] transport and handles:
//!
//! - PDU encoding/decoding via `rustmod-core`
//! - Configurable response timeouts
//! - Automatic retries with reconnection on transport errors
//! - Inter-request throttle delays for slow devices
//! - Request/response validation (echo checks, payload lengths)
//! - Optional metrics collection (`metrics` feature)
//!
//! For synchronous (blocking) usage, see [`SyncModbusTcpClient`].
//!
//! # Supported function codes
//!
//! | FC | Method |
//! |----|--------|
//! | 01 | [`read_coils`](ModbusClient::read_coils) |
//! | 02 | [`read_discrete_inputs`](ModbusClient::read_discrete_inputs) |
//! | 03 | [`read_holding_registers`](ModbusClient::read_holding_registers) |
//! | 04 | [`read_input_registers`](ModbusClient::read_input_registers) |
//! | 05 | [`write_single_coil`](ModbusClient::write_single_coil) |
//! | 06 | [`write_single_register`](ModbusClient::write_single_register) |
//! | 07 | [`read_exception_status`](ModbusClient::read_exception_status) |
//! | 08 | [`diagnostics`](ModbusClient::diagnostics) |
//! | 15 | [`write_multiple_coils`](ModbusClient::write_multiple_coils) |
//! | 16 | [`write_multiple_registers`](ModbusClient::write_multiple_registers) |
//! | 22 | [`mask_write_register`](ModbusClient::mask_write_register) |
//! | 23 | [`read_write_multiple_registers`](ModbusClient::read_write_multiple_registers) |
//! | 24 | [`read_fifo_queue`](ModbusClient::read_fifo_queue) |
//! | 17 | [`report_server_id`](ModbusClient::report_server_id) |
//! | 43 | [`read_device_identification`](ModbusClient::read_device_identification) |

#![forbid(unsafe_code)]

pub mod points;
pub mod sync;

pub use points::{CoilPoints, RegisterPoints};
pub use sync::{SyncClientError, SyncModbusTcpClient};

use rustmod_core::encoding::{Reader, Writer};
use rustmod_core::pdu::{
    CustomRequest, ExceptionResponse, ReadCoilsRequest, ReadDiscreteInputsRequest,
    ReadHoldingRegistersRequest, ReadInputRegistersRequest, ReadWriteMultipleRegistersRequest,
    Request, Response, MaskWriteRegisterRequest, WriteMultipleCoilsRequest,
    WriteMultipleRegistersRequest, WriteSingleCoilRequest, WriteSingleRegisterRequest,
};
use rustmod_core::{DecodeError, EncodeError};
pub use rustmod_datalink::UnitId;
use rustmod_datalink::{DataLink, DataLinkError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, warn};

/// Controls which requests are eligible for automatic retry on transport errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryPolicy {
    /// Never retry any request.
    Never,
    /// Only retry read-only requests (FC01–04, FC07, FC08, FC24, FC17, FC43).
    ReadOnly,
    /// Retry all requests, including writes.
    All,
}

/// Configuration for a [`ModbusClient`].
///
/// Use the builder methods to customise, or rely on [`Default`] which provides
/// a 5-second timeout, 3 retries (read-only), and no throttle delay.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct ClientConfig {
    /// Maximum time to wait for a response before returning [`ClientError::Timeout`].
    pub response_timeout: Duration,
    /// Number of additional attempts after the first failure (0 = no retries).
    pub retry_count: u8,
    /// Minimum delay between consecutive requests (useful for slow devices).
    pub throttle_delay: Option<Duration>,
    /// Which request types are eligible for automatic retry.
    pub retry_policy: RetryPolicy,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            response_timeout: Duration::from_secs(5),
            retry_count: 3,
            throttle_delay: None,
            retry_policy: RetryPolicy::ReadOnly,
        }
    }
}

impl ClientConfig {
    /// Set the maximum time to wait for a Modbus response.
    #[must_use = "builder methods return a new value"]
    pub fn with_response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = timeout;
        self
    }

    /// Set the number of retry attempts after the initial request fails.
    #[must_use = "builder methods return a new value"]
    pub fn with_retry_count(mut self, retry_count: u8) -> Self {
        self.retry_count = retry_count;
        self
    }

    /// Set the minimum inter-request delay (throttle).
    #[must_use = "builder methods return a new value"]
    pub fn with_throttle_delay(mut self, throttle_delay: Option<Duration>) -> Self {
        self.throttle_delay = throttle_delay;
        self
    }

    /// Set the retry policy controlling which requests may be retried.
    #[must_use = "builder methods return a new value"]
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }
}

/// Errors that can occur when executing a Modbus request through [`ModbusClient`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Transport-level error (I/O, connection closed, etc.).
    #[error("datalink error: {0}")]
    DataLink(#[from] DataLinkError),
    /// Failed to encode the request PDU.
    #[error("encode error: {0}")]
    Encode(#[from] EncodeError),
    /// Failed to decode the response PDU.
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),
    /// The device did not respond within the configured timeout.
    #[error("request timed out")]
    Timeout,
    /// The device returned a Modbus exception response.
    #[error("modbus exception: {0}")]
    Exception(ExceptionResponse),
    /// The response was structurally invalid.
    #[error("invalid response: {0}")]
    InvalidResponse(InvalidResponseKind),
}

/// Describes why a Modbus response was considered invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidResponseKind {
    /// Extra bytes remain after decoding the response PDU.
    TrailingBytes,
    /// The response function code does not match the request.
    FunctionMismatch,
    /// A write response did not echo the expected address/value.
    EchoMismatch,
    /// The response byte count does not match the requested quantity.
    PayloadLengthMismatch,
    /// The response payload was shorter than expected.
    PayloadTruncated,
    /// Catch-all for other validation failures.
    Other(&'static str),
}

impl std::fmt::Display for InvalidResponseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrailingBytes => f.write_str("trailing bytes in response"),
            Self::FunctionMismatch => f.write_str("unexpected function response"),
            Self::EchoMismatch => f.write_str("echo mismatch"),
            Self::PayloadLengthMismatch => f.write_str("payload length mismatch"),
            Self::PayloadTruncated => f.write_str("payload truncated"),
            Self::Other(msg) => f.write_str(msg),
        }
    }
}

/// Response from FC17 (Report Server ID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportServerIdResponse {
    /// The server's self-reported identifier byte.
    pub server_id: u8,
    /// `true` if the device is in run mode, `false` if halted.
    pub run_indicator_status: bool,
    /// Device-specific additional data (may be empty).
    pub additional_data: Vec<u8>,
}

/// A single object returned in a FC43/0x0E (Read Device Identification) response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentificationObject {
    /// Object ID (e.g. 0x00 = Vendor Name, 0x01 = Product Code, 0x02 = Major Minor Revision).
    pub object_id: u8,
    /// Raw object value bytes (typically UTF-8 text).
    pub value: Vec<u8>,
}

/// Response from FC43/0x0E (Read Device Identification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDeviceIdentificationResponse {
    /// The requested read device ID code (0x01 basic, 0x02 regular, 0x03 extended, 0x04 individual).
    pub read_device_id_code: u8,
    /// Conformity level of the device.
    pub conformity_level: u8,
    /// `true` if more objects are available in subsequent requests.
    pub more_follows: bool,
    /// The object ID to request next when `more_follows` is `true`.
    pub next_object_id: u8,
    /// The identification objects returned by the device.
    pub objects: Vec<DeviceIdentificationObject>,
}

/// Atomic counters tracking client activity (available with the `metrics` feature).
#[cfg(feature = "metrics")]
#[derive(Debug, Default)]
pub struct ClientMetrics {
    requests_total: AtomicU64,
    successful_responses: AtomicU64,
    retries_total: AtomicU64,
    timeouts_total: AtomicU64,
    transport_errors_total: AtomicU64,
    exceptions_total: AtomicU64,
    decode_errors_total: AtomicU64,
}

/// A point-in-time snapshot of [`ClientMetrics`] counters.
#[cfg(feature = "metrics")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientMetricsSnapshot {
    pub requests_total: u64,
    pub successful_responses: u64,
    pub retries_total: u64,
    pub timeouts_total: u64,
    pub transport_errors_total: u64,
    pub exceptions_total: u64,
    pub decode_errors_total: u64,
}

#[cfg(feature = "metrics")]
impl ClientMetrics {
    fn snapshot(&self) -> ClientMetricsSnapshot {
        ClientMetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            successful_responses: self.successful_responses.load(Ordering::Relaxed),
            retries_total: self.retries_total.load(Ordering::Relaxed),
            timeouts_total: self.timeouts_total.load(Ordering::Relaxed),
            transport_errors_total: self.transport_errors_total.load(Ordering::Relaxed),
            exceptions_total: self.exceptions_total.load(Ordering::Relaxed),
            decode_errors_total: self.decode_errors_total.load(Ordering::Relaxed),
        }
    }
}

/// Async Modbus client that wraps a [`DataLink`] transport.
///
/// The client is cheaply cloneable — all clones share the same underlying
/// transport, throttle state, and metrics counters.
pub struct ModbusClient<D: DataLink> {
    datalink: Arc<D>,
    config: ClientConfig,
    last_request_at: Arc<Mutex<Option<Instant>>>,
    request_counter: Arc<AtomicU64>,
    #[cfg(feature = "metrics")]
    metrics: Arc<ClientMetrics>,
}

impl<D: DataLink> Clone for ModbusClient<D> {
    fn clone(&self) -> Self {
        Self {
            datalink: Arc::clone(&self.datalink),
            config: self.config,
            last_request_at: Arc::clone(&self.last_request_at),
            request_counter: Arc::clone(&self.request_counter),
            #[cfg(feature = "metrics")]
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl<D: DataLink> ModbusClient<D> {
    /// Create a new client with default configuration.
    #[must_use]
    pub fn new(datalink: D) -> Self {
        Self::with_config(datalink, ClientConfig::default())
    }

    /// Create a new client with the given configuration.
    #[must_use]
    pub fn with_config(datalink: D, config: ClientConfig) -> Self {
        Self {
            datalink: Arc::new(datalink),
            config,
            last_request_at: Arc::new(Mutex::new(None)),
            request_counter: Arc::new(AtomicU64::new(1)),
            #[cfg(feature = "metrics")]
            metrics: Arc::new(ClientMetrics::default()),
        }
    }

    /// Return the current client configuration.
    pub fn config(&self) -> ClientConfig {
        self.config
    }

    /// Check if the underlying transport is connected.
    pub fn is_connected(&self) -> bool {
        self.datalink.is_connected()
    }

    /// Take a snapshot of the current metrics counters.
    #[cfg(feature = "metrics")]
    pub fn metrics_snapshot(&self) -> ClientMetricsSnapshot {
        self.metrics.snapshot()
    }

    fn next_correlation_id(&self) -> u64 {
        self.request_counter.fetch_add(1, Ordering::Relaxed)
    }

    async fn apply_throttle(&self) {
        let Some(delay) = self.config.throttle_delay else {
            return;
        };

        let mut last = self.last_request_at.lock().await;
        if let Some(previous) = *last {
            let elapsed = previous.elapsed();
            if elapsed < delay {
                sleep(delay - elapsed).await;
            }
        }
        *last = Some(Instant::now());
    }

    fn is_retryable(err: &DataLinkError) -> bool {
        matches!(
            err,
            DataLinkError::Io(_)
                | DataLinkError::Timeout
                | DataLinkError::ConnectionClosed
        )
    }

    fn request_is_retry_eligible(&self, request: &Request<'_>) -> bool {
        match self.config.retry_policy {
            RetryPolicy::Never => false,
            RetryPolicy::All => true,
            RetryPolicy::ReadOnly => matches!(
                request,
                Request::ReadCoils(_)
                    | Request::ReadDiscreteInputs(_)
                    | Request::ReadHoldingRegisters(_)
                    | Request::ReadInputRegisters(_)
                    | Request::ReadExceptionStatus(_)
                    | Request::Diagnostics(_)
                    | Request::ReadFifoQueue(_)
                    | Request::Custom(CustomRequest { function_code: 0x11, .. })
                    | Request::Custom(CustomRequest { function_code: 0x2B, .. })
            ),
        }
    }

    async fn exchange_raw(
        &self,
        correlation_id: u64,
        unit_id: UnitId,
        request_pdu: &[u8],
        response_buf: &mut [u8],
        retry_eligible: bool,
    ) -> Result<usize, ClientError> {
        self.apply_throttle().await;

        #[cfg(feature = "metrics")]
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

        let attempts = usize::from(self.config.retry_count) + 1;
        let mut last_err: Option<ClientError> = None;

        for attempt in 1..=attempts {
            let result = timeout(
                self.config.response_timeout,
                self.datalink.exchange(unit_id, request_pdu, response_buf),
            )
            .await;

            match result {
                Ok(Ok(len)) => {
                    debug!(
                        correlation_id,
                        unit_id = unit_id.as_u8(),
                        attempt,
                        len,
                        "modbus request succeeded"
                    );
                    #[cfg(feature = "metrics")]
                    self.metrics
                        .successful_responses
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(len);
                }
                Ok(Err(err)) => {
                    #[cfg(feature = "metrics")]
                    self.metrics
                        .transport_errors_total
                        .fetch_add(1, Ordering::Relaxed);
                    if attempt < attempts && retry_eligible && Self::is_retryable(&err) {
                        warn!(
                            correlation_id,
                            unit_id = unit_id.as_u8(),
                            attempt,
                            error = %err,
                            "retrying modbus request after transport error"
                        );
                        if let Err(reconnect_err) = self.datalink.reconnect().await {
                            debug!(
                                correlation_id,
                                unit_id = unit_id.as_u8(),
                                error = %reconnect_err,
                                "reconnect attempt failed"
                            );
                        }
                        #[cfg(feature = "metrics")]
                        self.metrics.retries_total.fetch_add(1, Ordering::Relaxed);
                        last_err = Some(ClientError::DataLink(err));
                        continue;
                    }
                    return Err(ClientError::DataLink(err));
                }
                Err(_) => {
                    #[cfg(feature = "metrics")]
                    self.metrics.timeouts_total.fetch_add(1, Ordering::Relaxed);
                    if attempt < attempts && retry_eligible {
                        warn!(
                            correlation_id,
                            unit_id = unit_id.as_u8(),
                            attempt,
                            "retrying modbus request after timeout"
                        );
                        #[cfg(feature = "metrics")]
                        self.metrics.retries_total.fetch_add(1, Ordering::Relaxed);
                        last_err = Some(ClientError::Timeout);
                        continue;
                    }
                    return Err(ClientError::Timeout);
                }
            }
        }

        Err(last_err.unwrap_or(ClientError::InvalidResponse(
            InvalidResponseKind::Other("retry loop exhausted"),
        )))
    }

    async fn send_request<'a>(
        &self,
        unit_id: UnitId,
        request: &Request<'_>,
        response_storage: &'a mut [u8],
    ) -> Result<Response<'a>, ClientError> {
        let correlation_id = self.next_correlation_id();
        let mut req_buf = [0u8; 260];
        let mut writer = Writer::new(&mut req_buf);
        request.encode(&mut writer)?;

        debug!(
            correlation_id,
            unit_id = unit_id.as_u8(),
            function = request.function_code().as_u8(),
            pdu_len = writer.as_written().len(),
            "dispatching modbus request"
        );
        let retry_eligible = self.request_is_retry_eligible(request);

        let response_len = self
            .exchange_raw(
                correlation_id,
                unit_id,
                writer.as_written(),
                response_storage,
                retry_eligible,
            )
            .await?;

        let mut reader = Reader::new(&response_storage[..response_len]);
        let response = match Response::decode(&mut reader) {
            Ok(resp) => resp,
            Err(err) => {
                #[cfg(feature = "metrics")]
                self.metrics
                    .decode_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(ClientError::Decode(err));
            }
        };

        if !reader.is_empty() {
            #[cfg(feature = "metrics")]
            self.metrics
                .decode_errors_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(ClientError::InvalidResponse(InvalidResponseKind::TrailingBytes));
        }

        if let Response::Exception(ex) = response {
            #[cfg(feature = "metrics")]
            self.metrics.exceptions_total.fetch_add(1, Ordering::Relaxed);
            return Err(ClientError::Exception(ex));
        }

        Ok(response)
    }

    /// Read coils (FC01) starting at `start`, returning `quantity` boolean values.
    pub async fn read_coils(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<bool>, ClientError> {
        let request = Request::ReadCoils(ReadCoilsRequest {
            start_address: start,
            quantity,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::ReadCoils(data) => {
                let count = usize::from(quantity);
                let expected_bytes = count.div_ceil(8);
                if data.coil_status.len() != expected_bytes {
                    return Err(ClientError::InvalidResponse(InvalidResponseKind::PayloadLengthMismatch));
                }
                Ok((0..count).filter_map(|idx| data.coil(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Send a custom (user-defined) function code request and return the raw response payload.
    pub async fn custom_request(
        &self,
        unit_id: UnitId,
        function_code: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let request = Request::Custom(CustomRequest {
            function_code,
            data: payload,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::Custom(custom) if custom.function_code == function_code => {
                Ok(custom.data.to_vec())
            }
            Response::Custom(_) => {
                Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch))
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Report Server ID (FC17) — returns the device identifier and run status.
    pub async fn report_server_id(&self, unit_id: UnitId) -> Result<ReportServerIdResponse, ClientError> {
        let payload = self.custom_request(unit_id, 0x11, &[]).await?;
        let Some((&byte_count, data)) = payload.split_first() else {
            return Err(ClientError::InvalidResponse(InvalidResponseKind::Other("report server id payload missing byte count")));
        };
        let byte_count = usize::from(byte_count);
        if data.len() != byte_count || byte_count < 2 {
            return Err(ClientError::InvalidResponse(InvalidResponseKind::Other("report server id payload length mismatch")));
        }

        Ok(ReportServerIdResponse {
            server_id: data[0],
            run_indicator_status: data[1] != 0,
            additional_data: data[2..].to_vec(),
        })
    }

    /// Read Device Identification (FC43/0x0E) — returns device info objects.
    pub async fn read_device_identification(
        &self,
        unit_id: UnitId,
        read_device_id_code: u8,
        object_id: u8,
    ) -> Result<ReadDeviceIdentificationResponse, ClientError> {
        let payload = self
            .custom_request(unit_id, 0x2B, &[0x0E, read_device_id_code, object_id])
            .await?;

        if payload.len() < 6 {
            return Err(ClientError::InvalidResponse(InvalidResponseKind::Other("read device identification payload too short")));
        }
        if payload[0] != 0x0E {
            return Err(ClientError::InvalidResponse(InvalidResponseKind::Other("read device identification MEI type mismatch")));
        }

        let object_count = usize::from(payload[5]);
        let mut cursor = 6usize;
        let mut objects = Vec::with_capacity(object_count);
        for _ in 0..object_count {
            if payload.len().saturating_sub(cursor) < 2 {
                return Err(ClientError::InvalidResponse(InvalidResponseKind::Other("read device identification object header truncated")));
            }
            let id = payload[cursor];
            let len = usize::from(payload[cursor + 1]);
            cursor += 2;
            let end = cursor
                .checked_add(len)
                .ok_or(ClientError::InvalidResponse(InvalidResponseKind::Other("read device identification object length overflow")))?;
            if end > payload.len() {
                return Err(ClientError::InvalidResponse(InvalidResponseKind::Other("read device identification object data truncated")));
            }
            objects.push(DeviceIdentificationObject {
                object_id: id,
                value: payload[cursor..end].to_vec(),
            });
            cursor = end;
        }
        if cursor != payload.len() {
            return Err(ClientError::InvalidResponse(InvalidResponseKind::Other("read device identification trailing data")));
        }

        Ok(ReadDeviceIdentificationResponse {
            read_device_id_code: payload[1],
            conformity_level: payload[2],
            more_follows: payload[3] != 0,
            next_object_id: payload[4],
            objects,
        })
    }

    /// Read discrete inputs (FC02) starting at `start`, returning `quantity` boolean values.
    pub async fn read_discrete_inputs(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<bool>, ClientError> {
        let request = Request::ReadDiscreteInputs(ReadDiscreteInputsRequest {
            start_address: start,
            quantity,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::ReadDiscreteInputs(data) => {
                let count = usize::from(quantity);
                let expected_bytes = count.div_ceil(8);
                if data.input_status.len() != expected_bytes {
                    return Err(ClientError::InvalidResponse(InvalidResponseKind::PayloadLengthMismatch));
                }
                Ok((0..count).filter_map(|idx| data.coil(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Read holding registers (FC03) starting at `start`, returning `quantity` 16-bit values.
    pub async fn read_holding_registers(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<u16>, ClientError> {
        let request = Request::ReadHoldingRegisters(ReadHoldingRegistersRequest {
            start_address: start,
            quantity,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::ReadHoldingRegisters(data) => {
                let count = usize::from(quantity);
                if data.register_count() != count {
                    return Err(ClientError::InvalidResponse(InvalidResponseKind::PayloadLengthMismatch));
                }
                Ok((0..count).filter_map(|idx| data.register(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Read input registers (FC04) starting at `start`, returning `quantity` 16-bit values.
    pub async fn read_input_registers(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<u16>, ClientError> {
        let request = Request::ReadInputRegisters(ReadInputRegistersRequest {
            start_address: start,
            quantity,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::ReadInputRegisters(data) => {
                let count = usize::from(quantity);
                if data.register_count() != count {
                    return Err(ClientError::InvalidResponse(InvalidResponseKind::PayloadLengthMismatch));
                }
                Ok((0..count).filter_map(|idx| data.register(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Write a single coil (FC05) at `address` to `value`.
    pub async fn write_single_coil(
        &self,
        unit_id: UnitId,
        address: u16,
        value: bool,
    ) -> Result<(), ClientError> {
        let request = Request::WriteSingleCoil(WriteSingleCoilRequest { address, value });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::WriteSingleCoil(resp) if resp.address == address && resp.value == value => Ok(()),
            Response::WriteSingleCoil(_) => {
                Err(ClientError::InvalidResponse(InvalidResponseKind::EchoMismatch))
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Write a single holding register (FC06) at `address` to `value`.
    pub async fn write_single_register(
        &self,
        unit_id: UnitId,
        address: u16,
        value: u16,
    ) -> Result<(), ClientError> {
        let request = Request::WriteSingleRegister(WriteSingleRegisterRequest { address, value });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::WriteSingleRegister(resp) if resp.address == address && resp.value == value => {
                Ok(())
            }
            Response::WriteSingleRegister(_) => {
                Err(ClientError::InvalidResponse(InvalidResponseKind::EchoMismatch))
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Mask write register (FC22): `result = (current AND and_mask) OR (or_mask AND NOT and_mask)`.
    pub async fn mask_write_register(
        &self,
        unit_id: UnitId,
        address: u16,
        and_mask: u16,
        or_mask: u16,
    ) -> Result<(), ClientError> {
        let request = Request::MaskWriteRegister(MaskWriteRegisterRequest {
            address,
            and_mask,
            or_mask,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::MaskWriteRegister(resp)
                if resp.address == address && resp.and_mask == and_mask && resp.or_mask == or_mask =>
            {
                Ok(())
            }
            Response::MaskWriteRegister(_) => {
                Err(ClientError::InvalidResponse(InvalidResponseKind::EchoMismatch))
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Write multiple coils (FC15) starting at `start`.
    pub async fn write_multiple_coils(
        &self,
        unit_id: UnitId,
        start: u16,
        values: &[bool],
    ) -> Result<(), ClientError> {
        let request_variant = WriteMultipleCoilsRequest {
            start_address: start,
            values,
        };
        let expected_qty = request_variant.quantity()?;

        let request = Request::WriteMultipleCoils(request_variant);
        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::WriteMultipleCoils(resp)
                if resp.start_address == start && resp.quantity == expected_qty =>
            {
                Ok(())
            }
            Response::WriteMultipleCoils(_) => {
                Err(ClientError::InvalidResponse(InvalidResponseKind::EchoMismatch))
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Write multiple holding registers (FC16) starting at `start`.
    pub async fn write_multiple_registers(
        &self,
        unit_id: UnitId,
        start: u16,
        values: &[u16],
    ) -> Result<(), ClientError> {
        let request_variant = WriteMultipleRegistersRequest {
            start_address: start,
            values,
        };
        let expected_qty = request_variant.quantity()?;

        let request = Request::WriteMultipleRegisters(request_variant);
        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::WriteMultipleRegisters(resp)
                if resp.start_address == start && resp.quantity == expected_qty =>
            {
                Ok(())
            }
            Response::WriteMultipleRegisters(_) => {
                Err(ClientError::InvalidResponse(InvalidResponseKind::EchoMismatch))
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Atomically read and write multiple registers (FC23).
    pub async fn read_write_multiple_registers(
        &self,
        unit_id: UnitId,
        read_start: u16,
        read_quantity: u16,
        write_start: u16,
        write_values: &[u16],
    ) -> Result<Vec<u16>, ClientError> {
        let request = Request::ReadWriteMultipleRegisters(ReadWriteMultipleRegistersRequest {
            read_start_address: read_start,
            read_quantity,
            write_start_address: write_start,
            values: write_values,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::ReadWriteMultipleRegisters(data) => {
                let count = usize::from(read_quantity);
                if data.register_count() != count {
                    return Err(ClientError::InvalidResponse(InvalidResponseKind::PayloadLengthMismatch));
                }
                Ok((0..count).filter_map(|idx| data.register(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Read coils returning raw packed bytes and the quantity, avoiding the
    /// 8x memory expansion of `Vec<bool>`.
    pub async fn read_coils_raw(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<(Vec<u8>, u16), ClientError> {
        let request = Request::ReadCoils(ReadCoilsRequest {
            start_address: start,
            quantity,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::ReadCoils(data) => {
                let expected_bytes = usize::from(quantity).div_ceil(8);
                if data.coil_status.len() != expected_bytes {
                    return Err(ClientError::InvalidResponse(InvalidResponseKind::PayloadLengthMismatch));
                }
                Ok((data.coil_status.to_vec(), quantity))
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// Read discrete inputs returning raw packed bytes and the quantity.
    pub async fn read_discrete_inputs_raw(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<(Vec<u8>, u16), ClientError> {
        let request = Request::ReadDiscreteInputs(ReadDiscreteInputsRequest {
            start_address: start,
            quantity,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::ReadDiscreteInputs(data) => {
                let expected_bytes = usize::from(quantity).div_ceil(8);
                if data.input_status.len() != expected_bytes {
                    return Err(ClientError::InvalidResponse(InvalidResponseKind::PayloadLengthMismatch));
                }
                Ok((data.input_status.to_vec(), quantity))
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// FC07 - Read Exception Status
    pub async fn read_exception_status(
        &self,
        unit_id: UnitId,
    ) -> Result<u8, ClientError> {
        use rustmod_core::pdu::ReadExceptionStatusRequest;
        let request = Request::ReadExceptionStatus(ReadExceptionStatusRequest);

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::ReadExceptionStatus(data) => Ok(data.data),
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// FC08 - Diagnostics
    pub async fn diagnostics(
        &self,
        unit_id: UnitId,
        sub_function: u16,
        data: u16,
    ) -> Result<(u16, u16), ClientError> {
        use rustmod_core::pdu::DiagnosticsRequest;
        let request = Request::Diagnostics(DiagnosticsRequest { sub_function, data });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::Diagnostics(resp) => Ok((resp.sub_function, resp.data)),
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }

    /// FC24 - Read FIFO Queue
    pub async fn read_fifo_queue(
        &self,
        unit_id: UnitId,
        address: u16,
    ) -> Result<Vec<u16>, ClientError> {
        use rustmod_core::pdu::ReadFifoQueueRequest;
        let request = Request::ReadFifoQueue(ReadFifoQueueRequest {
            fifo_pointer_address: address,
        });

        let mut response_buf = [0u8; 260];
        let response = self
            .send_request(unit_id, &request, &mut response_buf)
            .await?;

        match response {
            Response::ReadFifoQueue(data) => {
                Ok((0..data.fifo_count())
                    .filter_map(|idx| data.value(idx))
                    .collect())
            }
            _ => Err(ClientError::InvalidResponse(InvalidResponseKind::FunctionMismatch)),
        }
    }
}

#[cfg(test)]
const _: () = {
    fn _assert_send_sync<T: Send + Sync>() {}
    fn _assertions() {
        _assert_send_sync::<ModbusClient<rustmod_datalink::ModbusTcpTransport>>();
    }
};

#[cfg(test)]
mod tests {
    use super::{ClientConfig, ClientError, InvalidResponseKind, ModbusClient, RetryPolicy, UnitId};
    use async_trait::async_trait;
    use rustmod_datalink::{DataLink, DataLinkError};
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tokio::time::sleep;

    type MockQueue = VecDeque<Result<Vec<u8>, DataLinkError>>;

    #[derive(Clone, Default)]
    struct MockLink {
        responses: Arc<Mutex<MockQueue>>,
        calls: Arc<AtomicUsize>,
    }

    impl MockLink {
        fn with_responses(responses: Vec<Result<Vec<u8>, DataLinkError>>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into())),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl DataLink for MockLink {
        async fn exchange(
            &self,
            _unit_id: UnitId,
            _request_pdu: &[u8],
            response_pdu: &mut [u8],
        ) -> Result<usize, DataLinkError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut guard = self.responses.lock().await;
            let next = guard
                .pop_front()
                .ok_or(DataLinkError::InvalidResponse("no mock response"))?;
            let bytes = next?;
            if bytes.len() > response_pdu.len() {
                return Err(DataLinkError::ResponseBufferTooSmall {
                    needed: bytes.len(),
                    available: response_pdu.len(),
                });
            }
            response_pdu[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    #[derive(Clone, Default)]
    struct ConnectionClosedThenSlowLink {
        calls: Arc<AtomicUsize>,
    }

    impl ConnectionClosedThenSlowLink {
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl DataLink for ConnectionClosedThenSlowLink {
        async fn exchange(
            &self,
            _unit_id: UnitId,
            _request_pdu: &[u8],
            response_pdu: &mut [u8],
        ) -> Result<usize, DataLinkError> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            if call == 0 {
                return Err(DataLinkError::ConnectionClosed);
            }

            sleep(Duration::from_millis(50)).await;
            response_pdu[..4].copy_from_slice(&[0x03, 0x02, 0x00, 0x2A]);
            Ok(4)
        }
    }

    #[tokio::test]
    async fn read_holding_registers_success() {
        let link = MockLink::with_responses(vec![Ok(vec![
            0x03, 0x04, 0x12, 0x34, 0xAB, 0xCD,
        ])]);
        let client = ModbusClient::new(link);

        let values = client.read_holding_registers(UnitId::new(1), 0, 2).await.unwrap();
        assert_eq!(values, vec![0x1234, 0xABCD]);
    }

    #[tokio::test]
    async fn exception_is_mapped() {
        let link = MockLink::with_responses(vec![Ok(vec![0x83, 0x02])]);
        let client = ModbusClient::new(link);

        let err = client.read_holding_registers(UnitId::new(1), 0, 1).await.unwrap_err();
        assert!(matches!(err, ClientError::Exception(_)));
    }

    #[tokio::test]
    async fn custom_request_roundtrip() {
        let link = MockLink::with_responses(vec![Ok(vec![0x41, 0x12, 0x34])]);
        let client = ModbusClient::new(link);

        let payload = client.custom_request(UnitId::new(1), 0x41, &[0xAA]).await.unwrap();
        assert_eq!(payload, vec![0x12, 0x34]);
    }

    #[tokio::test]
    async fn report_server_id_parses_payload() {
        let link = MockLink::with_responses(vec![Ok(vec![0x11, 0x03, 0x2A, 0xFF, 0x10])]);
        let client = ModbusClient::new(link);

        let report = client.report_server_id(UnitId::new(1)).await.unwrap();
        assert_eq!(report.server_id, 0x2A);
        assert!(report.run_indicator_status);
        assert_eq!(report.additional_data, vec![0x10]);
    }

    #[tokio::test]
    async fn read_device_identification_parses_objects() {
        let link = MockLink::with_responses(vec![Ok(vec![
            0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x07, b'r', b'u', b's', b't', b'-',
            b'm', b'o', 0x01, 0x03, b'0', b'.', b'1',
        ])]);
        let client = ModbusClient::new(link);

        let response = client.read_device_identification(UnitId::new(1), 0x01, 0x00).await.unwrap();
        assert_eq!(response.read_device_id_code, 0x01);
        assert_eq!(response.conformity_level, 0x01);
        assert!(!response.more_follows);
        assert_eq!(response.next_object_id, 0x00);
        assert_eq!(response.objects.len(), 2);
        assert_eq!(response.objects[0].object_id, 0x00);
        assert_eq!(response.objects[0].value, b"rust-mo".to_vec());
        assert_eq!(response.objects[1].object_id, 0x01);
        assert_eq!(response.objects[1].value, b"0.1".to_vec());
    }

    #[tokio::test]
    async fn read_device_identification_rejects_wrong_mei_type() {
        let link = MockLink::with_responses(vec![Ok(vec![
            0x2B, 0x0D, 0x01, 0x01, 0x00, 0x00, 0x00,
        ])]);
        let client = ModbusClient::new(link);

        let err = client
            .read_device_identification(UnitId::new(1), 0x01, 0x00)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ClientError::InvalidResponse(InvalidResponseKind::Other("read device identification MEI type mismatch"))
        ));
    }

    #[tokio::test]
    async fn retries_after_connection_closed() {
        let link = MockLink::with_responses(vec![
            Err(DataLinkError::ConnectionClosed),
            Ok(vec![0x03, 0x02, 0x00, 0x2A]),
        ]);
        let link_for_assert = link.clone();

        let client = ModbusClient::with_config(link, ClientConfig::default().with_retry_count(1));

        let values = client.read_holding_registers(UnitId::new(1), 0, 1).await.unwrap();
        assert_eq!(values, vec![42]);
        assert_eq!(link_for_assert.call_count(), 2);
    }

    #[tokio::test]
    async fn write_is_not_retried_by_default() {
        let link = MockLink::with_responses(vec![
            Err(DataLinkError::ConnectionClosed),
            Ok(vec![0x06, 0x00, 0x01, 0x00, 0x2A]),
        ]);
        let link_for_assert = link.clone();

        let client = ModbusClient::with_config(link, ClientConfig::default().with_retry_count(1));
        let err = client.write_single_register(UnitId::new(1), 1, 42).await.unwrap_err();

        assert!(matches!(
            err,
            ClientError::DataLink(DataLinkError::ConnectionClosed)
        ));
        assert_eq!(link_for_assert.call_count(), 1);
    }

    #[tokio::test]
    async fn response_buffer_too_small_is_not_retried() {
        let link = MockLink::with_responses(vec![
            Err(DataLinkError::ResponseBufferTooSmall {
                needed: 300,
                available: 260,
            }),
            Ok(vec![0x03, 0x02, 0x00, 0x2A]),
        ]);
        let link_for_assert = link.clone();

        let client = ModbusClient::with_config(link, ClientConfig::default().with_retry_count(1));
        let err = client.read_holding_registers(UnitId::new(1), 0, 1).await.unwrap_err();

        assert!(matches!(
            err,
            ClientError::DataLink(DataLinkError::ResponseBufferTooSmall { .. })
        ));
        assert_eq!(link_for_assert.call_count(), 1);
    }

    #[tokio::test]
    async fn write_can_retry_when_policy_is_all() {
        let link = MockLink::with_responses(vec![
            Err(DataLinkError::ConnectionClosed),
            Ok(vec![0x06, 0x00, 0x01, 0x00, 0x2A]),
        ]);
        let link_for_assert = link.clone();

        let config = ClientConfig::default()
            .with_retry_count(1)
            .with_retry_policy(RetryPolicy::All);
        let client = ModbusClient::with_config(link, config);
        client.write_single_register(UnitId::new(1), 1, 42).await.unwrap();

        assert_eq!(link_for_assert.call_count(), 2);
    }

    #[tokio::test]
    async fn final_timeout_is_reported_over_previous_transport_error() {
        let link = ConnectionClosedThenSlowLink::default();
        let link_for_assert = link.clone();

        let config = ClientConfig::default()
            .with_retry_count(1)
            .with_response_timeout(Duration::from_millis(10));
        let client = ModbusClient::with_config(link, config);

        let err = client.read_holding_registers(UnitId::new(1), 0, 1).await.unwrap_err();
        assert!(matches!(err, ClientError::Timeout));
        assert_eq!(link_for_assert.call_count(), 2);
    }

    #[tokio::test]
    async fn mask_write_register_success() {
        let link = MockLink::with_responses(vec![Ok(vec![0x16, 0x00, 0x04, 0xFF, 0x00, 0x00, 0x12])]);
        let client = ModbusClient::new(link);
        client
            .mask_write_register(UnitId::new(1), 0x0004, 0xFF00, 0x0012)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_write_multiple_registers_success() {
        let link = MockLink::with_responses(vec![Ok(vec![0x17, 0x04, 0x12, 0x34, 0xAB, 0xCD])]);
        let client = ModbusClient::new(link);

        let values = client
            .read_write_multiple_registers(UnitId::new(1), 0x0010, 2, 0x0020, &[0x0102, 0x0304])
            .await
            .unwrap();
        assert_eq!(values, vec![0x1234, 0xABCD]);
    }

    #[tokio::test]
    async fn read_coils_rejects_truncated_payload() {
        let link = MockLink::with_responses(vec![Ok(vec![0x01, 0x01, 0b0000_1111])]);
        let client = ModbusClient::new(link);
        let err = client.read_coils(UnitId::new(1), 0, 9).await.unwrap_err();
        assert!(matches!(
            err,
            ClientError::InvalidResponse(InvalidResponseKind::PayloadLengthMismatch)
        ));
    }

    #[tokio::test]
    async fn read_discrete_inputs_rejects_truncated_payload() {
        let link = MockLink::with_responses(vec![Ok(vec![0x02, 0x01, 0b0000_1111])]);
        let client = ModbusClient::new(link);
        let err = client.read_discrete_inputs(UnitId::new(1), 0, 9).await.unwrap_err();
        assert!(matches!(
            err,
            ClientError::InvalidResponse(InvalidResponseKind::PayloadLengthMismatch)
        ));
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn metrics_count_success() {
        let link = MockLink::with_responses(vec![Ok(vec![0x03, 0x02, 0x00, 0x2A])]);
        let client = ModbusClient::new(link);

        let _ = client.read_holding_registers(UnitId::new(1), 0, 1).await.unwrap();
        let metrics = client.metrics_snapshot();

        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.successful_responses, 1);
        assert_eq!(metrics.exceptions_total, 0);
    }
}
