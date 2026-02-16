//! High-level Modbus client crate.

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
use rustmod_datalink::{DataLink, DataLinkError};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, warn};

#[cfg(feature = "metrics")]
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicy {
    Never,
    ReadOnly,
    All,
}

#[derive(Debug, Clone, Copy)]
pub struct ClientConfig {
    pub response_timeout: Duration,
    pub retry_count: u8,
    pub throttle_delay: Option<Duration>,
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
    pub fn with_response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = timeout;
        self
    }

    pub fn with_retry_count(mut self, retry_count: u8) -> Self {
        self.retry_count = retry_count;
        self
    }

    pub fn with_throttle_delay(mut self, throttle_delay: Option<Duration>) -> Self {
        self.throttle_delay = throttle_delay;
        self
    }

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("datalink error: {0}")]
    DataLink(#[from] DataLinkError),
    #[error("encode error: {0}")]
    Encode(#[from] EncodeError),
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),
    #[error("request timed out")]
    Timeout,
    #[error("modbus exception: {0:?}")]
    Exception(ExceptionResponse),
    #[error("invalid response: {0}")]
    InvalidResponse(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportServerIdResponse {
    pub server_id: u8,
    pub run_indicator_status: bool,
    pub additional_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentificationObject {
    pub object_id: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDeviceIdentificationResponse {
    pub read_device_id_code: u8,
    pub conformity_level: u8,
    pub more_follows: bool,
    pub next_object_id: u8,
    pub objects: Vec<DeviceIdentificationObject>,
}

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

pub struct ModbusClient<D: DataLink> {
    datalink: D,
    config: ClientConfig,
    last_request_at: Mutex<Option<Instant>>,
    request_counter: AtomicU64,
    #[cfg(feature = "metrics")]
    metrics: Arc<ClientMetrics>,
}

impl<D: DataLink> ModbusClient<D> {
    pub fn new(datalink: D) -> Self {
        Self::with_config(datalink, ClientConfig::default())
    }

    pub fn with_config(datalink: D, config: ClientConfig) -> Self {
        Self {
            datalink,
            config,
            last_request_at: Mutex::new(None),
            request_counter: AtomicU64::new(1),
            #[cfg(feature = "metrics")]
            metrics: Arc::new(ClientMetrics::default()),
        }
    }

    pub fn config(&self) -> ClientConfig {
        self.config
    }

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
            ),
        }
    }

    async fn exchange_raw(
        &self,
        correlation_id: u64,
        unit_id: u8,
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
                        unit_id,
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
                            unit_id,
                            attempt,
                            error = %err,
                            "retrying modbus request after transport error"
                        );
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
                            unit_id,
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
            "retry loop exhausted",
        )))
    }

    async fn send_request<'a>(
        &self,
        unit_id: u8,
        request: &Request<'_>,
        response_storage: &'a mut [u8],
    ) -> Result<Response<'a>, ClientError> {
        let correlation_id = self.next_correlation_id();
        let mut req_buf = [0u8; 260];
        let mut writer = Writer::new(&mut req_buf);
        request.encode(&mut writer)?;

        debug!(
            correlation_id,
            unit_id,
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
            return Err(ClientError::InvalidResponse("trailing bytes in response"));
        }

        if let Response::Exception(ex) = response {
            #[cfg(feature = "metrics")]
            self.metrics.exceptions_total.fetch_add(1, Ordering::Relaxed);
            return Err(ClientError::Exception(ex));
        }

        Ok(response)
    }

    pub async fn read_coils(
        &self,
        unit_id: u8,
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
                if data.coil_status.len() * 8 < count {
                    return Err(ClientError::InvalidResponse(
                        "coil payload shorter than requested",
                    ));
                }
                Ok((0..count).filter_map(|idx| data.coil(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn custom_request(
        &self,
        unit_id: u8,
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
                Err(ClientError::InvalidResponse("custom response function mismatch"))
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn report_server_id(&self, unit_id: u8) -> Result<ReportServerIdResponse, ClientError> {
        let payload = self.custom_request(unit_id, 0x11, &[]).await?;
        let Some((&byte_count, data)) = payload.split_first() else {
            return Err(ClientError::InvalidResponse(
                "report server id payload missing byte count",
            ));
        };
        let byte_count = usize::from(byte_count);
        if data.len() != byte_count || byte_count < 2 {
            return Err(ClientError::InvalidResponse(
                "report server id payload length mismatch",
            ));
        }

        Ok(ReportServerIdResponse {
            server_id: data[0],
            run_indicator_status: data[1] != 0,
            additional_data: data[2..].to_vec(),
        })
    }

    pub async fn read_device_identification(
        &self,
        unit_id: u8,
        read_device_id_code: u8,
        object_id: u8,
    ) -> Result<ReadDeviceIdentificationResponse, ClientError> {
        let payload = self
            .custom_request(unit_id, 0x2B, &[0x0E, read_device_id_code, object_id])
            .await?;

        if payload.len() < 6 {
            return Err(ClientError::InvalidResponse(
                "read device identification payload too short",
            ));
        }
        if payload[0] != 0x0E {
            return Err(ClientError::InvalidResponse(
                "read device identification MEI type mismatch",
            ));
        }

        let object_count = usize::from(payload[5]);
        let mut cursor = 6usize;
        let mut objects = Vec::with_capacity(object_count);
        for _ in 0..object_count {
            if payload.len().saturating_sub(cursor) < 2 {
                return Err(ClientError::InvalidResponse(
                    "read device identification object header truncated",
                ));
            }
            let id = payload[cursor];
            let len = usize::from(payload[cursor + 1]);
            cursor += 2;
            let end = cursor
                .checked_add(len)
                .ok_or(ClientError::InvalidResponse(
                    "read device identification object length overflow",
                ))?;
            if end > payload.len() {
                return Err(ClientError::InvalidResponse(
                    "read device identification object data truncated",
                ));
            }
            objects.push(DeviceIdentificationObject {
                object_id: id,
                value: payload[cursor..end].to_vec(),
            });
            cursor = end;
        }
        if cursor != payload.len() {
            return Err(ClientError::InvalidResponse(
                "read device identification trailing data",
            ));
        }

        Ok(ReadDeviceIdentificationResponse {
            read_device_id_code: payload[1],
            conformity_level: payload[2],
            more_follows: payload[3] != 0,
            next_object_id: payload[4],
            objects,
        })
    }

    pub async fn read_discrete_inputs(
        &self,
        unit_id: u8,
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
                if data.input_status.len() * 8 < count {
                    return Err(ClientError::InvalidResponse(
                        "discrete input payload shorter than requested",
                    ));
                }
                Ok((0..count).filter_map(|idx| data.coil(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn read_holding_registers(
        &self,
        unit_id: u8,
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
                if data.register_count() < count {
                    return Err(ClientError::InvalidResponse(
                        "register payload shorter than requested",
                    ));
                }
                Ok((0..count).filter_map(|idx| data.register(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn read_input_registers(
        &self,
        unit_id: u8,
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
                if data.register_count() < count {
                    return Err(ClientError::InvalidResponse(
                        "register payload shorter than requested",
                    ));
                }
                Ok((0..count).filter_map(|idx| data.register(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn write_single_coil(
        &self,
        unit_id: u8,
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
                Err(ClientError::InvalidResponse("write single coil echo mismatch"))
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn write_single_register(
        &self,
        unit_id: u8,
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
                Err(ClientError::InvalidResponse("write single register echo mismatch"))
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn mask_write_register(
        &self,
        unit_id: u8,
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
                Err(ClientError::InvalidResponse("mask write register echo mismatch"))
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn write_multiple_coils(
        &self,
        unit_id: u8,
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
                Err(ClientError::InvalidResponse("write multiple coils echo mismatch"))
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn write_multiple_registers(
        &self,
        unit_id: u8,
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
                Err(ClientError::InvalidResponse(
                    "write multiple registers echo mismatch",
                ))
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }

    pub async fn read_write_multiple_registers(
        &self,
        unit_id: u8,
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
                if data.register_count() < count {
                    return Err(ClientError::InvalidResponse(
                        "read-write register payload shorter than requested",
                    ));
                }
                Ok((0..count).filter_map(|idx| data.register(idx)).collect())
            }
            _ => Err(ClientError::InvalidResponse("unexpected function response")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientConfig, ClientError, ModbusClient, RetryPolicy};
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
            _unit_id: u8,
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
            _unit_id: u8,
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

        let values = client.read_holding_registers(1, 0, 2).await.unwrap();
        assert_eq!(values, vec![0x1234, 0xABCD]);
    }

    #[tokio::test]
    async fn exception_is_mapped() {
        let link = MockLink::with_responses(vec![Ok(vec![0x83, 0x02])]);
        let client = ModbusClient::new(link);

        let err = client.read_holding_registers(1, 0, 1).await.unwrap_err();
        assert!(matches!(err, ClientError::Exception(_)));
    }

    #[tokio::test]
    async fn custom_request_roundtrip() {
        let link = MockLink::with_responses(vec![Ok(vec![0x41, 0x12, 0x34])]);
        let client = ModbusClient::new(link);

        let payload = client.custom_request(1, 0x41, &[0xAA]).await.unwrap();
        assert_eq!(payload, vec![0x12, 0x34]);
    }

    #[tokio::test]
    async fn report_server_id_parses_payload() {
        let link = MockLink::with_responses(vec![Ok(vec![0x11, 0x03, 0x2A, 0xFF, 0x10])]);
        let client = ModbusClient::new(link);

        let report = client.report_server_id(1).await.unwrap();
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

        let response = client.read_device_identification(1, 0x01, 0x00).await.unwrap();
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
            .read_device_identification(1, 0x01, 0x00)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ClientError::InvalidResponse("read device identification MEI type mismatch")
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

        let values = client.read_holding_registers(1, 0, 1).await.unwrap();
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
        let err = client.write_single_register(1, 1, 42).await.unwrap_err();

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
        let err = client.read_holding_registers(1, 0, 1).await.unwrap_err();

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
        client.write_single_register(1, 1, 42).await.unwrap();

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

        let err = client.read_holding_registers(1, 0, 1).await.unwrap_err();
        assert!(matches!(err, ClientError::Timeout));
        assert_eq!(link_for_assert.call_count(), 2);
    }

    #[tokio::test]
    async fn mask_write_register_success() {
        let link = MockLink::with_responses(vec![Ok(vec![0x16, 0x00, 0x04, 0xFF, 0x00, 0x00, 0x12])]);
        let client = ModbusClient::new(link);
        client
            .mask_write_register(1, 0x0004, 0xFF00, 0x0012)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_write_multiple_registers_success() {
        let link = MockLink::with_responses(vec![Ok(vec![0x17, 0x04, 0x12, 0x34, 0xAB, 0xCD])]);
        let client = ModbusClient::new(link);

        let values = client
            .read_write_multiple_registers(1, 0x0010, 2, 0x0020, &[0x0102, 0x0304])
            .await
            .unwrap();
        assert_eq!(values, vec![0x1234, 0xABCD]);
    }

    #[tokio::test]
    async fn read_coils_rejects_truncated_payload() {
        let link = MockLink::with_responses(vec![Ok(vec![0x01, 0x01, 0b0000_1111])]);
        let client = ModbusClient::new(link);
        let err = client.read_coils(1, 0, 9).await.unwrap_err();
        assert!(matches!(
            err,
            ClientError::InvalidResponse("coil payload shorter than requested")
        ));
    }

    #[tokio::test]
    async fn read_discrete_inputs_rejects_truncated_payload() {
        let link = MockLink::with_responses(vec![Ok(vec![0x02, 0x01, 0b0000_1111])]);
        let client = ModbusClient::new(link);
        let err = client.read_discrete_inputs(1, 0, 9).await.unwrap_err();
        assert!(matches!(
            err,
            ClientError::InvalidResponse("discrete input payload shorter than requested")
        ));
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn metrics_count_success() {
        let link = MockLink::with_responses(vec![Ok(vec![0x03, 0x02, 0x00, 0x2A])]);
        let client = ModbusClient::new(link);

        let _ = client.read_holding_registers(1, 0, 1).await.unwrap();
        let metrics = client.metrics_snapshot();

        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.successful_responses, 1);
        assert_eq!(metrics.exceptions_total, 0);
    }
}
