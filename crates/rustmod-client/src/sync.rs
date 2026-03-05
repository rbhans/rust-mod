use crate::{
    ClientConfig, ClientError, ModbusClient, ReadDeviceIdentificationResponse,
    ReportServerIdResponse, UnitId,
};
use rustmod_datalink::{DataLinkError, ModbusTcpTransport};
use thiserror::Error;
use tokio::runtime::Runtime;

/// Errors that can occur when using [`SyncModbusTcpClient`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SyncClientError {
    /// Failed to initialise the Tokio runtime.
    #[error("runtime init error: {0}")]
    RuntimeInit(std::io::Error),
    /// Transport-level error.
    #[error("datalink error: {0}")]
    DataLink(#[from] DataLinkError),
    /// Error from the underlying async [`ModbusClient`].
    #[error("client error: {0}")]
    Client(#[from] ClientError),
}

/// Blocking Modbus TCP client for use outside an async runtime.
///
/// Internally creates a single-threaded Tokio runtime and delegates to
/// [`ModbusClient`]. All methods block the calling thread until the response
/// arrives or the timeout expires.
pub struct SyncModbusTcpClient {
    runtime: Runtime,
    client: ModbusClient<ModbusTcpTransport>,
}

impl SyncModbusTcpClient {
    /// Connect to a Modbus TCP device at `addr` (e.g. `"192.168.1.10:502"`) with default config.
    pub fn connect(addr: &str) -> Result<Self, SyncClientError> {
        Self::connect_with_config(addr, ClientConfig::default())
    }

    /// Connect to a Modbus TCP device with a custom [`ClientConfig`].
    pub fn connect_with_config(addr: &str, config: ClientConfig) -> Result<Self, SyncClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(SyncClientError::RuntimeInit)?;
        let link = runtime.block_on(ModbusTcpTransport::connect(addr))?;
        let client = ModbusClient::with_config(link, config);
        Ok(Self { runtime, client })
    }

    /// Return the current client configuration.
    pub fn config(&self) -> ClientConfig {
        self.client.config()
    }

    /// Read coils (FC01). See [`ModbusClient::read_coils`](crate::ModbusClient::read_coils).
    pub fn read_coils(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<bool>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_coils(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    /// Read discrete inputs (FC02). See [`ModbusClient::read_discrete_inputs`](crate::ModbusClient::read_discrete_inputs).
    pub fn read_discrete_inputs(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<bool>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_discrete_inputs(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    /// Read holding registers (FC03). See [`ModbusClient::read_holding_registers`](crate::ModbusClient::read_holding_registers).
    pub fn read_holding_registers(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<u16>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_holding_registers(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    /// Read input registers (FC04). See [`ModbusClient::read_input_registers`](crate::ModbusClient::read_input_registers).
    pub fn read_input_registers(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<u16>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_input_registers(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    /// Write a single coil (FC05). See [`ModbusClient::write_single_coil`](crate::ModbusClient::write_single_coil).
    pub fn write_single_coil(
        &self,
        unit_id: UnitId,
        address: u16,
        value: bool,
    ) -> Result<(), SyncClientError> {
        self.runtime
            .block_on(self.client.write_single_coil(unit_id, address, value))
            .map_err(SyncClientError::Client)
    }

    /// Write a single register (FC06). See [`ModbusClient::write_single_register`](crate::ModbusClient::write_single_register).
    pub fn write_single_register(
        &self,
        unit_id: UnitId,
        address: u16,
        value: u16,
    ) -> Result<(), SyncClientError> {
        self.runtime
            .block_on(self.client.write_single_register(unit_id, address, value))
            .map_err(SyncClientError::Client)
    }

    /// Mask write register (FC22). See [`ModbusClient::mask_write_register`](crate::ModbusClient::mask_write_register).
    pub fn mask_write_register(
        &self,
        unit_id: UnitId,
        address: u16,
        and_mask: u16,
        or_mask: u16,
    ) -> Result<(), SyncClientError> {
        self.runtime
            .block_on(
                self.client
                    .mask_write_register(unit_id, address, and_mask, or_mask),
            )
            .map_err(SyncClientError::Client)
    }

    /// Write multiple coils (FC15). See [`ModbusClient::write_multiple_coils`](crate::ModbusClient::write_multiple_coils).
    pub fn write_multiple_coils(
        &self,
        unit_id: UnitId,
        start: u16,
        values: &[bool],
    ) -> Result<(), SyncClientError> {
        self.runtime
            .block_on(self.client.write_multiple_coils(unit_id, start, values))
            .map_err(SyncClientError::Client)
    }

    /// Write multiple registers (FC16). See [`ModbusClient::write_multiple_registers`](crate::ModbusClient::write_multiple_registers).
    pub fn write_multiple_registers(
        &self,
        unit_id: UnitId,
        start: u16,
        values: &[u16],
    ) -> Result<(), SyncClientError> {
        self.runtime
            .block_on(self.client.write_multiple_registers(unit_id, start, values))
            .map_err(SyncClientError::Client)
    }

    /// Read and write multiple registers (FC23). See [`ModbusClient::read_write_multiple_registers`](crate::ModbusClient::read_write_multiple_registers).
    pub fn read_write_multiple_registers(
        &self,
        unit_id: UnitId,
        read_start: u16,
        read_quantity: u16,
        write_start: u16,
        write_values: &[u16],
    ) -> Result<Vec<u16>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_write_multiple_registers(
                unit_id,
                read_start,
                read_quantity,
                write_start,
                write_values,
            ))
            .map_err(SyncClientError::Client)
    }

    /// Send a custom function code request. See [`ModbusClient::custom_request`](crate::ModbusClient::custom_request).
    pub fn custom_request(
        &self,
        unit_id: UnitId,
        function_code: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, SyncClientError> {
        self.runtime
            .block_on(self.client.custom_request(unit_id, function_code, payload))
            .map_err(SyncClientError::Client)
    }

    /// Report Server ID (FC17). See [`ModbusClient::report_server_id`](crate::ModbusClient::report_server_id).
    pub fn report_server_id(&self, unit_id: UnitId) -> Result<ReportServerIdResponse, SyncClientError> {
        self.runtime
            .block_on(self.client.report_server_id(unit_id))
            .map_err(SyncClientError::Client)
    }

    /// Read Device Identification (FC43/0x0E). See [`ModbusClient::read_device_identification`](crate::ModbusClient::read_device_identification).
    pub fn read_device_identification(
        &self,
        unit_id: UnitId,
        read_device_id_code: u8,
        object_id: u8,
    ) -> Result<ReadDeviceIdentificationResponse, SyncClientError> {
        self.runtime
            .block_on(self.client.read_device_identification(
                unit_id,
                read_device_id_code,
                object_id,
            ))
            .map_err(SyncClientError::Client)
    }

    /// Read coils as raw packed bytes (FC01). See [`ModbusClient::read_coils_raw`](crate::ModbusClient::read_coils_raw).
    pub fn read_coils_raw(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<(Vec<u8>, u16), SyncClientError> {
        self.runtime
            .block_on(self.client.read_coils_raw(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    /// Read discrete inputs as raw packed bytes (FC02). See [`ModbusClient::read_discrete_inputs_raw`](crate::ModbusClient::read_discrete_inputs_raw).
    pub fn read_discrete_inputs_raw(
        &self,
        unit_id: UnitId,
        start: u16,
        quantity: u16,
    ) -> Result<(Vec<u8>, u16), SyncClientError> {
        self.runtime
            .block_on(self.client.read_discrete_inputs_raw(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    /// Read Exception Status (FC07). See [`ModbusClient::read_exception_status`](crate::ModbusClient::read_exception_status).
    pub fn read_exception_status(&self, unit_id: UnitId) -> Result<u8, SyncClientError> {
        self.runtime
            .block_on(self.client.read_exception_status(unit_id))
            .map_err(SyncClientError::Client)
    }

    /// Diagnostics (FC08). See [`ModbusClient::diagnostics`](crate::ModbusClient::diagnostics).
    pub fn diagnostics(
        &self,
        unit_id: UnitId,
        sub_function: u16,
        data: u16,
    ) -> Result<(u16, u16), SyncClientError> {
        self.runtime
            .block_on(self.client.diagnostics(unit_id, sub_function, data))
            .map_err(SyncClientError::Client)
    }

    /// Read FIFO Queue (FC24). See [`ModbusClient::read_fifo_queue`](crate::ModbusClient::read_fifo_queue).
    pub fn read_fifo_queue(
        &self,
        unit_id: UnitId,
        address: u16,
    ) -> Result<Vec<u16>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_fifo_queue(unit_id, address))
            .map_err(SyncClientError::Client)
    }
}
