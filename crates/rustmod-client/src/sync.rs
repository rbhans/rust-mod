use crate::{
    ClientConfig, ClientError, ModbusClient, ReadDeviceIdentificationResponse,
    ReportServerIdResponse,
};
use rustmod_datalink::{DataLinkError, ModbusTcpTransport};
use thiserror::Error;
use tokio::runtime::Runtime;

#[derive(Debug, Error)]
pub enum SyncClientError {
    #[error("runtime init error: {0}")]
    RuntimeInit(std::io::Error),
    #[error("datalink error: {0}")]
    DataLink(#[from] DataLinkError),
    #[error("client error: {0}")]
    Client(#[from] ClientError),
}

pub struct SyncModbusTcpClient {
    runtime: Runtime,
    client: ModbusClient<ModbusTcpTransport>,
}

impl SyncModbusTcpClient {
    pub fn connect(addr: &str) -> Result<Self, SyncClientError> {
        Self::connect_with_config(addr, ClientConfig::default())
    }

    pub fn connect_with_config(addr: &str, config: ClientConfig) -> Result<Self, SyncClientError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(SyncClientError::RuntimeInit)?;
        let link = runtime.block_on(ModbusTcpTransport::connect(addr))?;
        let client = ModbusClient::with_config(link, config);
        Ok(Self { runtime, client })
    }

    pub fn config(&self) -> ClientConfig {
        self.client.config()
    }

    pub fn read_coils(
        &self,
        unit_id: u8,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<bool>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_coils(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    pub fn read_discrete_inputs(
        &self,
        unit_id: u8,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<bool>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_discrete_inputs(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    pub fn read_holding_registers(
        &self,
        unit_id: u8,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<u16>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_holding_registers(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    pub fn read_input_registers(
        &self,
        unit_id: u8,
        start: u16,
        quantity: u16,
    ) -> Result<Vec<u16>, SyncClientError> {
        self.runtime
            .block_on(self.client.read_input_registers(unit_id, start, quantity))
            .map_err(SyncClientError::Client)
    }

    pub fn write_single_coil(
        &self,
        unit_id: u8,
        address: u16,
        value: bool,
    ) -> Result<(), SyncClientError> {
        self.runtime
            .block_on(self.client.write_single_coil(unit_id, address, value))
            .map_err(SyncClientError::Client)
    }

    pub fn write_single_register(
        &self,
        unit_id: u8,
        address: u16,
        value: u16,
    ) -> Result<(), SyncClientError> {
        self.runtime
            .block_on(self.client.write_single_register(unit_id, address, value))
            .map_err(SyncClientError::Client)
    }

    pub fn mask_write_register(
        &self,
        unit_id: u8,
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

    pub fn write_multiple_coils(
        &self,
        unit_id: u8,
        start: u16,
        values: &[bool],
    ) -> Result<(), SyncClientError> {
        self.runtime
            .block_on(self.client.write_multiple_coils(unit_id, start, values))
            .map_err(SyncClientError::Client)
    }

    pub fn write_multiple_registers(
        &self,
        unit_id: u8,
        start: u16,
        values: &[u16],
    ) -> Result<(), SyncClientError> {
        self.runtime
            .block_on(self.client.write_multiple_registers(unit_id, start, values))
            .map_err(SyncClientError::Client)
    }

    pub fn read_write_multiple_registers(
        &self,
        unit_id: u8,
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

    pub fn custom_request(
        &self,
        unit_id: u8,
        function_code: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, SyncClientError> {
        self.runtime
            .block_on(self.client.custom_request(unit_id, function_code, payload))
            .map_err(SyncClientError::Client)
    }

    pub fn report_server_id(&self, unit_id: u8) -> Result<ReportServerIdResponse, SyncClientError> {
        self.runtime
            .block_on(self.client.report_server_id(unit_id))
            .map_err(SyncClientError::Client)
    }

    pub fn read_device_identification(
        &self,
        unit_id: u8,
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
}
