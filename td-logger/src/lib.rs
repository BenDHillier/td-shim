// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

use log::{Level, Metadata, Record};
use log::{LevelFilter, SetLoggerError};

mod logger;
pub use logger::*;

macro_rules! tdlog {
    ($($arg:tt)*) => (crate::logger::_log_ex(crate::logger::LOG_LEVEL_INFO, crate::logger::LOG_MASK_ALL, format_args!($($arg)*)));
}

/// Logger backend for td-shim.
pub struct LoggerBackend;

impl log::Log for LoggerBackend {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            tdlog!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

/// Logger backend for the log crate
static LOGGER_BACKEND: LoggerBackend = LoggerBackend;

#[cfg(any(
    all(not(feature = "tdx"), feature = "serial-port"),
    all(
        feature = "tdx",
        not(feature = "tdg_dbg"),
        not(feature = "no-tdvmcall")
    ),
    all(not(feature = "tdx"), feature = "serial-port")
))]
const SERIAL_IO_PORT: u16 = 0x3F8;
const INTERRUPT_ENABLE_PORT: u16 = SERIAL_IO_PORT + 1;
const FIFO_CONTROL_PORT: u16 = SERIAL_IO_PORT + 2;
const LINE_CONTROL_PORT: u16 = SERIAL_IO_PORT + 3;
const MODEM_CONTROL_PORT: u16 = SERIAL_IO_PORT + 4;

pub fn init() -> Result<(), SetLoggerError> {
    // Disable interrupts
    tdx_tdcall::tdx::tdvmcall_io_write_8(INTERRUPT_ENABLE_PORT, 0 as u8);

    // Enable the Divisor Latch Access Bit (DLAB) to configure baud rate.
    // When DLAB is set, the Serial port and IE port function as the divisor
    // latch registers
    tdx_tdcall::tdx::tdvmcall_io_write_8(LINE_CONTROL_PORT, 0x80 as u8);
    // Set baud rate to 115200 (DLL=1, DLM=0)
    tdx_tdcall::tdx::tdvmcall_io_write_8(SERIAL_IO_PORT, 0x1 as u8);
    tdx_tdcall::tdx::tdvmcall_io_write_8(INTERRUPT_ENABLE_PORT, 0 as u8);

    // Disable DLAB and set word length to 8 bits
    tdx_tdcall::tdx::tdvmcall_io_write_8(LINE_CONTROL_PORT, 0x3 as u8);

    // Enable FIFO, clear TX/RX queues and
    // set interrupt watermark at 14 bytes
    tdx_tdcall::tdx::tdvmcall_io_write_8(FIFO_CONTROL_PORT, 0xc7 as u8);

    // Set data terminal ready
    tdx_tdcall::tdx::tdvmcall_io_write_8(MODEM_CONTROL_PORT, 0xb as u8);

    // Enable interrupts
    tdx_tdcall::tdx::tdvmcall_io_write_8(INTERRUPT_ENABLE_PORT, 1 as u8);

    log::set_logger(&LOGGER_BACKEND).map(|()| log::set_max_level(LevelFilter::Info))
}

/// Write a byte to the debug port, converting `\n' to '\r\n`.
pub fn dbg_write_byte(byte: u8) {
    if byte == b'\n' {
        dbg_port_write(b'\r')
    }
    dbg_port_write(byte)
}

/// Write a string to the debug port.
pub fn dbg_write_string(s: &str) {
    for c in s.chars() {
        dbg_write_byte(c as u8);
    }
}

// tdx, tdg_dbg
#[cfg(all(feature = "tdx", feature = "tdg_dbg"))]
fn dbg_port_write(byte: u8) {
    tdx_tdcall::tdx::tdcall_tdg_debug_write_8(byte);
}

// tdx, !tdg_dbg, no-tdvmcall
#[cfg(all(feature = "tdx", not(feature = "tdg_dbg"), feature = "no-tdvmcall"))]
fn dbg_port_write(_byte: u8) {
    // no-tdvmcall but tdx present, skip port write
}

// tdx, !tdg_dbg, !no-tdvmcall
#[cfg(all(
    feature = "tdx",
    not(feature = "tdg_dbg"),
    not(feature = "no-tdvmcall")
))]
fn dbg_port_write(byte: u8) {
    tdx_tdcall::tdx::tdvmcall_io_write_8(SERIAL_IO_PORT, byte);
}

// !tdx, serial-port
#[cfg(all(not(feature = "tdx"), feature = "serial-port"))]
fn dbg_port_write(byte: u8) {
    unsafe { x86::io::outb(SERIAL_IO_PORT, byte) };
}

// !tdx, !serial-port
#[cfg(not(any(feature = "tdx", feature = "serial-port")))]
fn dbg_port_write(_byte: u8) {
    // fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger() {
        init().unwrap();

        assert_eq!(LOGGER.lock().get_level(), LOG_LEVEL_INFO);
        LOGGER.lock().set_level(LOG_LEVEL_ERROR);
        assert_eq!(LOGGER.lock().get_level(), LOG_LEVEL_ERROR);

        assert_eq!(LOGGER.lock().get_mask(), LOG_MASK_ALL);
        LOGGER.lock().set_mask(LOG_MASK_COMMON);
        assert_eq!(LOGGER.lock().get_mask(), LOG_MASK_COMMON);

        LOGGER.lock().write_byte(0x1);
        LOGGER.lock().write_string("Hello");

        LOGGER.lock().set_level(LOG_LEVEL_INFO);
        log::error!("just a test");
    }
}
