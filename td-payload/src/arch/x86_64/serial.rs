// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

/// Write a byte to the debug port, converting `\n' to '\r\n`.
fn serial_write_byte(byte: u8) {
    if byte == b'\n' {
        io_write(b'\r')
    }
    io_write(byte)
}

/// Write a string to the debug port.
pub fn serial_write_string(s: &str) {
    for c in s.chars() {
        serial_write_byte(c as u8);
    }
}

const SERIAL_IO_PORT: u16 = 0x3F8;
const INTERRUPT_ENABLE_PORT: u16 = SERIAL_IO_PORT + 1;
const FIFO_CONTROL_PORT: u16 = SERIAL_IO_PORT + 2;
const LINE_CONTROL_PORT: u16 = SERIAL_IO_PORT + 3;
const MODEM_CONTROL_PORT: u16 = SERIAL_IO_PORT + 4;

#[cfg(feature = "tdx")]
fn io_write(byte: u8) {
    tdx_tdcall::tdx::tdvmcall_io_write_8(SERIAL_IO_PORT, byte);
}

#[cfg(not(feature = "tdx"))]
fn io_write(byte: u8) {
    unsafe { x86::io::outb(SERIAL_IO_PORT, byte) };
}

pub fn init() {
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
}
