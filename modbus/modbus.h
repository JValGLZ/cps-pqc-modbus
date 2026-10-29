/*
 * modbus.h - minimal Modbus/TCP (MBAP + FC 0x03 / 0x06), enough for the polling experiments.
 *
 * ADU = MBAP header (7 bytes) + PDU
 *   MBAP: transaction id (2) | protocol id (2) = 0 | length (2) = bytes after this field | unit id (1)
 *   0x03 Read Holding Registers  req: addr(2) qty(2)      resp: byte_count(1) values(2*qty)
 *   0x06 Write Single Register   req: addr(2) value(2)    resp: echo of the request
 *   exception response: fc | 0x80, exception code (1)
 * All multi-byte fields are big-endian.
 */
#ifndef MODBUS_H
#define MODBUS_H

#include <stddef.h>
#include <stdint.h>

#include "../transport/transport.h"

#define MB_MBAP_LEN 7
#define MB_MAX_ADU 260
#define MB_MAX_READ_QTY 125

#define MB_FC_READ_HOLDING 0x03
#define MB_FC_WRITE_SINGLE 0x06

#define MB_EX_ILLEGAL_FUNCTION 0x01
#define MB_EX_ILLEGAL_ADDRESS  0x02
#define MB_EX_ILLEGAL_VALUE    0x03

size_t mb_build_read_holding(uint8_t *buf, uint16_t tid, uint8_t unit, uint16_t addr, uint16_t qty);
size_t mb_build_write_single(uint8_t *buf, uint16_t tid, uint8_t unit, uint16_t addr, uint16_t value);

/* Read one full ADU. Returns ADU length, 0 on orderly close before any byte, -1 on error/malformed. */
ssize_t mb_recv_adu(transport *t, uint8_t *buf, size_t cap);

/* Check a response against its request.
 * Returns 0 = OK, >0 = Modbus exception code, -1 = malformed / mismatched. */
int mb_check_response(const uint8_t *req, size_t req_len, const uint8_t *resp, size_t resp_len);

/* Server side: build the response for one request ADU against a register bank.
 * Returns response length, or 0 if the request is malformed (caller should drop the connection). */
size_t mb_server_handle(const uint8_t *req, size_t req_len, uint8_t *resp, uint16_t *regs, uint16_t nregs);

#endif
