#include "modbus.h"

#include <string.h>

static inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static size_t put_mbap(uint8_t *buf, uint16_t tid, uint8_t unit, size_t pdu_len)
{
    put16(buf, tid);
    put16(buf + 2, 0);                       /* protocol id: 0 = Modbus */
    put16(buf + 4, (uint16_t)(pdu_len + 1)); /* unit id + PDU */
    buf[6] = unit;
    return MB_MBAP_LEN;
}

size_t mb_build_read_holding(uint8_t *buf, uint16_t tid, uint8_t unit, uint16_t addr, uint16_t qty)
{
    put_mbap(buf, tid, unit, 5);
    buf[7] = MB_FC_READ_HOLDING;
    put16(buf + 8, addr);
    put16(buf + 10, qty);
    return 12;
}

size_t mb_build_write_single(uint8_t *buf, uint16_t tid, uint8_t unit, uint16_t addr, uint16_t value)
{
    put_mbap(buf, tid, unit, 5);
    buf[7] = MB_FC_WRITE_SINGLE;
    put16(buf + 8, addr);
    put16(buf + 10, value);
    return 12;
}

ssize_t mb_recv_adu(transport *t, uint8_t *buf, size_t cap)
{
    if (cap < MB_MAX_ADU) return -1;
    ssize_t n = transport_recv_exact(t, buf, MB_MBAP_LEN);
    if (n <= 0) return n;
    if (get16(buf + 2) != 0) return -1;                 /* not Modbus */
    uint16_t len = get16(buf + 4);                      /* unit id + PDU */
    if (len < 2 || len > MB_MAX_ADU - 6) return -1;     /* PDU is 1..253 bytes */
    n = transport_recv_exact(t, buf + MB_MBAP_LEN, len - 1u);
    if (n != (ssize_t)(len - 1u)) return -1;
    return (ssize_t)(MB_MBAP_LEN + len - 1u);
}

int mb_check_response(const uint8_t *req, size_t req_len, const uint8_t *resp, size_t resp_len)
{
    if (req_len < 8 || resp_len < 9) return -1;
    if (get16(req) != get16(resp)) return -1;           /* transaction id */
    if (req[6] != resp[6]) return -1;                   /* unit id */
    uint8_t fc = req[7];
    if (resp[7] == (fc | 0x80)) return resp[8];         /* exception */
    if (resp[7] != fc) return -1;

    switch (fc) {
    case MB_FC_READ_HOLDING: {
        uint16_t qty = get16(req + 10);
        if (resp[8] != 2 * qty || resp_len != (size_t)(9 + 2 * qty)) return -1;
        return 0;
    }
    case MB_FC_WRITE_SINGLE:
        return (resp_len == req_len && memcmp(req, resp, req_len) == 0) ? 0 : -1;
    default:
        return -1;
    }
}

static size_t exception(const uint8_t *req, uint8_t *resp, uint8_t code)
{
    put_mbap(resp, get16(req), req[6], 2);
    resp[7] = (uint8_t)(req[7] | 0x80);
    resp[8] = code;
    return 9;
}

size_t mb_server_handle(const uint8_t *req, size_t req_len, uint8_t *resp, uint16_t *regs, uint16_t nregs)
{
    if (req_len < 8) return 0;
    size_t pdu_len = req_len - MB_MBAP_LEN;
    uint8_t fc = req[7];

    switch (fc) {
    case MB_FC_READ_HOLDING: {
        if (pdu_len != 5) return exception(req, resp, MB_EX_ILLEGAL_VALUE);
        uint16_t addr = get16(req + 8), qty = get16(req + 10);
        if (qty < 1 || qty > MB_MAX_READ_QTY) return exception(req, resp, MB_EX_ILLEGAL_VALUE);
        if ((uint32_t)addr + qty > nregs) return exception(req, resp, MB_EX_ILLEGAL_ADDRESS);
        put_mbap(resp, get16(req), req[6], 2 + 2u * qty);
        resp[7] = fc;
        resp[8] = (uint8_t)(2 * qty);
        for (uint16_t i = 0; i < qty; i++) put16(resp + 9 + 2 * i, regs[addr + i]);
        return 9 + 2u * qty;
    }
    case MB_FC_WRITE_SINGLE: {
        if (pdu_len != 5) return exception(req, resp, MB_EX_ILLEGAL_VALUE);
        uint16_t addr = get16(req + 8);
        if (addr >= nregs) return exception(req, resp, MB_EX_ILLEGAL_ADDRESS);
        regs[addr] = get16(req + 10);
        memcpy(resp, req, req_len);   /* normal response echoes the request */
        return req_len;
    }
    default:
        return exception(req, resp, MB_EX_ILLEGAL_FUNCTION);
    }
}
