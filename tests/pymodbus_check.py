#!/usr/bin/env python3
"""Interop check: an independent Modbus implementation (pymodbus) talks to our C mb_server.

    ./bin/mb_server --port 1502 &
    python3 tests/pymodbus_check.py --port 1502

Passes if pymodbus can read registers, write one, read it back, and gets an
"illegal data address" exception for an out-of-range read.
"""
import argparse
import inspect
import sys

from pymodbus.client import ModbusTcpClient


def unit_kw(fn):
    # pymodbus renamed the unit-id keyword over time: unit -> slave -> device_id
    params = inspect.signature(fn).parameters
    for name in ("device_id", "slave", "unit"):
        if name in params:
            return name
    return None


def call(fn, *args, unit=1, **kw):
    k = unit_kw(fn)
    if k:
        kw[k] = unit
    return fn(*args, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1502)
    ap.add_argument("--regs", type=int, default=100, help="register count the server was started with")
    a = ap.parse_args()

    c = ModbusTcpClient(a.host, port=a.port)
    if not c.connect():
        sys.exit(f"FAIL: cannot connect to {a.host}:{a.port}")
    ok = True

    r = call(c.read_holding_registers, 1, count=9)
    if r.isError() or list(r.registers) != list(range(1, 10)):
        print("FAIL read 1..9:", r); ok = False
    else:
        print("ok   read holding registers 1..9 ->", list(r.registers))

    w = call(c.write_register, 5, 1234)
    r = call(c.read_holding_registers, 5, count=1)
    if w.isError() or r.isError() or r.registers[0] != 1234:
        print("FAIL write/readback:", w, r); ok = False
    else:
        print("ok   write register 5 = 1234, read back", r.registers[0])
    call(c.write_register, 5, 5)  # restore

    r = call(c.read_holding_registers, a.regs - 5, count=10)
    if r.isError() and getattr(r, "exception_code", None) == 2:
        print("ok   out-of-range read -> exception 2 (illegal data address)")
    else:
        print("FAIL out-of-range read should raise exception 2:", r); ok = False

    c.close()
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
