#!/usr/bin/env python3
"""User-space link emulator: a TCP relay that adds one-way delay and a bandwidth cap per direction.

Stand-in for `tc netem`, which the WSL2 kernel doesn't ship (CONFIG_NET_SCH_NETEM unset). No root needed.

    client --> [listen port] link_emu --> [target port] server

Each direction is a FIFO "wire": a chunk of B bytes read at time t starts transmitting when the wire is
free, takes B*8/rate seconds, and arrives `delay` later. So a TLS flight of B bytes costs about
B*8/rate + delay, and every round trip costs at least 2*delay, which is what makes post-quantum
handshakes slower than classical ones on slow links.

Limits (say so in the write-up): it does not model packet loss or TCP congestion control (initial
window, slow start). Both legs to the relay are on loopback, so TCP segmentation happens on loopback.
It models application-level flights crossing a link with fixed latency and bandwidth.

    scripts/link_emu.py --listen 15040 --target 127.0.0.1:15041 --delay-ms 25 --rate-kbps 10000
"""
import argparse, asyncio


async def wire(reader, writer, delay, rate_bps):
    loop = asyncio.get_running_loop()
    q = asyncio.Queue()

    async def rx():
        free_at = 0.0
        while True:
            data = await reader.read(65536)
            now = loop.time()
            if not data:
                await q.put((None, max(now, free_at) + delay))
                return
            start = max(now, free_at)
            free_at = start + (len(data) * 8 / rate_bps if rate_bps else 0.0)
            await q.put((data, free_at + delay))

    async def tx():
        while True:
            data, at = await q.get()
            wait = at - loop.time()
            if wait > 0:
                await asyncio.sleep(wait)
            if data is None:
                try:
                    writer.write_eof()
                except (OSError, RuntimeError):
                    pass
                return
            writer.write(data)
            await writer.drain()

    try:
        await asyncio.gather(rx(), tx())
    except (ConnectionError, OSError):
        pass


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", type=int, required=True, help="port the client connects to")
    ap.add_argument("--target", required=True, help="HOST:PORT of the real server")
    ap.add_argument("--delay-ms", type=float, default=0.0, help="one-way delay (RTT = 2x)")
    ap.add_argument("--rate-kbps", type=float, default=0.0, help="bandwidth per direction, 0 = unlimited")
    a = ap.parse_args()
    th, tp = a.target.rsplit(":", 1)
    delay, rate = a.delay_ms / 1000.0, a.rate_kbps * 1000.0

    async def handle(cr, cw):
        try:
            sr, sw = await asyncio.open_connection(th, int(tp))
        except OSError:
            cw.close()
            return
        for w in (cw, sw):
            sock = w.get_extra_info("socket")
            if sock is not None:
                import socket
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        await asyncio.gather(wire(cr, sw, delay, rate), wire(sr, cw, delay, rate))
        for w in (cw, sw):
            w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", a.listen)
    print(f"link_emu: :{a.listen} -> {a.target}  one-way {a.delay_ms} ms  "
          f"{'unlimited' if not rate else f'{a.rate_kbps:g} kbps'}", flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
