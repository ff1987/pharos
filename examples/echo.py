#!/usr/bin/env python3
"""Tiny TCP echo for the Pharos loopback demo. Listens on 127.0.0.1:7000."""

import socket

def main() -> None:
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 7000))
    server.listen()
    print("echo listening on 127.0.0.1:7000", flush=True)
    while True:
        conn, _addr = server.accept()
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)


if __name__ == "__main__":
    main()
