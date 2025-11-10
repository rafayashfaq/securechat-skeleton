#!/usr/bin/env python3
"""
server.py — minimal mutual-TLS echo server for the SecureChat assignment.

Behavior:
- Loads server cert/key and the CA cert used to verify client certs.
- Listens on 127.0.0.1:12345, accepts connections, performs TLS handshake,
  reads a single message and echoes it back, then closes the connection.
- Uses the correct pattern: accept() first, then wrap the accepted socket.
"""

import socket
import ssl
import sys
import traceback

HOST = "127.0.0.1"
PORT = 12345

SERVER_CERT = "certs/public/securechat_server.cert.pem"
SERVER_KEY = "certs/private/securechat_server.key.pem"
CA_FILE = "certs/ca/ca.cert.pem"
READ_BUFF = 4096

def main():
    try:
        # TLS context for server requiring client authentication (mutual TLS)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
        context.load_verify_locations(cafile=CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED

        # plain TCP listening socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as listen_sock:
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind((HOST, PORT))
            listen_sock.listen(5)
            print(f"[+] Server listening on {HOST}:{PORT} ...")

            # accept client connections in a loop
            while True:
                client_sock, addr = listen_sock.accept()
                print(f"[+] Incoming connection from {addr}, performing TLS handshake...")
                try:
                    # Wrap the *accepted* client socket (server_side=True)
                    with context.wrap_socket(client_sock, server_side=True) as tls_conn:
                        print("[+] TLS handshake completed. Peer:", tls_conn.getpeercert())
                        data = tls_conn.recv(READ_BUFF)
                        if not data:
                            print("[-] No data received, closing connection.")
                            continue
                        print("[<] Received:", data.decode(errors="replace"))
                        # Echo back
                        tls_conn.sendall(data)
                        print("[>] Echoed back to client.")
                except ssl.SSLError as e:
                    print("TLS error during handshake/connection:", e)
                except Exception as e:
                    print("Connection handling error:", e)
                    traceback.print_exc()
    except FileNotFoundError as e:
        print("File not found (cert/key missing):", e)
        sys.exit(1)
    except Exception as e:
        print("Server error:", e)
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()

