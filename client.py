#!/usr/bin/env python3
"""
client.py — minimal mutual-TLS echo client for SecureChat.

Behavior:
- Loads client cert/key and the CA cert used to verify server.
- Connects to 127.0.0.1:12345, performs TLS handshake.
- Sends a message, receives the echo, then closes connection.
"""

import socket
import ssl
import sys
import traceback

HOST = "127.0.0.1"
PORT = 12345

CLIENT_CERT = "certs/public/securechat_client.cert.pem"
CLIENT_KEY = "certs/private/securechat_client.key.pem"
CA_FILE = "certs/ca/ca.cert.pem"
READ_BUFF = 4096
MSG = "hello from client"

def main():
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
        context.load_verify_locations(cafile=CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED

        print(f"[+] Connecting to {HOST}:{PORT} ...")
        with socket.create_connection((HOST, PORT)) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=HOST) as tls_sock:
                print("[+] TLS handshake complete.")
                print("[+] Server certificate subject:", tls_sock.getpeercert())
                
                print(f"[>] Sending: '{MSG}'")
                tls_sock.sendall(MSG.encode())
                
                data = tls_sock.recv(READ_BUFF)
                print(f"[<] Received: '{data.decode()}'")
                
                print("[+] Closing connection.")
    except ssl.SSLError as e:
        print("SSL/TLS error:", e)
    except FileNotFoundError as e:
        print("Certificate file not found:", e)
        sys.exit(1)
    except Exception as e:
        print("Client error:", e)
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()

