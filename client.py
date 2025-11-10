import socket
import ssl
import base64
import struct

HOST = "127.0.0.1"
PORT = 12345
CA_FILE = "certs/ca/ca.cert.pem"

# Receive exact n bytes
def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# Receive framed message
def recv_msg(sock):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]
    return recvall(sock, msg_len)

# Send framed message
def send_msg(sock, msg_bytes):
    sock.sendall(struct.pack('>I', len(msg_bytes)) + msg_bytes)

def main():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
    context.load_cert_chain(
        certfile="certs/public/securechat_client.cert.pem",
        keyfile="certs/private/securechat_client.key.pem"
    )

    with socket.create_connection((HOST, PORT)) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
            print("[+] TLS handshake complete.")
            print("[+] Server certificate subject:", dict(tls_sock.getpeercert()))

            while True:
                msg = input("Enter message (or 'exit' to quit): ")
                if msg.lower() == "exit":
                    break

                # Encode and send
                encrypted_msg = base64.b64encode(msg.encode())
                send_msg(tls_sock, encrypted_msg)
                print(f"[>] Sent encrypted (Base64): {encrypted_msg.decode()}")

                # Receive echo
                reply = recv_msg(tls_sock)
                if not reply:
                    print("[-] Server disconnected.")
                    break
                decrypted_reply = base64.b64decode(reply)
                print(f"[<] Received decrypted: {decrypted_reply.decode()}")

            print("[+] Closing connection.")

if __name__ == "__main__":
    main()

