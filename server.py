import socket
import ssl
import base64
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = "127.0.0.1"
PORT = 12345

# AES decrypt helper
def aes_decrypt(ciphertext, key, iv):
    decryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

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
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile="certs/public/securechat_server.cert.pem",
        keyfile="certs/private/securechat_server.key.pem"
    )
    context.load_verify_locations("certs/ca/ca.cert.pem")
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"✅ Server listening on {HOST}:{PORT}")

        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            print(f"🔐 Secure connection from {addr}")

            while True:
                encrypted_msg = recv_msg(conn)
                if not encrypted_msg:
                    break

                # Base64 decode
                decoded_msg = base64.b64decode(encrypted_msg)

                # Here you can decrypt with AES session key if implemented
                # For now just echo back
                send_msg(conn, base64.b64encode(decoded_msg))
                print("Client:", decoded_msg.decode())

if __name__ == "__main__":
    main()

