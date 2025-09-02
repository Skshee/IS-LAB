import socket
import threading
import hashlib
import time

HOST = '127.0.0.1'
PORT = 65432

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

# Server Thread
def server_thread():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening on {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print(f"[Server] Connected by {addr}")
            data = conn.recv(1024)
            if not data:
                print("[Server] No data received.")
                return
            print(f"[Server] Received data: {data.decode()}")
            hash_value = compute_hash(data)
            print(f"[Server] Computed hash: {hash_value}")
            conn.sendall(hash_value.encode())

# Client Thread
def client_thread(simulate_corruption=False):
    time.sleep(1)  # Wait for server to start
    original_data = "This is a message to verify integrity."
    data_to_send = original_data.encode()

    if simulate_corruption:
        data_to_send = b"This is a tampered message."

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(data_to_send)
        received_hash = s.recv(1024).decode()
        local_hash = compute_hash(data_to_send)

        print(f"[Client] Received hash from server: {received_hash}")
        print(f"[Client] Locally computed hash:     {local_hash}")

        if received_hash == local_hash:
            print("[Client] Data integrity verified. No tampering detected.")
        else:
            print("[Client] Data integrity check failed! Possible corruption or tampering.")

# Run both threads
if __name__ == "__main__":
    threading.Thread(target=server_thread).start()
    threading.Thread(target=client_thread, args=(False,)).start()  # Change to True to simulate tampering