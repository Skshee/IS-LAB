#!/usr/bin/env python3

"""
This script compiles and refactors the functionalities from Q1.py, Q2.py,
AQ1.py, and Q3.py into a single, class-based application.

It demonstrates:
1. A custom hash function.
2. A simple network integrity check (signature and verification).
3. A chunked-data network integrity check (signature and verification).
4. A performance analysis of MD5, SHA-1, and SHA-256.
"""

import socket
import threading
import hashlib
import time
import random
import string
import matplotlib.pyplot as plt
from collections import defaultdict

# ----------------------------------------------------------------------------
# Class from Q1.py: Custom Hashing
# ----------------------------------------------------------------------------
class CustomHasher:
    """
    Implements a custom hash function based on the djb2 algorithm variant
    (from Q1.py).
    """
    def __init__(self, initial_value=5381):
        """Initializes the hasher with a starting seed."""
        self.initial_value = initial_value

    def compute_hash(self, input_string: str) -> int:
        """
        Computes the custom hash for a given string.

        The process starts with an initial value (5381), and for each
        character, it multiplies the current hash by 33, adds the
        character's ASCII value, and applies bitwise mixing.
        """
        hash_value = self.initial_value

        for char in input_string:
            # Multiply by 33 (hash * 33) using bitshift: (hash << 5) + hash
            hash_value = ((hash_value << 5) + hash_value) + ord(char)
            
            # Bitwise mixing: XOR with shifted hash
            hash_value ^= (hash_value >> 13)

        # Ensure the final hash is within a 32-bit unsigned range
        hash_value &= 0xFFFFFFFF
        return hash_value

    def demo(self):
        """Runs a simple demonstration of the custom hasher."""
        print("=" * 50)
        print("Demo 1: Custom Hasher (from Q1.py)")
        print("-" * 50)
        test_string = "Hello World!"
        hash_val = self.compute_hash(test_string)
        print(f"Input string: '{test_string}'")
        print(f"Custom Hash (32-bit): {hash_val}")
        print("=" * 50 + "\n")


# ----------------------------------------------------------------------------
# Class from Q2.py: Simple Network Integrity Demo
# ----------------------------------------------------------------------------
class SimpleNetworkIntegrityDemo:
    """
    Demonstrates a basic data integrity check over a socket connection
    (from Q2.py).
    
    The client sends a single message. The server hashes it and sends
    the hash back. The client verifies this hash against its own.
    """
    def __init__(self, host='127.0.0.1', port=65433):
        self.HOST = host
        self.PORT = port

    def _compute_sha256(self, data: bytes) -> str:
        """Internal helper to compute SHA-256 hash."""
        return hashlib.sha256(data).hexdigest()

    def _server_thread(self):
        """Runs the server logic in a thread."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.HOST, self.PORT))
                s.listen()
                print(f"[Server-Q2] Listening on {self.HOST}:{self.PORT}")
                conn, addr = s.accept()
                with conn:
                    print(f"[Server-Q2] Connected by {addr}")
                    # Receives the single data packet
                    data = conn.recv(1024)
                    if data:
                        print(f"[Server-Q2] Received data: {data.decode()}")
                        # 1. Server computes hash of received data
                        hash_value = self._compute_sha256(data)
                        print(f"[Server-Q2] Computed hash: {hash_value}")
                        # 2. Server sends the hash back to the client
                        conn.sendall(hash_value.encode())
        except Exception as e:
            print(f"[Server-Q2] Error: {e}")

    def _client_thread(self, simulate_corruption=False):
        """Runs the client logic."""
        try:
            time.sleep(1)  # Wait for server
            original_data = "This is a message to verify integrity."
            data_to_send = original_data.encode()

            if simulate_corruption:
                # Simulate data being tampered with during transmission
                data_to_send = b"This is a tampered message."

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.HOST, self.PORT))
                
                # 1. Client computes its own "signature" hash
                local_hash = self._compute_sha256(original_data.encode())
                print(f"[Client-Q2] Original data: {original_data}")
                print(f"[Client-Q2] Local hash (Signature): {local_hash}")
                
                if simulate_corruption:
                    print(f"[Client-Q2] Sending TAMPERED data: {data_to_send.decode()}")
                
                # 2. Client sends the (potentially tampered) data
                s.sendall(data_to_send)
                
                # 3. Client receives the server's hash
                received_hash = s.recv(1024).decode()
                print(f"[Client-Q2] Received hash from server: {received_hash}")

                # 4. Verification step
                if local_hash == received_hash:
                    print("[Client-Q2]  VERIFIED: Data integrity confirmed.")
                else:
                    print("[Client-Q2]  FAILED: Data corruption or tampering detected!")
        except Exception as e:
            print(f"[Client-Q2] Error: {e}")

    def run_demo(self, simulate_corruption=False):
        """Starts the server and client threads for the demo."""
        print("=" * 50)
        demo_type = "Corruption Simulation" if simulate_corruption else "Normal Operation"
        print(f"Demo 2: Simple Network Integrity (from Q2.py) - {demo_type}")
        print("-" * 50)
        
        threading.Thread(target=self._server_thread, daemon=True).start()
        self._client_thread(simulate_corruption)
        
        print("=" * 50 + "\n")
        time.sleep(0.5) # Allow threads to settle


# ----------------------------------------------------------------------------
# Class from AQ1.py: Chunked-Data Network Integrity Demo
# ----------------------------------------------------------------------------
class ChunkedNetworkIntegrityDemo:
    """
    Demonstrates data integrity for (more realistic) chunked data
    over a socket connection (based on AQ1.py).
    
    The client sends a long message in small parts. The server reassembles
    it, hashes the full message, and sends the hash back for verification.
    """
    def __init__(self, host='127.0.0.1', port=65432):
        self.HOST = host
        self.PORT = port

    def _compute_sha256(self, message: str) -> str:
        """Internal helper to compute SHA-256 hash."""
        return hashlib.sha256(message.encode()).hexdigest()

    def _server_program(self):
        """Runs the server logic in a thread."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.HOST, self.PORT))
                s.listen()
                print(f"[SERVER-AQ1] Listening on {self.HOST}:{self.PORT}...")
                conn, addr = s.accept()
                with conn:
                    print(f"[SERVER-AQ1] Connected by {addr}")
                    full_message = ""
                    # 1. Server receives data in chunks until "END" signal
                    while True:
                        chunk = conn.recv(1024).decode()
                        if chunk == "END":
                            break
                        full_message += chunk

                    print(f"[SERVER-AQ1] Full message received: {full_message}")
                    # 2. Server computes hash of the *reassembled* message
                    message_hash = self._compute_sha256(full_message)
                    print(f"[SERVER-AQ1] Computed hash: {message_hash}")
                    # 3. Server sends the single hash back
                    conn.sendall(message_hash.encode())
        except Exception as e:
            print(f"[SERVER-AQ1] Error: {e}")

    def _client_program(self, message, simulate_tampering=False):
        """Runs the client logic."""
        try:
            time.sleep(1) # Give server time to start
            original_message = message
            
            if simulate_tampering:
                # We will send a different message than the one we hash locally
                message_to_send = "This is a tampered message!"
            else:
                message_to_send = original_message
            
            # 1. Client computes its local "signature" hash of the *original* data
            local_hash = self._compute_sha256(original_message)
            print(f"[CLIENT-AQ1] Original message intended: {original_message}")
            print(f"[CLIENT-AQ1] Local hash (Signature): {local_hash}")

            chunks = [message_to_send[i:i+10] for i in range(0, len(message_to_send), 10)]
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.HOST, self.PORT))
                
                if simulate_tampering:
                    print(f"[CLIENT-AQ1] Sending TAMPERED data in chunks: {message_to_send}")
                
                # 2. Client sends the (potentially tampered) data in chunks
                for chunk in chunks:
                    s.sendall(chunk.encode())
                    time.sleep(0.05) # Simulate network delay
                
                s.sendall("END".encode()) # Signal end of message

                # 3. Client receives the server's hash
                server_hash = s.recv(1024).decode()
                print(f"[CLIENT-AQ1] Server hash (of received): {server_hash}")

                # 4. Verification step
                if local_hash == server_hash:
                    print("[CLIENT-AQ1]  VERIFIED: Data integrity confirmed.")
                else:
                    print("[CLIENT-AQ1]  FAILED: Data corruption/tampering detected!")
        except Exception as e:
            print(f"[CLIENT-AQ1] Error: {e}")

    def run_demo(self, message, simulate_tampering=False):
        """Starts the server and client threads for the demo."""
        print("=" * 50)
        demo_type = "Tampering Simulation" if simulate_tampering else "Normal Operation"
        print(f"Demo 3: Chunked Network Integrity (from AQ1.py) - {demo_type}")
        print("-" * 50)
        
        server_thread = threading.Thread(target=self._server_program, daemon=True)
        server_thread.start()
        
        self._client_program(message, simulate_tampering)
        
        print("=" * 50 + "\n")
        time.sleep(0.5) # Allow threads to settle


# ----------------------------------------------------------------------------
# Class from Q3.py: Hash Performance Analyzer
# ----------------------------------------------------------------------------
class HashPerformanceAnalyzer:
    """
    Analyzes and compares the performance (computation time) and
    collision resistance of MD5, SHA-1, and SHA-256 (from Q3.py).
    """
    def __init__(self, num_strings_range=(50, 100), str_length_range=(10, 50000)):
        self.num_strings = random.randint(*num_strings_range)
        self.length_range = str_length_range
        self.dataset = []
        self.results = {}

    def _generate_random_strings(self):
        """Generates the dataset of random strings."""
        print(f"Generating {self.num_strings} random strings (length {self.length_range})...")
        for _ in range(self.num_strings):
            length = random.randint(*self.length_range)
            rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            self.dataset.append(rand_str)
        print("Dataset generated.")

    def _compute_hashes(self, algorithm):
        """Computes hashes for the dataset using a given algorithm."""
        hashes = []
        start_time = time.time()
        for item in self.dataset:
            h = hashlib.new(algorithm)
            h.update(item.encode('utf-8'))
            hashes.append(h.hexdigest())
        end_time = time.time()
        return hashes, end_time - start_time

    def _detect_collisions(self, hashes):
        """Detects collisions in a list of hashes."""
        seen = set()
        collisions = []
        for h in hashes:
            if h in seen:
                collisions.append(h)
            else:
                seen.add(h)
        return collisions

    def _plot_results(self):
        """Plots the computation time and collision results."""
        try:
            algorithms = self.results.keys()
            times = [self.results[a]['time'] for a in algorithms]
            collisions = [self.results[a]['collisions'] for a in algorithms]

            plt.figure(figsize=(12, 6))

            # Plot 1: Computation Time
            plt.subplot(1, 2, 1)
            plt.bar(algorithms, times, color='skyblue')
            plt.title('Hash Computation Time')
            plt.ylabel('Time (seconds)')
            plt.xlabel('Hash Algorithm')

            # Plot 2: Collision Count
            plt.subplot(1, 2, 2)
            plt.bar(algorithms, collisions, color='salmon')
            plt.title('Collision Count')
            plt.ylabel('Number of Collisions')
            plt.xlabel('Hash Algorithm')
            
            plt.tight_layout()
            print("\nPlotting results. Please check the popup window(s).")
            plt.show()
            
        except ImportError:
            print("\nMatplotlib not found. Skipping plots.")
        except Exception as e:
            print(f"\nCould not plot results. Error: {e}")
            print("This might be because you are in a non-GUI environment.")

    def run_experiment(self):
        """Runs the full performance analysis experiment."""
        print("=" * 50)
        print("Demo 4: Hash Performance Analyzer (from Q3.py)")
        print("-" * 50)
        
        self._generate_random_strings()
        algorithms_to_test = ['md5', 'sha1', 'sha256']

        for algo in algorithms_to_test:
            print(f"\nTesting {algo.upper()}...")
            hashes, duration = self._compute_hashes(algo)
            collisions = self._detect_collisions(hashes)
            
            self.results[algo] = {
                'time': duration,
                'collisions': len(collisions),
            }
            print(f"Time taken: {duration:.6f} seconds")
            # Note: Collisions are extremely unlikely with this small dataset.
            print(f"Collisions detected: {len(collisions)}")
            
        self._plot_results()
        print("=" * 50 + "\n")


# ----------------------------------------------------------------------------
# Main execution
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    
    # --- Demo 1: Custom Hasher (from Q1.py) ---
    hasher = CustomHasher()
    hasher.demo()
    
    # --- Demo 2: Simple Network Integrity (from Q2.py) ---
    # Scenario A: Normal operation, no corruption
    simple_demo_ok = SimpleNetworkIntegrityDemo(port=65433)
    simple_demo_ok.run_demo(simulate_corruption=False)
    
    # Scenario B: Simulated corruption
    simple_demo_corrupt = SimpleNetworkIntegrityDemo(port=65434) # Use a new port
    simple_demo_corrupt.run_demo(simulate_corruption=True)

    # --- Demo 3: Chunked Network Integrity (from AQ1.py) ---
    long_message = "This is a much longer message that must be sent in multiple parts to test the chunking and reassembly logic."
    
    # Scenario A: Normal operation, no tampering
    chunked_demo_ok = ChunkedNetworkIntegrityDemo(port=65432)
    chunked_demo_ok.run_demo(long_message, simulate_tampering=False)
    
    # Scenario B: Simulated tampering
    chunked_demo_tamper = ChunkedNetworkIntegrityDemo(port=65435) # Use a new port
    chunked_demo_tamper.run_demo(long_message, simulate_tampering=True)

    # --- Demo 4: Hash Performance Analyzer (from Q3.py) ---
    analyzer = HashPerformanceAnalyzer()
    analyzer.run_experiment()
