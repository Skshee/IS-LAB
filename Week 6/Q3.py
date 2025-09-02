import hashlib
import random
import string
import time
from collections import defaultdict
import matplotlib.pyplot as plt

# Generate random strings
def generate_random_strings(n, length_range=(10, 50000)):
    dataset = []
    for _ in range(n):
        length = random.randint(*length_range)
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(rand_str)
    return dataset

# Hashing functions
def compute_hashes(dataset, algorithm):
    hashes = []
    start_time = time.time()
    for item in dataset:
        h = hashlib.new(algorithm)
        h.update(item.encode('utf-8'))
        hashes.append(h.hexdigest())
    end_time = time.time()
    return hashes, end_time - start_time

# Collision detection
def detect_collisions(hashes):
    seen = set()
    collisions = []
    for h in hashes:
        if h in seen:
            collisions.append(h)
        else:
            seen.add(h)
    return collisions

# Main experiment
def run_experiment():
    num_strings = random.randint(50, 100)
    dataset = generate_random_strings(num_strings)

    algorithms = ['md5', 'sha1', 'sha256']
    results = {}

    for algo in algorithms:
        print(f"\n Testing {algo.upper()}...")
        hashes, duration = compute_hashes(dataset, algo)
        collisions = detect_collisions(hashes)
        results[algo] = {
            'time': duration,
            'collisions': len(collisions),
            'hashes': hashes
        }
        print(f"Time taken: {duration:.6f} seconds")
        print(f"Collisions detected: {len(collisions)}")

    # Plotting results
    plt.figure(figsize=(10, 5))
    plt.bar(results.keys(), [results[a]['time'] for a in algorithms], color='skyblue')
    plt.title('Hash Computation Time')
    plt.ylabel('Time (seconds)')
    plt.xlabel('Hash Algorithm')
    plt.show()

    plt.figure(figsize=(10, 5))
    plt.bar(results.keys(), [results[a]['collisions'] for a in algorithms], color='salmon')
    plt.title('Collision Count')
    plt.ylabel('Number of Collisions')
    plt.xlabel('Hash Algorithm')
    plt.show()

# Run it
if __name__ == "__main__":
    run_experiment()