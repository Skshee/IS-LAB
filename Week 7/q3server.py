# server.py
import socket, random, hashlib, hmac
p, g = 2087, 2

priv = random.randint(2, p-2)
pub = pow(g, priv, p)

s = socket.socket(); s.bind(('localhost', 9000)); s.listen(1)
print("Server waiting...")
conn, _ = s.accept()
client_pub = int(conn.recv(1024).decode())
conn.send(str(pub).encode())
K = pow(client_pub, priv, p)
key = hashlib.sha256(str(K).encode()).digest()

data = conn.recv(1024).decode().split("|")
msg, tag = data[0].encode(), data[1]
valid = hmac.new(key, msg, hashlib.sha256).hexdigest() == tag
print("Server received:", msg)
print("Verified:", valid)
conn.send(b"VERIFIED" if valid else b"FAILED")
conn.close()
