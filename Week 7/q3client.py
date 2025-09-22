# client.py
import socket, random, hashlib, hmac
p, g = 2087, 2

priv = random.randint(2, p-2)
pub = pow(g, priv, p)

s = socket.socket(); s.connect(('localhost', 9000))
s.send(str(pub).encode())
server_pub = int(s.recv(1024).decode())
K = pow(server_pub, priv, p)
key = hashlib.sha256(str(K).encode()).digest()

msg = b"Hello Server"
tag = hmac.new(key, msg, hashlib.sha256).hexdigest()
s.send(msg + b"|" + tag.encode())
print("Server reply:", s.recv(1024).decode())
s.close()
