message = "The key is hidden under the door pad"
pt = str()
key_sq = [['' for _ in range(5)] for _ in range(5)]
key = "GUIDANCE"
count = 0
pad = 'A'
prev = ''

#I and J share a block
if 'I' in key:
    key_sq[4][4] = 'J'
    for i in range(len(message)):
        if message[i].isalpha():
            if message[i] == prev:
                pt+='X'
                i-=1
            if message[i] == 'j' or message[i] == 'J':
                pt += 'I'
            else:
                pt+=message[i].upper()
elif 'J' in key:
    key_sq[4][4] = 'I'
    for i in range(len(message)):
        if message[i].isalpha():
            if message[i] == prev:
                pt+='X'
                i-=1
            if message[i] == 'i' or message[i] == 'I':
                pt += 'J'
            else:
                pt += message[i].upper()
print(pt)

#create key square
for i in range(5):
    for j in range(5):
        if count < len(key):
            key_sq[i][j]=key[count]
            count += 1
        else:
            while any(pad in row for row in key_sq):
                pad = chr(ord(pad) + 1)
            key_sq[i][j] = pad

#key square
for i in range(5):
    for j in range(5):
        print(key_sq[i][j], end=" ")
    print("")