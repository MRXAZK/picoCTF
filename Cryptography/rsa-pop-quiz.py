import binascii
from pwn import *

MMI = lambda A, n, s=1, t=0, N=0: (n < 2 and t % N or MMI(n, A % n, t, s - A // n * t, N or n), -1)[n < 1]

r = remote('jupiter.challenges.picoctf.org', 58617)
 
# Q1
lines = r.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):')
print(lines)
q = int([l for l in lines.split(b'\n') if b'q :' in l][0].split(b':')[1].strip(), 10)
p = int([l for l in lines.split(b'\n') if b'p :' in l][0].split(b':')[1].strip(), 10)
r.sendline(b'Y')
print(r.recvuntil(b'n:'))
ans = q * p
print('Sending: {}'.format(ans))
r.sendline('{}'.format(ans).encode())

# Q2
lines = r.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):')
print(lines)
p = int([l for l in lines.split(b'\n') if b'p :' in l][0].split(b':')[1].strip(), 10)
n = int([l for l in lines.split(b'\n') if b'n :' in l][0].split(b':')[1].strip(), 10)
r.sendline(b'Y')
print(r.recvuntil(b'q:'))
ans = n // p
print('Sending: {}'.format(ans))
r.sendline('{}'.format(ans).encode())

# Q3
lines = r.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):')
print(lines)
r.sendline(b'N')

# Q4
lines = r.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):')
print(lines)
q = int([l for l in lines.split(b'\n') if b'q :' in l][0].split(b':')[1].strip(), 10)
p = int([l for l in lines.split(b'\n') if b'p :' in l][0].split(b':')[1].strip(), 10)
r.sendline(b'Y')
print(r.recvuntil(b'totient(n):'))
ans = (q - 1) * (p - 1)
print('Sending: {}'.format(ans))
r.sendline('{}'.format(ans).encode())

# Q5
lines = r.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):')
print(lines)
plain = int([l for l in lines.split(b'\n') if b'plaintext :' in l][0].split(b':')[1].strip(), 10)
e = int([l for l in lines.split(b'\n') if b'e :' in l][0].split(b':')[1].strip(), 10)
n = int([l for l in lines.split(b'\n') if b'n :' in l][0].split(b':')[1].strip(), 10)
r.sendline(b'Y')
print(r.recvuntil(b'ciphertext:'))
ans = pow(plain, e, n)
print('Sending: {}'.format(ans))
r.sendline('{}'.format(ans).encode())

# Q6
lines = r.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):')
print(lines)
r.sendline(b'N')

# Q7
lines = r.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):')
print(lines)
q = int([l for l in lines.split(b'\n') if b'q :' in l][0].split(b':')[1].strip(), 10)
p = int([l for l in lines.split(b'\n') if b'p :' in l][0].split(b':')[1].strip(), 10)
e = int([l for l in lines.split(b'\n') if b'e :' in l][0].split(b':')[1].strip(), 10)
r.sendline(b'Y')
print(r.recvuntil(b'd:'))
ans = MMI(e, (q - 1) * (p - 1))
print('Sending: {}'.format(ans))
r.sendline('{}'.format(ans).encode())

# Q8
lines = r.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):')
print(lines)
p = int([l for l in lines.split(b'\n') if b'p :' in l][0].split(b':')[1].strip(), 10)
cipher = int([l for l in lines.split(b'\n') if b'ciphertext :' in l][0].split(b':')[1].strip(), 10)
e = int([l for l in lines.split(b'\n') if b'e :' in l][0].split(b':')[1].strip(), 10)
n = int([l for l in lines.split(b'\n') if b'n :' in l][0].split(b':')[1].strip(), 10)
r.sendline(b'Y')
print(r.recvuntil(b'plaintext:'))
q = n // p
d = MMI(e, (q - 1) * (p - 1))
ans = pow(cipher, d, n)
print('Sending: {}'.format(ans))
r.sendline('{}'.format(ans).encode())
lines = r.recvall()
print(lines)
print('In hex: {}'.format(hex(ans)))
print(binascii.unhexlify(hex(ans)[2:]))
