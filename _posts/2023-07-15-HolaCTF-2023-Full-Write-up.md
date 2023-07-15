# HolaCTF Full HD Write-up

## :rocket: Reverse Engineering

## 1. B1thon

> Author: [Cao Tất Thành]()

Excutable file is built from Python, so we need [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) to convert excutable into [pyc] file (https://www.tutorialspoint.com/What-are-pyc-files-in-Python) and [uncompyle6](https://pypi.org/project/uncompyle6/) to decompile pyc into python source code like following:

```python=
def banner():
    print('')
    print('██████╗  ██╗████████╗██╗  ██╗ ██████╗ ███╗   ██╗')
    print('██╔══██╗███║╚══██╔══╝██║  ██║██╔═████╗████╗  ██║')
    print('██████╔╝╚██║   ██║   ███████║██║██╔██║██╔██╗ ██║')
    print('██╔══██╗ ██║   ██║   ██╔══██║████╔╝██║██║╚██╗██║')
    print('██████╔╝ ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║')
    print('╚═════╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝')
    print('███████████████████████████████████████████████╗')
    print('╚══════════════════════════════════════════════╝')
    print('')


def encrypt_1(inp):
    return ((inp >> 7 & 1 | (inp >> 6 & 1) << 1) << 6 | (inp >> 5 & 1 | (inp >> 4 & 1) << 1) << 4 | (inp >> 3 & 1 | (inp >> 2 & 1) << 1) << 2 | (inp >> 1 & 1 | (inp & 1) << 1)) >> 4 | ((inp >> 7 & 1 | (inp >> 6 & 1) << 1) << 6 | (inp >> 5 & 1 | (inp >> 4 & 1) << 1) << 4 | (inp >> 3 & 1 | (inp >> 2 & 1) << 1) << 2 | (inp >> 1 & 1 | (inp & 1) << 1)) << 4 & 255


def encrypt_2(inp):
    return encrypt_1(encrypt_1(encrypt_1(inp) >> 7 | encrypt_1(inp) << 1 & 255) >> 7 | encrypt_1(encrypt_1(inp) >> 7 | encrypt_1(inp) << 1 & 255) << 1 & 255)


def check(inp):
    if len(inp) != 26:
        return False
    data = [178, 212, 186, 246, 50, 238, 233, 164, 58, 238, 233, 190, 50, 205, 216, 30, 202, 212, 233, 158, 210, 20, 202, 172, 56, 52]
    dark = []
    for i in range(0, len(inp), 2):
        dark.append(((encrypt_2(ord(inp[i])) << 8 | encrypt_2(ord(inp[i + 1]))) ^ 4919) >> 8)
        dark.append(((encrypt_2(ord(inp[i])) << 8 | encrypt_2(ord(inp[i + 1]))) ^ 4919) & 255)

    for i in range(len(inp)):
        if dark[i] != data[i]:
            return False

    return True


def main():
    banner()
    inp = str(input('Enter the flag: '))
    if check(inp):
        print('\n!!! Congratulation !!!\n')
    else:
        print('\n!!! Try harder !!!\n')


if __name__ == '__main__':
    main()
```

The flow of encrypt_2 is encrypt_1 -> rotate left 1 bit -> encrypt_1 -> rotate left 1 bit -> encrypt_1. Don't try to understand what encrypt_1 does, because if this function runs even times, the data will return to the original. Next, look at the check function, it encrypts each 2 characters and appends it to the dark list. So I wrote a short script to solve this challenge

```
def decrypt(inp):
        return ((inp >> 7 & 1 | (inp >> 6 & 1) << 1) << 6 | (inp >> 5 & 1 | (inp >> 4 & 1) << 1) << 4 | (inp >> 3 & 1 | (inp >> 2 & 1) << 1) << 2 | (inp >> 1 & 1 | (inp & 1) << 1)) >> 4 | ((inp >> 7 & 1 | (inp >> 6 & 1) << 1) << 6 | (inp >> 5 & 1 | (inp >> 4 & 1) << 1) << 4 | (inp >> 3 & 1 | (inp >> 2 & 1) << 1) << 2 | (inp >> 1 & 1 | (inp & 1) << 1)) << 4 & 255

def main():
        data = [178, 212, 186, 246, 50, 238, 233, 164, 58, 238, 233, 190, 50, 205, 216, 30, 202, 212, 233, 158, 210, 20, 202, 172, 56, 52]

        # XOR
        dark = []
        for i in range(0,26,2):
                temp = (data[i] << 8 | data[i+1]) ^ 4919
                dark.append(temp >> 8)
                dark.append(temp & 255)

        # Decrypt dark magic
        for i in range(26):
                dark[i] = decrypt(dark[i])
                dark[i] = (dark[i] >> 1) | ((dark[i] << 7) & 0b10000000)
                dark[i] = decrypt(dark[i])
                dark[i] = (dark[i] >> 1) | ((dark[i] << 7) & 0b10000000)
                dark[i] = decrypt(dark[i])

        for i in dark:
                print(chr(i), end = "")
        print()


if __name__ == '__main__':
        main()
```

The output is **pyth0n_c4n_d0_m4ny_th1ng5!** -> the flag: **EHC{pyth0n_c4n_d0_m4ny_th1ng5!}**

## 2. Letgo:

Look at the **main_main** function, see that **main_check** function was called here.

```
...
.text:000000000048F112                 mov     rax, [rcx]
.text:000000000048F115                 mov     rbx, [rcx+8]
.text:000000000048F119                 call    main_check
.text:000000000048F11E                 xchg    ax, ax
.text:000000000048F120                 test    al, al
...
```

Look through the **main_check** function, we can see some things interesting here

```
...
    v14 = v10 + 1;
    v15 = *(unsigned __int8 *)(v7 + v9);
    v16 = (unsigned __int8)(16 * v15);
    v17 = v15 >> 4;
    v18 = *((_QWORD *)&v33 + v9) ^ (v17 | v16);
...
```

It just rotates 4 bits and then XOR with key. We know the length of the input is 27 and we have 2 arrays having 27 elements each array.

```
...
  *(_QWORD *)&v33 = 102LL;
  *((_QWORD *)&v33 + 1) = 246LL;
  v34 = 87LL;
  v35 = 230LL;
  v36 = 70LL;
  v37 = 86LL;
  v38 = 39LL;
  v39 = 245LL;
  v40 = 246LL;
  v41 = 102LL;
  v42 = 245LL;
  v43 = 118LL;
  v44 = 246LL;
  v45 = 198LL;
  v46 = 22LL;
  v47 = 230LL;
  v48 = 118LL;
  v49 = 245LL;
  v50 = 150LL;
  v51 = 55LL;
  v52 = 245LL;
  v53 = 118LL;
  v54 = 246LL;
  v55 = 246LL;
  v56 = 118LL;
  v57 = 198LL;
  v58 = 86LL;
...
  *(_QWORD *)&v28 = 117LL;
  *((_QWORD *)&v28 + 1) = 193LL;
  v29 = 162LL;
  v30 = 144LL;
  v31 = 69LL;
  v32[0] = 163LL;
  v32[1] = 225LL;
  v32[2] = 182LL;
  v32[3] = 16LL;
  v32[4] = 16LL;
  v32[5] = 0LL;
  v32[6] = 69LL;
  v32[7] = 181LL;
  v32[8] = 241LL;
  v32[9] = 129LL;
  v32[10] = 19LL;
  v32[11] = 49LL;
  v32[12] = 246LL;
  v32[13] = 99LL;
  v32[14] = 16LL;
  v32[15] = 198LL;
  v32[16] = 17LL;
  v32[17] = 197LL;
  v32[18] = 209LL;
  v32[19] = 69LL;
  v32[20] = 53LL;
  v32[21] = 165LL;
...
```

So, I wrote a short script to solve this challenge:

```
data1 = [102, 246, 87, 230, 70, 86, 39, 245, 246, 102, 245, 118, 246, 198, 22, 230, 118, 245, 150, 55, 245, 118, 246, 246, 118, 198, 86]
data2 = [117, 193, 162, 144, 69, 163, 225, 182, 16, 16, 0, 69, 181, 241, 129, 19, 49, 246, 99, 16, 198, 17, 197, 209, 69, 53, 165]
for i in range(27):
        temp = (data1[i] ^ data2[i])
        temp = (temp >> 4) | ((temp << 4) & 0xff)
        print(chr(temp), end = "")

print()
```

The flag: **EHC{1s_g0_l4ng_34sy_t0_r3v3r3??}**

## 3. Zi Zay 3:

First of all, look at the main function, we know that we need to enter the flag, this flag will send to a check function and get the output if it is correct. Then just look through the check function, there are too many conditions. And all of those are not possible to solve handly.

So we just need a tool to do this for us. [z3](https://pypi.org/project/z3/) is fine to do that.

I wrote a short script to solve by z3.

```
import z3

flag = [z3.Int(f'flag_{i}') for i in range(18)]

solver = z3.Solver()

solver.add(flag[0x03] - flag[0x11] + flag[0x08] - flag[0x0c] - flag[0x09] + flag[0x0f] - flag[0x06] - flag[0x00] - flag[0x02] + flag[0x05] == -396) 
solver.add(flag[0x02] - flag[0x07] - flag[0x00] - flag[0x0f] - flag[0x0a] - flag[0x0e] - flag[0x03] + flag[0x06] + flag[0x04] + flag[0x0d] == -67) 
solver.add(flag[0x02] - flag[0x0b] + flag[0x10] - flag[0x03] + flag[0x11] - flag[0x05] - flag[0x04] + flag[0x00] - flag[0x0a] + flag[0x01] == 82) 
solver.add(flag[0x0e] + flag[0x0d] + flag[0x04] - flag[0x09] + flag[0x05] - flag[0x0c] - flag[0x11] - flag[0x0f] - flag[0x10] - flag[0x08] == -122) 
solver.add(flag[0x0b] + flag[0x0d] - flag[0x04] + flag[0x11] + flag[0x06] - flag[0x05] + flag[0x0c] + flag[0x03] - flag[0x09] + flag[0x0e] == 318) 
solver.add(flag[0x11] + flag[0x03] + flag[0x00] + flag[0x0f] + flag[0x06] + flag[0x0c] + flag[0x05] + flag[0x04] - flag[0x0a] - flag[0x0e] == 552) 
solver.add(flag[0x06] + flag[0x11] + flag[0x04] + flag[0x0d] + flag[0x09] - flag[0x0b] + flag[0x0c] - flag[0x08] + flag[0x0a] - flag[0x01] == 577) 
solver.add(flag[0x03] - flag[0x0f] + flag[0x00] - flag[0x0d] - flag[0x05] - flag[0x0b] - flag[0x01] + flag[0x0a] + flag[0x06] + flag[0x02] == 119) 
solver.add(flag[0x05] - flag[0x08] + flag[0x06] - flag[0x01] - flag[0x07] + flag[0x09] + flag[0x00] + flag[0x02] - flag[0x0c] - flag[0x0d] == 157) 
solver.add(flag[0x00] - flag[0x11] - flag[0x0b] + flag[0x05] + flag[0x0f] - flag[0x03] + flag[0x02] + flag[0x06] + flag[0x0d] - flag[0x08] == 309) 
solver.add(flag[0x00] - flag[0x08] - flag[0x0a] - flag[0x0f] - flag[0x10] + flag[0x02] - flag[0x0c] - flag[0x07] + flag[0x01] - flag[0x05] == -302) 
solver.add(flag[0x0f] + flag[0x0c] + flag[0x05] - flag[0x07] - flag[0x04] - flag[0x00] - flag[0x0b] + flag[0x11] - flag[0x03] + flag[0x09] == 81) 
solver.add(flag[0x0c] - flag[0x09] - flag[0x02] - flag[0x0a] - flag[0x0f] - flag[0x01] + flag[0x0e] + flag[0x0b] - flag[0x11] + flag[0x07] == -172) 
solver.add(flag[0x0b] - flag[0x0a] - flag[0x05] + flag[0x0d] - flag[0x04] - flag[0x08] + flag[0x00] + flag[0x11] + flag[0x09] + flag[0x0c] == 236) 
solver.add(flag[0x02] - flag[0x00] - flag[0x10] + flag[0x11] - flag[0x05] - flag[0x0a] - flag[0x0e] - flag[0x01] + flag[0x03] + flag[0x0c] == -224) 
solver.add(flag[0x0a] - flag[0x06] - flag[0x02] + flag[0x05] + flag[0x0d] - flag[0x08] + flag[0x04] - flag[0x07] + flag[0x0c] - flag[0x09] == 122) 
solver.add(flag[0x04] + flag[0x10] - flag[0x01] + flag[0x0f] - flag[0x02] - flag[0x05] - flag[0x0c] + flag[0x0d] + flag[0x0b] + flag[0x03] == 122) 
solver.add(flag[0x09] - flag[0x08] + flag[0x0a] + flag[0x0c] - flag[0x01] - flag[0x06] - flag[0x03] + flag[0x0f] + flag[0x0e] + flag[0x04] == 336) 
solver.add(flag[0x0a] + flag[0x09] + flag[0x0c] - flag[0x0f] - flag[0x02] - flag[0x08] + flag[0x0e] - flag[0x04] - flag[0x0d] - flag[0x0b] == -37) 
solver.add(flag[0x07] - flag[0x09] + flag[0x00] + flag[0x08] + flag[0x11] - flag[0x01] + flag[0x0e] + flag[0x0a] + flag[0x02] - flag[0x04] == 355) 
solver.add(flag[0x00] + flag[0x10] - flag[0x03] + flag[0x0e] + flag[0x08] + flag[0x0f] - flag[0x0b] + flag[0x01] + flag[0x11] + flag[0x0d] == 596) 
solver.add(flag[0x0d] - flag[0x00] - flag[0x02] + flag[0x09] + flag[0x0c] + flag[0x0b] - flag[0x07] - flag[0x0e] + flag[0x03] - flag[0x10] == -78)

print(solver.check())

m = solver.model()
out = [chr(m.evaluate(flag[i]).as_long()) for i in range(18)]
print("".join(out))
```

When ran this script, the output is **z3_1s_g00d_4t_m4th**. So, the flag is **EHC{z3_1s_g00d_4t_m4th}** (you should check the result with this execute file before submitting the flag).






