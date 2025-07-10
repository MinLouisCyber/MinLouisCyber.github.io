---
title: "[write-up] Root-Me: Forensics Part 2"
published: 2024-08-08
tags: [CTF, Forensics, RootMe]
category: Write-up
description: Phân tích các bài Forensics trong Root-Me, khai thác dữ liệu ẩn để truy vết và tìm flag.
draft: false
---

## Find me

![image](/assets/data/33.png)

Dùng ```volatility``` để phân tích bộ nhớ ram 
```
 volatility -f dump imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/minhtuan/Documents/Cyber_Security/CTFs/RootMe/ch188/dump)
                      PAE type : No PAE
                           DTB : 0x185000L
                          KDBG : 0x8294bbe8L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0x8294cc00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2016-09-15 10:12:31 UTC+0000
     Image local date and time : 2016-09-15 12:12:31 +0200

```

plugin ```pstree``` để xem các tiến trình theo quan hệ cha-con

```
 0x84e27030:TrueCrypt.exe                           3224   1956     14    326 2016-09-15 10:11:20 UTC+0000
. 0x85a57d40:firefox.exe                             2720   1956     49    756 2016-09-15 10:11:15 UTC+0000
. 0x85a39ab8:mspaint.exe                             2644   1956      7    147 2016-09-15 10:11:13 UTC+0000
. 0x858cbd40:VBoxTray.exe                            1124   1956     14    167 2016-09-15 10:10:53 UTC+0000
 0x8579a030:notepad.exe                              3716   3684      2     59 2016-09-15 10:11:59 UTC+0000

```
Ta thấy có tiến trình ```TrueCrypt.exe``` là một phần mềm mã nguồn mở dùng để tạo ổ đĩa ảo được mã hóa hoặc mã hóa toàn bộ phân vùng/ổ đĩa thật

Giờ thì cần tìm file bị mã hóa ổ địa và mật khẩu TrueCrypt, ta sẽ dùng plugin ```cmdline```

```
notepad.exe pid:   3716
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\info\Desktop\findme
```
Oke đã tìm thấy file tên là ```findme```, kéo nó về

```
volatility -f dump --profile=Win7SP1x86_23418 filescan | grep "findme"
Volatility Foundation Volatility Framework 2.6.1
0x000000001ee20110      3      0 R--rwd \Device\HarddiskVolume2\Users\info\Desktop\findme
```

```
 volatility -f dump --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000001ee20110 -D .

Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x1ee20110   None   \Device\HarddiskVolume2\Users\info\Desktop\findme
```

Dùng plugin ```truecryptsummary``` để tìm mật khẩu của TrueCrypt

```
volatility -f dump --profile=Win7SP1x86_23418 truecryptsummary
Volatility Foundation Volatility Framework 2.6.1
Registry Version     TrueCrypt Version 7.0a
Password             R3sqdl3Fuuz2ZdbdYsf56opFFLe9sAsx at offset 0x87433e44
Process              TrueCrypt.exe at 0x84e27030 pid 3224
Service              truecrypt state SERVICE_RUNNING
Kernel Module        truecrypt.sys at 0x87400000 - 0x87437000
Symbolic Link        Volume{a4cc2add-7b2c-11e6-b853-0800271fb50b} -> \Device\TrueCryptVolumeF mounted 2016-09-15 10:11:42 UTC+0000
Driver               \Driver\truecrypt at 0x1ee1d700 range 0x87400000 - 0x87436980
Device               TrueCrypt at 0x84e1dc90 type FILE_DEVICE_UNKNOWN
```

Đã có password giờ thì mount ổ đĩa bình thường

![image](/assets/data/34.png)

Mở ảnh flag.png nhưng không có flag bên trong :))), readme.txt cũng vậy, nhưng file readme.odt có một bài hướng dẫn sử dụng ```keepass```, Nhưng mà file database của keepass ở đâu ????

Sau 1 lúc thì mình steganography trên file ```readme.odt```
Dùng ```binwalk``` sẽ thấy một tệp ```zip``` bị ẩn bên trong, giải nén và tìm được file database của keepass trong thư mục data

```
file data/my_safety_box
data/my_safety_box: Keepass password database 2.x KDBX

```

Nhưng mà không có mật khẩu để vào :)), quay lại file ```dump``` dùng ```hashdump``` để trích xuất hash mật khẩu sau đó dùng ```john``` để bẻ khóa (Mật khẩu là ở người dùng ```infor```)

```
volatility -f dump --profile=Win7SP1x86_23418 hashdump
Volatility Foundation Volatility Framework 2.6.1
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HomeGroupUser$:1001:aad3b435b51404eeaad3b435b51404ee:57e82f46aff390080f143c09ab2c5b68:::
info:1002:aad3b435b51404eeaad3b435b51404ee:dc3817f29d2199446639538113064277:::
```

```
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 3 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Remaining 2 password hashes with no different salts
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
#1Godfather      (info)
1g 0:00:00:00 DONE (2025-06-29 13:14) 1.724g/s 24730Kp/s 24730Kc/s 49444KC/s  _ 09..*7¡Vamos!
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```
Đã có file database và password giờ thì vào keepass xem có flag khong :)))

```
keepassxc my_safety_box
```
![image](/assets/data/36.png)

Và tất nhiên là không dễ dàng đến thế :))) một đống file, không thể xem từng cái được nên mình sẽ export về dạng CSV

![image](/assets/data/38.png)

Mở ta sẽ thấy 1 đoạn được mã hóa bằng base64 khá dài, giải mã tầm 10 lần liên tục ta sẽ nhận được flag hehe ;))

## Find me again

![image](/assets/data/39.png)

Giải nén ra ta được 2 file 

```
tar -xvf ch19.txz
backup/
backup/forensic.img
backup/memory.raw
```

Sử dụng ```fls``` để xem toàn bộ file ở phân vùng ```forensic.img```  nhưng đã bị mã hóa ```LUKS``` muốn giải mã thì cần mật khẩu hoăc key

```
fls forensic.img
Encryption detected (LUKS)
```
Ta quay lại phân tích file ```memory.raw```, sử dụng ```volatility``` nhưng không tìm được ```imageinfo```, sau một lúc thì biết được ```memory.raw``` không có sẵn và cũng không phải của window mà là của Linux

```
strings memory.raw | grep "Linux version"

Linux version 4.4.0-72-lowlatency (buildd@lcy01-17) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #93-Ubuntu SMP PREEMPT Fri Mar 31 15:25:21 UTC 2017 (Ubuntu 4.4.0-72.93-lowlatency 4.4.49)
Linux version 4.4.0-72-lowlatency (buildd@lcy01-17) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #93-Ubuntu SMP PREEMPT Fri Mar 31 15:25:21 UTC 2017 (Ubuntu 4.4.0-72.93-lowlatency 4.4.49)
 o  The intent is to make the tool independent of Linux version dependencies,

```
Phải tiến hành cài ```profile``` khá lằng nhằng chúng ta để sau

1. ***Mở file LUKS***

Để tìm được key thì có 1 tool đơn giản khá hiệu quả là ```aeskeyfind```

```
aeskeyfind memory.raw
8d3f527de514872f595908958dbc0ed1
Keyfind progress: 100%
```

Giờ đã có key dùng ```cryptsetup``` để mount phân vùng

```
echo "8d3f527de514872f595908958dbc0ed1" | xxd -r -p > lukskey.bin
```
```!
sudo cryptsetup luksOpen forensic.img luks_forensic --master-key-file lukskey.bin
```
```
sudo mkdir /mnt/forensic
```
```
sudo mount /dev/mapper/luks_forensic /mnt/forensic
```

```
ls /mnt/forensic
dir2  lost+found
```

Chúng ta có mount phân vùng ra và được thư mục ```dir2``` có 3 file

```
ls
end.png  findme.txt.gpg  readme.txt
```
file ```findme.txt.gpg``` bị mã hóa gpg 

2. ***Tệp end.png***

Thấy ảnh png có vẻ nghi ngờ nên mình dùng ```binwalk``` trích xuất ra 1 tệp zip chứa file ```end.zip.gpg```

```
binwalk end.png


DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 850 x 300, 8-bit/color RGB, non-interlaced
320           0x140           Zlib compressed data, best compression
917           0x395           Zlib compressed data, best compression
493886        0x7893E         Zip archive data, at least v2.0 to extract, compressed size: 61917, uncompressed size: 61907, name: end.zip.gpg
555953        0x87BB1         End of Zip archive, footer length: 22
```

Vậy là có 2 file ```findme.txt.gpg``` và ```end.zip.gpg``` đều bị mã hóa gpg

3. ***Profile Volatility***

Cài đặt profile ```LinuxUbuntu16044x64```


4. ***Các tập tin gpg***

Dùng plugin ```linux_bash``` để xem các lệnh bash được dùng

```
volatility -f memory.raw --profile=LinuxUbuntu16044x64 linux_bash

Volatility Foundation Volatility Framework 2.6.1
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
    1229 bash                 2017-04-14 07:58:36 UTC+0000   history
    1229 bash                 2017-04-14 07:58:36 UTC+0000   apt-get install linux-image-4.4.0-72-lowlatency linux-headers-lowlatency
    1229 bash                 2017-04-14 07:58:36 UTC+0000   reboot
    1229 bash                 2017-04-14 07:58:36 UTC+0000   apt-get insta
    1229 bash                 2017-04-14 07:59:07 UTC+0000   history
    1229 bash                 2017-05-05 12:04:44 UTC+0000   apt-get install lynx gnupg
    1229 bash                 2017-05-05 12:06:54 UTC+0000   nano /etc/fstab
    1229 bash                 2017-05-05 12:06:58 UTC+0000   nano /etc/crypttab
    1229 bash                 2017-05-05 12:07:08 UTC+0000   cd /mnt/
    1229 bash                 2017-05-05 12:07:29 UTC+0000   cp -R /media/sf_DUMP/dir* .
    1229 bash                 2017-05-05 12:07:38 UTC+0000   ping 8.8.8.8
    1229 bash                 2017-05-05 12:09:14 UTC+0000   gpg --quick-gen-key 'Troll <abuse@root-me.org>' rsa4096 cert 1y
    1229 bash                 2017-05-05 12:09:49 UTC+0000   lynx -accept_all_cookies "https://www.google.com/?=password+porno+collection"
    1229 bash                 2017-05-05 12:10:27 UTC+0000   gpg --yes --batch --passphrase=1m_4n_4dul7_n0w -c findme.txt
    1229 bash                 2017-05-05 12:10:37 UTC+0000   lynx -accept_all_cookies "https://www.google.com/?=password+troll+memes"
    1229 bash                 2017-05-05 12:11:04 UTC+0000   gpg --yes --batch --passphrase=Troll_Tr0ll_TrOll -c end.zip
    1229 bash                 2017-05-05 12:11:20 UTC+0000   nano dir1/dic_fr_l33t.txt
    1229 bash                 2017-05-05 12:11:28 UTC+0000   rm findme.txt
    1229 bash                 2017-05-05 12:11:35 UTC+0000   rm -rf dir1/
    1229 bash                 2017-05-05 12:11:55 UTC+0000   dd if=/dev/sdb of=/media/sf_DUMP/forensic.img bs=2048
```
Ta thấy có các câu lệnh mã hóa 2 file ```findme.txt.gpg``` và ```end.zip.gpg``` có mật khẩu kèm theo, giờ thì giải mã khá đơn giản

```
gpg --batch --yes --passphrase 1m_4n_4dul7_n0w -d findme.txt.gpg > findme.txt

gpg: AES.CFB encrypted data
gpg: encrypted with 1 passphrase
```
file ```fixme.txt``` chứa 

```
cat findme.txt
The flag is not here of course !!!
You must find it :-)
Troll one day troll always ........
```

```
gpg --batch --yes --passphrase Troll_Tr0ll_TrOll -d end.zip.gpg > end.zip

gpg: CAST5.CFB encrypted data
gpg: encrypted with 1 passphrase
gpg: WARNING: message was not integrity protected
```

Giải nén tệp ```end.zip``` nhưng nó yêu cầu mật khẩu :)))



5. ***Mật khẩu end.zip***

Xem lại lịch sử bash, chúng ta thấy rằng ```dir1/dic_fr_l33t.txt``` đã được chỉnh sửa rồi xóa.
Hãy thử khôi phục tệp này

```
sudo extundelete /dev/mapper/luks_forensic --restore-directory dir1

NOTICE: Extended attributes are not restored.
WARNING: EXT3_FEATURE_INCOMPAT_RECOVER is set.
The partition should be unmounted to undelete any files without further data loss.
If the partition is not currently mounted, this message indicates
it was improperly unmounted, and you should run fsck before continuing.
If you decide to continue, extundelete may overwrite some of the deleted
files and make recovering those files impossible.  You should unmount the
file system and check it with fsck before using extundelete.
Would you like to continue? (y/n)
y
Loading filesystem metadata ... 3 groups loaded.
Loading journal descriptors ... 31 descriptors loaded.
Searching for recoverable inodes in directory dir1 ...
2 recoverable inodes found.
Looking through the directory structure for deleted files ...
1 recoverable inodes still lost.
```
Giờ dùng ```john``` với wordlists là tệp vừa khôi phục ta sẽ bẻ khóa được mật khẩu

```
john hash.txt --wordlist=../RECOVERED_FILES/dir1/dic_fr_l33t.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Cyb3rs3curit3    (end.zip/flag.gif)
1g 0:00:00:00 DONE (2025-06-29 15:19) 33.33g/s 1911Kp/s 1911Kc/s 1911KC/s Cont3ntions..D3activons
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Giải nén được 1 tệp ```flag.gif```
```
unzip end.zip
Archive:  end.zip
[end.zip] flag.gif password:
  inflating: flag.gif
```
```flag.gif``` được thay đổi liên tục theo từng frame có thể viết mã ```python``` nhưng đơn giản hơn là dùng ```zbarimg```

```
zbarimg -q --raw flag.gif | tr -d '\n'
....
The_flag_is:1_Lik3_F0r3nS1c_4nd_y0u?
```