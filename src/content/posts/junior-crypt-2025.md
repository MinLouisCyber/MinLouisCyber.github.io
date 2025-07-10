---
title: "[Write-up] Junior.Crypt.2025 CTF"
published: 2025-07-04
tags: [CTF, Junior.Crypt]
category: Write-up
description: Thật vui khi ghi được điểm trong cuộc thii
draft: false
---



## Forensics
### Recovery password

Đây là một bài forensics về lỗ hổng bảo mật ```CVE-2023-32784``` về phiên bản ```keepaas 2.X``` có thể tham khảo tại đây

Ta sẽ phân tích file ```KeePass.DMP``` để lấy mật khẩu 
```
keepass KeePass.DMP
....
1.:     ●
2.:     3, 2, Ï, £, À, ', §, e, \, z, 4, , m, b, &, B, /,  ,
3.:     S, 2,
4.:     t, 6,
5.:     _, 8, ¸,
6.:     f, 7,
7.:     0, 6, ð,
8.:     r, 5,
9.:     _, 1,
10.:    z, 2,
11.:    3, A,
12.:    r, i,
13.:    0,
14.:    -,
15.:    d,
16.:    4,
17.:    y,
18.:    _,
19.:    H,
20.:    u,
21.:    n,
22.:    T,
23.:    1,
24.:    N,
25.:    g,
Combined: ●{3, 2, Ï, £, À, ', §, e, \, z, 4, , m, b, &, B, /,  }{S, 2}{t, 6}{_, 8, ¸}{f, 7}{0, 6, ð}{r, 5}{_, 1}{z, 2}{3, A}{r, i}0-d4y_HunT1Ng

```
```
*3St_f0r_z3r0-d4y_HunT1Ng
```
Ta có thể thấy bị thiếu chữ cái đầu, có thể dùng ```python``` để sinh ra 1 list mật khẩu với chữ cái đầu thay đổi sau đó dùng ```kepass2john``` để tấn công dựa trên wordlist đã tạo, tìm được mật khẩu là ```z3St_f0r_z3r0-d4y_HunT1Ng``` vào keepass và lấy flag

```
flag: grodno{T001_uP_0r_Dr00L_D0wn}
```
### Rainbow in White
>Sir Isaac Newton experimentally proved that white light consists of a mixture of seven colors, such as red, orange, yellow, green, blue, indigo, and violet. Newton also showed that you can collect these colors back into white light using a prism. We don't need a prism. And we have more colors. And we need to find a flag.

Xem ảnh chỉ toàn là màu trắng, mình đoán nó sai kích thước chiều dài chiều rộng nên không hiển thị được pixel

Đổi tên thành ```.data``` sau đó mở bằng ```Gimp 3``` điều chỉnh lại chiều dài và rộng ta sẽ thấy được flag

![image](/assets/data/junior_1.png)

```
flag: grodno{hihihi-hahaha-hohoho-kokoko}
```

### S=HxW
>In geometry it's like this: S = H * W. This isn't geometry. Here you'll be taught ...

Mở ảnh lên thì cũng trắng xóa đề bài cũng gợi ý là ảnh liên quan đến width và height nên ta mở bằng gimp 3 để điều chỉnh là nhưng không hiệu quả, không thể đọc được


Mở bằng trình soản thảo hex ta xác định được chiều rộng của ảnh ở  4 byte ```F7 00 00 00``` và chiều cao là```EB 00 00 00```, ta điều chỉnh chiều cao thành ```EB 01 00 00``` vì ảnh ``.bmp`` sử dụng ```little-endian``` nên khi giải mã ra thì byte thấp nhất được lưu trước, byte cao nhất lưu sau nên có dạng ```00 00 01 EB``` tương đương với ```491 pixel``` => hợp lí, Mở ra ta được flag

![NotGeometry](/assets/data/junior_2.bmp)


### All_in_white

## Beginner

### Double Trouble
>WjNKdlpHNXZlMlpwY25OMFgzTjBaWEJmYzJWamIyNWtYM04wWlhCOQ==
>The message you received looks like gibberish — but not entirely unfamiliar. You have a feeling you've seen this encoding style before. Maybe it’s been encoded… twise?

Giải mã chuỗi ```base64``` 2 lần ta sẽ được flag

```
flag: grodno{first_step_second_step}
```
### EXIF
>What is the easiest way to hide information in an image?

Xem thông tin của ảnh bằng ```exiftool``` ta sẽ thây flag ở phần ```Subject```

```flag: flag{beyond_the_image}```

### Birds and Wires
>These birds have been sitting on the wires for a week now, it seems to me they want to tell me something.!
[Birth.png](https://github.com/sajjadium/ctf-archives/blob/main/ctfs/Junior.Crypt/2025/misc/Birds_and_Wires/Birds.png)

Đây là ```Birds on a Wire Cipher``` dùng trang này để giải mã https://www.dcode.fr/birds-on-a-wire-cipher



### White Cat in a White Room
>It will be easier to find a white cat in a white room if you paint the cat black
[CatInRoom.bmp](https://github.com/sajjadium/ctf-archives/blob/main/ctfs/Junior.Crypt/2025/forensic/White_Cat_in_a_White_Room/CatInRoom.bmp)

Mở ra chỉ có 1 màu trắng nhưng thấy có sự bất thường, dùng ```stegsolve``` tách các lớp màu (RGB, ARGB, Blue Plane, Green Plane, Red Plane, v.v) để tìm thông tin ẩn ta sẽ thấy được flag 

![image](/assets/data/junior_3.png)

### Interesting prefix
Đề bài bắt chúng ta chuyển ```ip``` của trang web http://ctf-spcs.mf.grsu.by/ theo 6to4

Ta dễ dàng check được địa chỉ ip của trang web này là ```86.57.166.23```
IPv4 sang chuẩn IPv6 6to4 có dạng ```2002:<IPv4 in hex>::/48```

```
flag: grodno{2002:5639:A617::/48}
```

### Yin Yang
>From ancient philosophy to modern thought, Yin and Yang represent balance, duality, and harmony of opposites. This image contains a secret that embodies these principles. Can you find balance in chaos?
>[Yin_Yang.png](/assets/data/junior_3.png)

Ta thây có 2 số ấm dương, ```xor``` 2 chuỗi này theo thứ tự đầu cuối ta sẽ được 1 dãy số ascii giải ra ta được flag

```python
A = [3, 165, 166, 71, 149, 253, 21, 105, 212, 230, 240, 74, 229, 141, 28, 230, 92, 119, 15, 37, 232, 15, 219]
B = [126, 157, 149, 117, 165, 207, 38, 91, 231, 223, 200, 126, 215, 181, 40, 210, 39, 24, 97, 65, 135, 125, 188]

result = [a ^ b for a, b in zip(A, B)]

print(result)
```
### The Ripper
>The archive is one of the most secure places on my computer, unless the password is qwerty of course :)
Fortunately, I always use a random set of nine digits, oops... I shouldn’t have said that.
[super-secret-files.zip](https://github.com/sajjadium/ctf-archives/blob/main/ctfs/NewYear/2024/misc/The_Ripper/super-secret-files.zip)

Không còn lựa chọn nào khác là dùng ```John The Ripper``` để tấn công từ điển lấy mật khẩu 9 chữ số :)))
```
zip2john super-secret-files.zip > john.txt
```
```
john john.txt --mask='?d?d?d?d?d?d?d?d?d'

Using default input encoding: UTF-8
Loaded 4 password hashes with 4 different salts (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Loaded hashes with cost 1 (HMAC size) varying from 66 to 22210
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

```
Khoảng 1 tiếng :)))thì sẽ nhận được mật khẩu, giải nén và nhận flag 



## Misc

### Interesting WAV
>sometimes the PreseNt is deeper - not everythinG that sounds needs to be listened to
>[stego.wav](https://github.com/sajjadium/ctf-archives/blob/main/ctfs/Junior.Crypt/2025/misc/Interesting_WAV/stego.wav.xz)

Nghe thì không phải mã ```morse``` nên ta dùng ```binwalk``` để xem có tệp nào được ẩn bên trong không ta thấy có 1 tệp ảnh 

```
binwalk --dd=".*" stego.wav

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             RIFF audio data (WAV), PCM, 1 channels, 8000 sample rate
44            0x2C            JPEG image data, JFIF standard 1.01
```
Xem ảnh ta được flag

### Intel order VS Network order
>Where did the flag go? Flag in format grodno{flag}
>[task_for_001.bmp](https://github.com/sajjadium/ctf-archives/blob/main/ctfs/Junior.Crypt/2025/misc/Intel_order_VS_Network_order/task_for_001.bmp)

Mở lên thì thấy ảnh bitmap bị hỏng nên ta sẽ mở trình soạn thảo hex ```HxD```

![image](/assets/data/junior_5.png)

Ta thấy các byte ```00 00 00 28``` bị đảo ngược sửa lại thành ```28 00 00 00``` ta sẽ mở được ảnh và thấy flag


## Stegano

### Guitar melody
>My good friend sent me an audio file with a guitar melody. I can't understand what he wanted to tell me... Flag in the format grodno{secret_message}.
>[DEPart.wav](https://github.com/sajjadium/ctf-archives/blob/main/ctfs/Junior.Crypt/2025/steg/Guitar_melody/DEPart.wav.xz)

Mở file âm thanh bằng ```audacity``` chuyển thành chế độ ```spectrogram``` ta sẽ thấy 1 đoạn text khá khó đọc edit lật xoay 1 lúc thì ta có thể đọc được

![Screenshot 2025-07-01 171358](/assets/data/junior_6.png)

```
M37RO_2033_R3DUX
```

### Big pik
Mở lên nghe và biết đây là mã morse vì vậy có thể dùng https://morsecode.world/international/decoder/audio-decoder-adaptive.html để giải mã

```
THE LIFE AND ADVENTURES OF ROBINSON CRUSOE BY DANIEL DEFOE IS A NOVEL WRITTEN IN THE EARLY 18TH CENTURY THE BOOK CHRONICLES THE LIFE OF ROBINSON CRUSOE. A YOUNG MAN WHOSE ADVENTUROUS SPIRIT LEADS HIM TO DEFY HIS FATHER'S WISHES AND PURSUE A LIFE AT SEA. WHICH ULTIMATELY RESULTS IN A SERIES OF HARROWING MISFORTUNES. INCLUDING SHIPWRECK AND ISOLATION ON A DESERTED ISLAND THE OPENING OF THE NOVEL INTRODUCES ROBINSON CRUSOE'S EARLY LIFE. DETAILING HIS UPBRINGING IN IN GRODNO/4NDH1SYEARN1NGF0RADVENTURE/ DESPITE HIS FATHERS WARNINGS AGAINST SUCH A RECKLESS LIFESTYLE
```

```
flag: grodno{4nd_h1s_yearn1ng_f0r_adventure}
```

### Lonely Squirrel Blues

Thử thách cho ta 1 tệp ```.gif``` xem thông tin của tệp thì thấy tệp này được tạo từ ```https://ezgif.com/maker```, trang web này sẽ tạo tệp gif từ các ảnh

```
exiftool Squirrel_plays_the_banjo.gif
ExifTool Version Number         : 13.25
File Name                       : Squirrel_plays_the_banjo.gif
Directory                       : .
File Size                       : 120 kB
File Modification Date/Time     : 2025:07:02 12:09:17+07:00
File Access Date/Time           : 2025:07:04 16:51:03+07:00
File Inode Change Date/Time     : 2025:07:02 12:09:22+07:00
File Permissions                : -rw-r--r--
File Type                       : GIF
File Type Extension             : gif
MIME Type                       : image/gif
GIF Version                     : 89a
Image Width                     : 220
Image Height                    : 220
Has Color Map                   : Yes
Color Resolution Depth          : 8
Bits Per Pixel                  : 8
Background Color                : 0
Animation Iterations            : Infinite
Comment                         : GIF created with https://ezgif.com/maker
Frame Count                     : 5
Duration                        : 1.00 s
Image Size                      : 220x220
Megapixels                      : 0.048
```

Ta sẽ tách các ảnh từ tệp gif này ra bằng ```convert```

```
convert Squirrel_plays_the_banjo.gif frames/frame_%03d.png
```

Ta sẽ được 5 ảnh, dùng ```zsteg``` sẽ thấy mỗi ảnh có 1 đoạn text được mã hóa ```base32```

```
"part1:M5ZG6ZDON55US3S7ORUGKX3GNFSWYZC7N5TF62L:"
"part2:OMZXXE3LBORUW63S7ONSWG5LSNF2HSLC7JRSWC4:"
"part3:3UL5JWSZ3ONFTGSY3BNZ2F6QTJORZV6KCMKNBCS:"
"part4:X3BNRTW64TJORUG2X3JONPWC3S7NFWXA33SORQW:"
"part5:45C7ORXXA2LDL5XWMX3ENFZWG5LTONUW63T5:"
```

```
flag: grodno{In_the_field_of_information_security,_Least_Significant_Bits_(LSB)_algorithm_is_an_important_topic_of_discussion}
```

### Uncommon text

Thử thách cho ta 1 file ```.docx``` bằng tiếng pháp suy nghĩ một chút thì ta biết đây là một kỹ thuật steganography đơn giản, trích xuất thông điệp ẩn trong văn bản Word (.docx) bằng cách lợi dụng sự giống nhau về hình dạng giữa ký tự ```Cyrillic``` và ```Latin```, nếu là kí tự ```cyrillic``` thì là bit 0, kí tự ```Latin``` là bit 1

Kí tự ```Cyrillic``` và ```Latin``` rất giống nhau, nhìn bằng mắt thường thì không phát hiện được

Các kí tự ```Cyrillic``` và ```Latin``` giống nhau về hình dạng nhưng thực chất thì khác nhau
```python
visually_similar_letters = {
    'A': ('А', 'A'), 'a': ('а', 'a'),
    'B': ('В', 'B'),
    'C': ('С', 'C'), 'c': ('с', 'c'),
    'E': ('Е', 'E'), 'e': ('е', 'e'),
    'H': ('Н', 'H'),
    'K': ('К', 'K'),
    'M': ('М', 'M'),
    'O': ('О', 'O'), 'o': ('о', 'o'),
    'P': ('Р', 'P'), 'p': ('р', 'p'),
    'T': ('Т', 'T'),
    'X': ('Х', 'X'), 'x': ('х', 'x'),
    'Y': ('У', 'Y'), 'y': ('у', 'y'),
}

```

```python
from docx import Document

visually_similar_letters = {
    'A': ('А', 'A'), 'a': ('а', 'a'),
    'B': ('В', 'B'),
    'C': ('С', 'C'), 'c': ('с', 'c'),
    'E': ('Е', 'E'), 'e': ('е', 'e'),
    'H': ('Н', 'H'),
    'K': ('К', 'K'),
    'M': ('М', 'M'),
    'O': ('О', 'O'), 'o': ('о', 'o'),
    'P': ('Р', 'P'), 'p': ('р', 'p'),
    'T': ('Т', 'T'),
    'X': ('Х', 'X'), 'x': ('х', 'x'),
    'Y': ('У', 'Y'), 'y': ('у', 'y'),
}


char_origin = {}
for pair in visually_similar_letters.values():
    cyrillic, latin = pair
    char_origin[cyrillic] = '0'  
    char_origin[latin] = '1'     

def extract_bits_from_docx(path):
    doc = Document(path)
    bits = []

    for para in doc.paragraphs:
        for ch in para.text:
            if ch in char_origin:
                bits.append(char_origin[ch])

    return ''.join(bits)

binary_message = extract_bits_from_docx('history.docx')
print("binary_message:", binary_message)

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

hidden_text = bits_to_text(binary_message)
print("hidden text:", hidden_text)
```

```
python3 solve_docx.py
binary_message: 011001110111001001101111011001000110111001101111011110110011000101101110010101100011000101110011001100010011100001001100001100110101111101001100001100110011011100110111001100110101001001011010011111010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
hidden text: grodno{1nV1s18L3_L3773RZ}
```
### eXtraOrdinaRy song
### Broken pixels
### Text sound
### New Year's satellite
### Write comments!
