---
title: ASCIS (ASEAN Student Contest on Information Security) 's Web Write-ups
author:
  name: antoinenguyen_09
  link: https://github.com/antoinenguyen-09
date: 2021-10-17 12:00:00 +0700
categories: [CTF, Web Challenges]
tags: [writeups, web, SVATTT2021]
mermaid: true
---

> Ở SVATTT 2021 năm nay thì team mình không vượt qua vòng lại, tuy nhiên cá nhân mình vẫn solve đc 2 bài web Script Kiddie và OProxy, coi như là một kỉ niệm lần đầu đi thi SVATTT có vui lẫn buồn.

# Script Kiddie

![image](https://user-images.githubusercontent.com/61876488/138734841-93adf918-5e68-4ec4-8d81-9401f643cacd.png)

[Source]()

### 1. Initial reconaissance:

Như mô tả ta có thể biết rằng web có chứa lỗ hổng SQL-injection với cơ sở dữ liệu được dùng ở đây là Microsoft SQL Server. Câu query như hình dưới

![image](https://user-images.githubusercontent.com/61876488/139046934-9f31fbf9-36c9-4774-9736-a8befe8ad501.png)

### 2. Exploit and get the flag:

- Payload:

```
(CASE WHEN (ascii(substring(db_name(), 1, 1)) =115) THEN 99 ELSE 1*'name' end)
```

- Bạn có thể dùng Intruder của Burp Suite để brute force, hoặc tự viết script, các response trả về status 200 OK đồng nghĩa với payload trả về 99 --> true --> kí tự valid thuộc database name (lấy từ hàm `db_name` của payload).

- Tham khảo bài viết sau về các dùng Intruder của Burp Suite: https://portswigger.net/burp/documentation/desktop/tools/intruder/using.

![image](https://user-images.githubusercontent.com/61876488/147627227-2a1de958-cc94-46db-8b80-2621e926a2c2.png)

- Flag: `ASICS{ssalchtiwesmihcueymorf}`


# OProxy

![image](https://user-images.githubusercontent.com/61876488/138734999-47bd9310-d23a-4b6f-a76e-46920f30263e.png)

### 1. Initial reconnaissance:

Đầu tiên chúng ta cần tạo account để login vào:

![image](https://user-images.githubusercontent.com/61876488/138804603-2b407efe-bf24-4bf2-84b0-c3d1e24cac60.png)

Sau khi xem qua sơ bộ thì ta có thể tóm tắt web app của challenge này có những chức năng như sau:

- `/proxy`: khi nhập vào một URL bất kì (vd như https://stackoverflow.com) rồi bấm nút "Go!" thì web app sẽ tự động redirect đến URL đó.

![image](https://user-images.githubusercontent.com/61876488/138809779-5d5d13d9-88c5-4296-91b4-d22e1e2e979a.png)

- `/history?key=<key>&memcache=<memcache>`: tất cả những URL mà web app này redirect đến thông qua chức năng `/proxy` sẽ được ghi lại tại đây. Parameter `key` có lẽ là để xác định mỗi trang history riêng biệt cho từng user, còn `memcache` thì không rõ là để làm gì, nhưng khi gán `memcache` 1 giá trị bất kì thì ô thuộc cột **Cached** trong bảng history thay đổi.
  
![image](https://user-images.githubusercontent.com/61876488/138852559-ca8953c9-7b16-4e74-8807-cce28735f0b7.png)

### 2. Find the vulnerabilities:
  
- Như đã nói về parameter `key` thuộc chức năng `/history`, chúng ta sẽ tạo thêm một account nữa, sau đó thử lấy key của user `hoangnch` thay cho key của user đó để check xem web app này có bị [IDOR](https://portswigger.net/web-security/access-control/idor) không. 

![image](https://user-images.githubusercontent.com/61876488/138852424-302e1bac-8001-41c4-80bd-1a8b5b4f4896.png)

Hmm, như vậy không bị dính IDOR. Có lẽ chức năng `history` không phải là mấu chốt để giải được bài này.

- Chúng ta lại test tiếp chức năng `/proxy`. Sẽ ra sao nếu chúng ta không nhập vào đấy một URL bình thường như `https://github.com` mà là một cái link của Burp Collaborator client nhỉ?

![image](https://user-images.githubusercontent.com/61876488/138855646-420a0e30-cab3-4aa4-8bbe-9db155612fe3.png)

Web app này vẫn gửi request tới Collaborator client của chúng ta mà không hề validate URL. Điều này chứng tỏ nó đã bị dính [Server Side Forgery Request](https://portswigger.net/web-security/ssrf).

Oke, vậy sẽ ra sao nếu URL là `http://127.0.0.1/register` (`127.0.0.1` đồng nghĩa với localhost, là chính nó luôn) nhỉ?

![image](https://user-images.githubusercontent.com/61876488/138856877-767eebf3-3294-4401-9af7-f8ebb876f5e5.png)
 
OMG, cũng được luôn. Tuy nhiên, vì chúng ta sủ dụng URL có protocol là **HTTP**, do đó chắc chắn chỉ có thể nhìn nhận web app này dưới dạng HyperText. Thử sửa `http` thành `file` xem sao, cụ thể là `file://127.0.0.1/etc/passwd`:

![image](https://user-images.githubusercontent.com/61876488/138858321-a6b9325c-54d9-40e6-85b4-775ab93ec31f.png)

Tuyệt vời, điều này có nghĩa là chúng ta có thể path traversal thông qua [**FILE**](https://en.wikipedia.org/wiki/File_URI_scheme) protocol, sau đó thoải mái đọc file trên localhost của web app này!

### 3. Exploit and get flag:

Còn một trở ngại cuối cùng nữa, đó là chúng ta không biết flag này ở chỗ nào :v. Nếu bài này mà lại đi đoán đường dẫn thì unintended vl :(. Sau một hồi brute force tìm đường dẫn đến tuyệt vọng thì chợt nhận ra là Linux lưu trạng thái của tất cả mọi thứ dưới dạng file (đọc tại [đây](https://man7.org/linux/man-pages/man5/proc.5.html)), kể cả các process đang chạy trên máy. `/proc/self` là một trong những magic đó của Linux, nó là folder chứa **context của process hiện tại**. Trong `/proc/self` đó lại chứa rất nhiều file và folder lưu nhiều thông tin khác nhau của process hiện tại, trong đó cái thú vị nhất là `/proc/self/cwd` chứa directory hiện tại mà process đang chạy trên đó (current working directory):

![image](https://user-images.githubusercontent.com/61876488/138863249-b4cba18f-aa3f-4262-b42b-aaee09a7997c.png)

![image](https://user-images.githubusercontent.com/61876488/138863549-c7cdba14-8d1d-40e0-ad48-db5912a6e346.png)


Để dễ hiểu hơn thì ta sẽ thử chạy một cái app php tại đường dẫn `/home/kali/Documents/php_basic` trên linux rồi check xem bên trong `/proc/self/cwd` có gì:

![image](https://user-images.githubusercontent.com/61876488/138863839-d46d2672-204e-4c7f-bff6-d47e564f7948.png)

Vậy chắc chắn flag sẽ nằm trong current working directory của process đang chạy cái web app này. Do đó, payload của cuối cùng sẽ là: `file://127.0.0.1/proc/self/cwd/flag.txt`

![image](https://user-images.githubusercontent.com/61876488/138864339-2d92cbde-01fe-4d09-bfdf-2d2b8071e960.png)

Flag: `ASCIS{SSRF_M3mcached_inj3cti0n}`
