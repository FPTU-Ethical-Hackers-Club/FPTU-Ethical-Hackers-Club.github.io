---
title: Cryptographic
author:
    name: phucdc-noob
    link: https://github.com/phucdc-noob
date: 2021-11-09 20:07:00 +0700
categories: [Wiki, Cryptographic]
tags: [wiki, cryptographic]
mermaid: true
math: true
---

## Tổng quan

Cryptography (Mật mã học) là một phân nhánh cổ xưa nhất của bảo mật. Có lẽ trong số chúng ta lại biết nhiều nhất là mật mã Caesar của quân đội La Mã cổ đại, nhưng thực chất, lịch sử của mật mã học đã phát triển từ trước đó rất lâu rồi. Cụ thể, mật mã đầu tiên được ghi nhận là hệ thống các chữ tượng hình được khắc trên một lăng mộ tại Ai Cập (khoảng năm 1900 TCN), cũng vào thời kì này của Ai Cập, có một cuốn sách mang tên Greek Magical Papyri cũng được mã hoá một phần. Tại Ấn Độ (400 TCN - 200), các cặp đôi yêu nhau sử dụng kĩ thuật Mlecchita vikalpa như một phương pháp để trao đổi thông tin mà không bị phát hiện. Skip nhanh đến thời hiện đại, một nhà toán học vĩ đại, người mà nổi tiếng không chỉ trong lĩnh vực toán học, mà còn là tiền đề của ngành mật mã học và ngành học máy, Alan Turing với chiếc máy Bombe của mình, đã thành công giải mã các mật mã được tạo ra bởi cỗ máy Enigma của Đức Quốc xã (thứ mã Hitler ca ngợi là “Mật mã số một thế giới, thần thánh cũng không giải được”), từ đó, đem lại chiến thắng cho quân Đồng Minh.

Ngày nay, mật mã được ứng dụng rất nhiều trong tin học, cụ thể là trong việc trao đổi và lưu trữ dữ liệu một cách an toàn theo các tiêu chí:

- __Confidentiality__ (tính bảo mật): Dữ liệu phải được đảm bảo không bị lộ, truy cập bởi những người dung không được phép.

- __Integrity__ (tính toàn vẹn): Dữ liệu phải nguyên vẹn, đảm bảo không bị chỉnh sửa cho dù với bất kì nguyên nhân nào (bị tấn công, mất mát, …)

- __Availability__ (tính sẵn sàng): Dữ liệu phải luôn trong trạng thái sẵn sàng và có thể truy cập bất cứ lúc nào.

- __Non-repudiation__ (không thể chối bỏ): Cụ thể là khi dữ liệu được trao đổi giữa 2 bên A và B, cả 2 bên không thể phủ nhận việc đó, và cũng đồng thời chắc chắn 
rằng, không ai khác ngoài A và B biết điều này.

Mặc dù tính sẵn sàng không được thể hiện quá nhiều trong mã hoá, nhưng trong ứng dụng thực tế, các cơ chế mã hoá điện tử lại thể hiện rất rõ 3 tính chất còn lại. Hiện nay, việc nhắc đến “Cryptography” là ám chỉ một trong các kĩ thuật sau:

- __Symmetric encryption__ (Mã hoá đối xứng)

- __Asymmetric encryption__ (Mã hoá bất đối xứng)

- __Hashing__ (Kĩ thuật băm)

- __Digital signatures__(Chữ kí số)

Có 2 thuật ngữ mà ta cần nắm rõ:

- __Encryption:__ là quá trình mã hoá một thông điệp từ dạng đọc được (Plain text) thành không đọc được (Cipher text)

- __Decryption:__ là quá trình ngược lại của encryption (Cipher text à Plain text )

## Symmetric encryption

Mã hoá đối xứng là kiểu mã hoá mà quá trình encryption và decryption sử dụng chung một mã (key). Các thuật toán mã hoá đối xứng thường được sử dụng như DES, AES, RC4, RC5,…

Việc sử dụng mã hoá đối xứng sẽ hoạt động như sau:

- Bên gửi sinh ra Plain text $(M)$

- Bên gửi sinh ra một khoá kín ($KS$ – Secret Key) một cách ngẫu nhiên và gửi cho bên nhận

- Bên gửi sử dụng khoá $KS$ để encrypt plain text $M$ thành một bản mật ($C$ - Cipher text), quá trình này được thể hiện như sau $C = E(KS, M)$ và gửi cho bên nhận

- Bên nhận sử dụng key $KS$ và Cipher text đã nhận để Decrypt về plain text $M = D(KS, C)$

Từ cơ chế trên, ta thấy rằng, việc để ổ khoá chung với chìa khoá như vậy sẽ sinh ra các vấn đề về bảo mật. Hãy thử tưởng tượng, ông tướng A gửi một thư mật cho ông tướng B, bức thư được mã hoá và bên dưới có ghi cách giải, ông A giao cho anh lính gửi hoả tốc, nhưng trên đường bị tướng địch bắn hạ và thu được mật thư :D Đây chính là phương pháp tấn công Man-in-the-middle (MITM).

## Asymmetric encryption

Mã hoá bất đối xứng là kiểu mã hoá mà quá trình encryption và decryption sử dụng mã key khác nhau, các thuật toán mã hoá tiêu biểu: RSA, DSA, PKCS,…

Quá trình mã hoá bất đối xứng như sau:

- Bên nhận tạo ra một khoá công khai ($KP$ – public key) và gửi cho bên gửi, đồng thời tạo khoá kín ($KS$), được bên nhận giữ kín

- Bên gửi sau khi tạo ra plain text ($M$), tiến hành mã hoá $M$ bằng $KP$ của bên nhận đã gửi trước đó: $C = E(M, KP)$ và gửi C cho bên nhận

- Bên nhận sử dụng khoá $KS$ để giải mã thông điệp đã nhận được: $C = D(M, KS)$

Trong mã hoá bất đối xứng, $KS$ và $KP$ sẽ được tạo sao cho trong trường hợp người dung bị MITM lấy mất $KP$, hackers cũng không thể suy ra được $KS$ nhưng vẫn tồn tại một mối quan hệ toán học giữa 2 key, cơ chế $KS – KP$ này giúp người dung có thể yên tâm, ngay cả khi thông điệp giữa bên A và B bị lộ, thì những quá trình trao đổi thông tin giữa A và C, D, … vẫn được đảm bảo bí mật.

Có thể thấy rằng, mã hoá bất đối xứng đã giải quyết được những hạn chế của mã hoá đối xứng, khi mà chỉ có người sở hữu $KS$ mới có thể đọc được nội dung đã được mã hoá bằng $KP$. Nhưng, làm thế nào để ta biết được cái $KP$ là chính xác của bên gửi? Hãy tìm hiểu thêm về Public Key Infrastructure (PKI). Trên thực tế, chúng ta sẽ nhờ các nhà cung cấp chứng thực số (Certificate Authority - CA) đóng vai trò làm trung gian trong quá trình trao đổi thông tin.

## Hashing functions

Ngược lại với cơ chế mã hoá/giải mã như trên, hashing functions là những hàm chỉ có 1 chiều, tức là, bạn đưa input vào hash functions và nhận được một đoạn hash, nhưng bạn không thể convert ngược đoạn hash đó về input được :D

Một hàm hashing lý tưởng phải thoả mãn 2 điều kiện:

- Mã hash được tạo ra của input phải là độc nhất, 2 input khác nhau không được phép có mã hash giống nhau.

- Với input giống nhau phải cho ra mã hash giống nhau.

Nếu đã từng thao tác với mã hash thì sẽ thấy chúng giống như được tạo ra ngẫu nhiên, nhưng không phải vậy, với mỗi loại mã hash (SHA256, MD5, …) thì chúng sẽ có một độ dài cố định.

Từ những đặc điểm trên, hashing functions không thể được sử dụng trong việc lưu trữ dữ liệu (mã hoá xong phát coi như mất :D) nhưng lại có thể được sử dụng để xác định tính toàn vẹn của dữ liệu, vì chỉ cần thay đổi dù chỉ là một dấu cách trong input, sẽ tạo ra một mã hash khác hoàn toàn. Bên cạnh đó, khi mà việc lưu trữ trực tiếp password trong database đã quá nguy hiểm, việc lưu trữ chúng dưới dạng Hashing cũng là một lựa chọn, lưu password được tạo dưới dạng mã hash, mỗi lần người dùng đăng nhập thì hashing lại input của người dùng và đối chiếu với mã hash đã lưu, vừa đảm bảo có gì đó để so sánh, vừa đảm bảo không để lộ thông tin nhạy cảm khi sự cố xảy ra.

## Digital signatures

Đây là sự kết hợp giữa mã hoá bất đối xứng và hashing functions:

- Phía signer sẽ tiến hành hash input và mã hoá tiếp với KS

- Signer gửi thông điệp đính kèm với chữ kí số vừa được tạo

- Phía người nhận sẽ sử dụng $KP$ để decrypt chữ kí số về mã hash, sau đó tiến hành hash thông điệp đính kèm để đối chiếu với mã hash của chữ kí số

Đây là cách để đảm bảo tính toàn vẹn, tính bảo mật và tính không thể chối từ của thông điệp được gửi đi. Nhờ đảm bảo được những điều trên, chữ ký số được sử dụng trong giao dịch điện tử, e-mail, chuyển tiền, thanh toán trực tiếp, … Ngoài ra, chữ ký số cũng được áp dụng trong các công vụ của Chính phủ như thuế, hải quan, …

## Kết luận

Mật mã học (Cryptography) là một mảng đã có quãng thời gian phát triển lâu đời nhất trong bảo mật thông tin, với lịch sử phát triển lâu đời như vậy, thật không dễ để chúng ta có thể nắm được, vì vậy tôi xin được đề cập một số cuốn sách để tham khảo và rèn luyện về mảng “Old but Gold” này:

- Cryptography made simple – Nigel P. Smart

- Applied cryptography – Bruce Schneier

- Cryptography: Theory and Practice – Doug Stinson

- Understanding cryptography: A textbook for students – Christof Paar

- Giáo trình mật mã học và an toàn thông tin – Ts. Thái Thanh Tùng