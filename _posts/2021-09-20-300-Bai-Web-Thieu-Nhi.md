---
title: Bí kíp 300 bài Web thiếu nhi
author:
    name: LamNNT
date: 2021-09-20 19:45:00 +0700
categories: [Wiki, Web Exploitation]
tags: [wiki, web]
mermaid: true
---

Internet ngày nay đã trở thành một phần không thể thiếu trong cuộc sống của mỗi chúng ta. Cùng với sự phát triển của internet, các website cũng ngày càng phức tạp hơn so với những phiên bản đầu tiên của nó vào những năm 1990. Website bao gồm 2 phần chính, là front-end (bộ mặt của website) và back-end(bộ não của website). Back-end là khu vực xử lý các thao tác với database (cơ sở dữ liệu), trả lại các giá trị dựa trên những request (yêu cầu) mà client (người dùng) gửi lên server. Vì back-end là nơi lưu trữ các dữ liệu quan trọng của người dùng một trang web như tài khoản, mật khẩu, thông tin cá nhân,... nó trở thành mục tiêu tấn công của các hacker, nhằm vào các thông tin nhạy cảm. Việc xây dựng một trang web cũng vô cùng phức tạp, nên các lỗ hổng bảo mật (vulnerability) xuất hiện là điều không thể tránh khỏi, dẫn tới sự xuất hiện của lĩnh vực “Web Exploitation” (khai thác ứng dụng web). Với tư cách là một sinh viên đang ngồi trên ghế nhà mình, học online tại FPTU, mình xin chia sẻ một vài hiểu biết của bản thân về một lĩnh vực rộng lớn và vô cùng quan trọng trong ngành bảo mật. Năm 2017, __OWASP đã công bố 10 lỗ hổng nghiên trọng, phổ biến trên website như sau__:

- __Injection__: Hậu quả của việc server nhận dữ liệu không được kiểm chứng và được biên dịch dưới dạng các câu lệnh hoặc các query (truy vấn trong cơ sở dữ liệu). Tiêu biểu phải kể đến SQL Injection, lỗi xuất hiện trên hệ cơ sở dữ liệu SQL. Lỗi này có thể giúp hacker xem, xóa, sửa, các thông tin trên hệ cơ sở dữ liệu. Bên cạnh đó chúng ta còn có LDAP injection và HTTP header injection. Tất cả các lỗ hổng trên đều dễ gặp phải ở những trang web của những lập trình viên mới vào nghề, còn ít kinh nghiệm (ngoại trừ trang web của tập đoàn B* nào đó 🐧 )

- __Cross-Site Scripting XSS__: Xảy ra khi hacker chèn mã độc (thường viết bằng ngôn ngữ JavaScript) thông qua các đoạn script để thực thi ở phía client. Thông thường, một đoạn mã độc được ngụy trang dưới dạng dữ liệu xuất nhập thông thường sẽ được gửi lên server. Nếu không có các bộ lọc dữ liệu độc hại, mã độc sẽ được chèn vào mã nguồn của ứng dụng web (ta thường gọi trang web đó đã bị XSS) và bất cứ lúc nào người dùng bình thường truy cập website, các mã độc đó sẽ thực thi ngay trên trình duyệt của người dùng.

- __Broken Authentication__: Ứng dụng web có thể cài đặt phần đăng nhập không chính xác, khiến cho hacker có thể chạy các trình brute-force nhằm tìm được chính xác tài khoản và mật khẩu của người dùng, dẫn tới việc chiếm tạm thời hoặc hoàn toàn tài khoản đó.

- __Sensitive Data Exposure__: Rất nhiều trang web và các API thường không bảo vệ các dữ liệu nhạy cảm của người dùng như thông tin tài chính, sức khỏe,... một cách hợp lý. Ví dụ, mật khẩu, tài khoản được mã hóa sơ sài trong cookies. Điều này dẫn tới các dữ liệu ấy có thể bị lấy được trong quá trình truyền dữ liệu từ client tới server.

- __Broken Access Control__: Lỗi này xảy ra khi có lỗ hổng trong việc hạn chế người dùng bình thường truy cập vào các vùng bị hạn chế. Kẻ tấn công có thể tìm thấy các lỗi này và truy cập vào các vùng bị cấm, chỉnh sửa thông tin người dùng, thay đổi quyền của admin, đánh cắp thông tin của toàn bộ hệ thống....

- [__XML External Entities (XXE)__](https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE)): Nói đơn giản, lỗ hổng này nhằm tới file XML (một loại ngôn ngữ đánh dấu) trên các ứng dụng web. Các file XML quá cũ hoặc được cài đặt kém sẽ là đối tượng tấn công, vì đã để lộ các thông tin như port, shared file, ... Hacker sẽ khai thác các thông tin này để scan port, thực thi code từ xa, hoặc thậm chí là DoS và DDoS.

- [__Security Misconfiguration__](https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration): Đây là lỗ hổng thường gặp nhất và là hậu quả của việc sử dụng các cài đặt mặc định, vốn không an toàn trước những cuộc tấn công. Lỗi có thể xảy ra ở các kho lưu trữ đám mây mở, việc đặt HTTP header sai, hoặc các thông báo lỗi rườm rà sẽ chứa các thông tin nhạy cảm. Vì vậy, các hệ thống không chỉ cần được cài đặt một cách an toàn, chúng còn cần được cập nhật liên tục.

- [__Insecure Deserialization__](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization): Lỗ hổng này có thể dẫn tới việc thực thi các mã ở máy khách hàng. Dù việc này không dẫn tới việc thực thi mã độc từ xa, nó cũng có thể được dùng để tạo ra các cuộc tấn công, bao gồm tấn công lặp lại, tấn công kiểu injection, và tấn công leo thang đặc quyền.

- [__Using Components with Known Vulnerabilities__](https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities): Xây dựng 1 website cần rất nhiều thành phần, bao gồm thư viện, framework, các module phần mềm, và chúng sẽ chạy với quyền tương tự như quyền của ứng dụng web đấy. Nếu một trong các thành phần đang chạy bị hack, hacker có thể lợi dụng quyền của nó để xâm nhập vào hệ thống.

- [__Insufficient Logging & Monitoring__](https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging%2526Monitoring): Như tên gọi của lỗi này, ghi nhật ký và giám sát không đầy đủ, việc khai thác có thể gây nên các sự cố rất lớn. Kẻ tấn công dựa vào việc thiếu giám sát và phản ứng kịp thời để đạt được mục tiêu của chúng mà không bị phát hiện.

Nói chung, các lỗ hổng này thường được chia thành 3 mức độ nguy hiểm. Mức đầu tiên là các lỗ hổng gây ảnh hưởng tới 3 thuộc tính của dịch vụ là: Tính bảo mật, tính toàn vẹn và tính sẵn sàng. Nguy hiểm hơn là các lỗ hổng có thể gây nên việc thực thi mã từ xa. Và nguy hiểm nhất, chính là lỗ hổng gây nên các cuộc tấn công leo thang đặc quyền. Khi hacker thành công trong việc leo thang đặc quyền, hacker sẽ trở thành bố của hệ thống, có thể tùy ý tung hoành ngang dọc trong hệ thống mà không bị ai chặn lại, thậm chí có thể xóa luôn cả hệ thống ấy. Vì vậy, bên cạnh việc xây dựng giao diện thật đẹp, cũng như các tính năng hữu ích, việc bảo vệ hệ thống và tìm kiếm, nghiên cứu các lỗ hổng ứng dụng web mới luôn được đặt lên hàng đầu để tránh các hậu quả nặng nề.

Hãy theo dõi [page](https://www.facebook.com/ehc.fptu) của EHC để nhận thêm các thông tin, các tip hữu ích về an toàn thông tin trên mạng các bạn nhé !!!