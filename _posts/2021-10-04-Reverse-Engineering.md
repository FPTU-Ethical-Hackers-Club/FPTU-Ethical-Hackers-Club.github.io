---
title: Reverse Engineering
author:
    name: HungLT
date: 2021-10-04 20:07:00 +0700
categories: [Wiki, Reverse Engineering]
tags: [wiki, re]
mermaid: true
---

![RE](https://user-images.githubusercontent.com/82533607/145609327-4c5cf018-27d1-4753-90eb-ff35b44c5bab.jpg)

## Reverse engineering là gì? 

Dịch ngược (reverse engineering) trong An toàn thông tin là quá trình hiểu cách thức hoạt động của chương trình (hoặc phần cứng, nhưng trong bài viết này tạm thời chưa đề cập) với đầu vào (input) là đoạn nhị phân được biên dịch từ mã nguồn (source code.)

Chương trình được viết từ ngôn ngữ cấp cao, ví dụ như C, sau đó được biên dịch (compile) thành ngôn ngữ máy chỉ bao gồm 0 và 1 để có thể chạy (execute.) Khi ai khác chạy chương trình trong tình trạng không có source code, reversing đóng vai trò dịch ngược từ ngôn ngữ máy đang được thực thi về dạng hợp ngữ (assembly)—ngôn ngữ thân thiện và dễ hiểu hơn đối với con người.

## Reverse engineering làm được gì?

Cốt lõi của reversing là hiểu chương trình chạy như thế nào trong bối cảnh không có source code. Ứng dụng của reverse engineering là vô hạn, nhưng hiện tại đang phổ biến hai nhánh chính là:

- __Phân tích mã độc:__ Mã độc được cài cắm ở khắp mọi nơi. Có thể nó ở trong đường link hay file đính kèm của một email vô danh được gửi vào hòm thư của bạn. Có thể nó ở một trang web mà chỉ cần mở nó lên là mã độc được tự động tải về máy của bạn. Có thể nó ở trong một phần mềm mà nhìn tưởng là vô hại nhưng thực ra lại đang chạy mã độc. Bằng việc phân tích mã độc, chúng ta có thể xây dựng giải pháp để xác định mã độc (malware detection.) Dựa vào chữ ký file (file signature) của những malware đã từng bị phát hiện, các phần mềm chống mã độc (antimalware software) đọc file signature và cảnh báo hoặc xóa bỏ các file khả nghi. Một số file signature khả nghi có thể kể đến các file có đuôi (extension) .jar, .dll, .bat, .cmd, .ps1, .reg hoặc .exe. Điển hình và phổ biến nhất trong nhánh này là Windows Defender. Disclaimer. Thay đổi file extension không làm ảnh hưởng tới file signature và điều này sẽ được giải thích kỹ hơn trong bài viết về Forensics. Nhưng cảnh cáo trước là không phải file .pdf nào cũng thật sự là .pdf đâu, cẩn thận nó biết “chạy” đấy.

- __Kiểm định mã nguồn:__ Sự phát triển của kỹ thuật phần mềm (software engineering) yêu cầu reverse engineering cũng phải tiến bộ theo. Thời kỳ phần mềm chỉ cần chạy đúng chức năng là đủ đã qua từ lâu, nhà phát triển (developer) phải đảm bảo phần mềm không bị crack bởi các crackers. Ngoài ra, người dùng ngày nay quan tâm tới việc giữ kín thông tin cá nhân nên việc hạn chế các lỗi bảo mật tỏ ra cần thiết hơn bao giờ hết. Quá trình kiểm định mã nguồn của reverse engineering có đặc điểm là không được tiếp xúc với source code. Góc nhìn từ reverse engineering giống với góc nhìn của một cracker ở chỗ này, vì thế chúng ta có thể xây dựng các phương pháp để ngăn chặn reverse (anti-reversing) như làm rối hóa (obfuscating), ảo hóa mã nguồn (virtualizing source code), gói mã nguồn (packing source code),… Hãy nghĩ tới việc những phần mềm phổ biến mà hầu như ai cũng sử dụng như hệ điều hành Windows, Zoom—nơi tổ chức các lớp học và cuộc họp online hoặc ứng dụng PC-Covid có lỗi bảo mật nghiêm trọng. Động lực cho reverse engineering phát triển có lẽ được bắt nguồn từ đây. Hoặc nếu như trường của bạn có phần mềm thi E** hoặc P**. (jk)

![pasted image 0](https://user-images.githubusercontent.com/82533607/145609607-a9e0bcab-8a63-49e9-803a-f0939b4a205b.png)

## Reverse engineering cần gì?

Reverse engineering là một ngành khó. Làm việc trên assembly và các thanh ghi bộ nhớ đòi hỏi sự am hiểu về assembly, tổ chức và kiến trúc máy tính. Các phần mềm lại còn phụ thuộc vào nền tảng (platform-based), ví dụ như chỉ hoạt động trên Windows 32-bit, hoặc chỉ hoạt động trên Windows 64-bit, hoặc chỉ hoạt động trên macOS, iOS,… khiến lượng kiến thức cần phải biết tăng lên đáng kể. Ngoài ra cần thành thục tool để dịch ngược từ ngôn ngữ máy về assembly, hay còn gọi là disassemblers, như IDA; tool để debug chương trình, hay còn gọi là debuggers, như Ollydbg; tool để xem và chỉnh sửa giá trị của các bytes như Hex editor.

Reverse engineering, túb iát? Đọc lý thuyết nhiều người ta gọi là mọt sách. Còn cày 4470 điểm trên [reversing.kr](http://reversing.kr/) rồi quét sạch [crackmes.one](https://crackmes.one/) thì người ta gọi là reverse engineer. Chắc vậy.