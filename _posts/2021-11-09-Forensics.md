---
title: Forensics
author:
    name: AnhND
date: 2021-11-09 20:07:00 +0700
categories: [Wiki, Forensics]
tags: [wiki, forensics]
mermaid: true
---

## Digital Forensics là gì ?

Digital Forensics (hay còn gọi là điều tra số) là công việc phát hiện, bảo vệ và phân tích thông tin được lưu trữ, truyền tải hoặc được tạo ra bởi một máy tính hoặc mạng máy tính, nhằm đưa ra các suy luận hợp lý để tìm nguyên nhân, giải thích các hiện tượng trong quá trình điều tra. Khái niệm này được ra đời vào những năm 1980 do sự phát triển của máy tính cá nhân, khi xảy ra trộm cắp thiết bị phần cứng, mất mát dữ liệu, vi phạm bản quyền, virus máy tính phá hoại… Các doanh nghiệp và chính phủ các nước khi đó cũng ý thức hơn về vấn đề bảo mật.

## Mục tiêu

Mục tiêu cốt lõi của Digital Forensic là phát hiện, bảo quản, khai thác, tài liệu hóa và đưa ra kết luận về dữ liệu thu thập được. Cần lưu ý rằng dữ liệu phải đảm bảo tính xác thực, và được lấy mà không bị hư hại, nếu không dữ liệu đấy sẽ không còn ý nghĩa.Tại sao chúng ta cần Forensics ?Vấn đề được đặt ra giả sử bạn sở hữu một website hay thiết bị nào đấy, rồi đột nhiên bạn phát hiện ra thiết bị hay website của mình bị hacker tấn công và gây ra một lượng thiệt hại không nhỏ đối với bạn. Lúc này, bạn muốn xác định nguyên nhân bị tấn công, tìm cách khắc phục để sự việc không tái diễn hay thậm chí là xác định thủ phạm. Đó là lúc bạn cần đến Forensics. Đấy chỉ là một ví dụ khá điển hình, ngoài ra còn những trường hợp khác như để phát hiện mã độc trên máy tính, kiểm tra sự bất thường trong mạng, phát hiện sự xâm nhập… Nói chung Forensics giúp chúng ta xác định được nguyên nhân sự cố và đưa ra các biện pháp giải quyết tiếp theo. Nguyên tắc trao đổi của LocardEdmond Locard (1877 – 1966) được mệnh danh là Sherlock Holmes của nước Pháp. Ông là một chuyên gia điều tra pháp y, sáng lập Viện Hình sự học của trường Đại học Tổng hợp Lyon. Locard phát biểu một nguyên tắc mà sau này trở thành kim chỉ nam ngành khoa học điều tra. Ông ta cho rằng bất cứ khi nào hai người tiếp xúc với nhau, một thứ gì đó từ một người sẽ được trao đổi với người khác và ngược lại. Có thể là bụi, tế bào da, bùn đất, sợi, mạt kim loại. Những việc trao đổi này có xảy ra – vì thế chúng ta có thể bắt được nghi phạm. Với Computer Forensics, nguyên tắc này cũng hoàn toàn đúng. Khi bạn làm việc với máy tính hay một hệ thống thông tin, tất cả hành động của bạn đều bị ghi vết lại (mặc dù việc tìm ra thủ phạm trong trường hợp này khó khăn và mất nhiều thời gian hơn rất nhiều)

## Đặc điểm của Digital Forensics

- Dữ liệu cần phân tích lớn, nếu dữ liệu chỉ là text thôi thì với dung lượng vài mb chúng ta cũng có 1 lượng thông tin rất lớn rồi. Trong thực tế thì còn khổng lồ hơn.

- Dữ liệu thường không còn nguyên vẹn, bị thay đổi, phân mảnh, và có thể bị lỗi

- Bảo quản dữ liệu khó khăn, dữ liệu thu được có thể có tính toàn vẹn cao, chỉ một thay đổi nhỏ cũng có thể làm ảnh hưởng đến tất cả.

- Dữ liệu forensic có thể gồm nhiều loại khác nhau: file hệ thống, ứng dụng, …

- Vấn đề cần forensics là khá trừu tượng: mã máy, dump file, network packet…

- Dữ liệu dễ dàng bị giả mạo

- Xác định tội phạm khó khăn, có thể bạn tìm ra được dữ liệu về hacker(IP, email, profile…) nhưng để xác định được được đối tượng thật ngoài đời thì cũng không hề đơn giản.

## Forensics những gì ?

Digital Forensic thường làm việc với những đối tượng sau:

- __Physical Media, Media Management:__ Liên quan đến phần cứng, tổ chức phân vùng, phục hồi dữ liệu khi bị xóa…

- __File System:__ Phân tích các file hệ thống, hệ điều hành windows, linux, android…

- __Application:__ Phân tích dữ liệu từ ứng dụng như các file Log, file cấu hình, reverse ứng dụng…

- __Network:__ Phân tích gói tin mạng, sự bất thường trong mạng

- __Memory:__ Phân tích dữ liệu trên bộ nhớ, thường là dữ liệu lưu trên RAM được dump ra

## Ai làm forensic?

Những người làm công việc Forensics thường phải có kinh nghiệm và kiến thức khá rộng về khoa học máy tính, mạng, bảo mật. Trong những trường hợp cần kiến thức chuyên sâu, sẽ có nhiều người cùng tham gia để giải quyết. Ở các doanh nghiệp lớn, những người làm An toàn vận hành(Security Operator) sẽ đảm nhận công việc này. Với những người làm bảo mật thì đây cũng là một công việc rất thú vị.