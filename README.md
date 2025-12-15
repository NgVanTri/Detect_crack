Tổng quan chức năng:
1. Kiểm tra Tuân thủ (Compliance Inventory)
   •	Quét các ứng dụng đã cài đặt từ registry
   •	Phát hiện ứng dụng từ nhà phát hành không được phép
   •	Phát hiện ứng dụng không có thông tin publisher
   •	Tính điểm Compliance Score dựa trên số lượng vi phạm

2. Phát hiện Công cụ Crack (Crack Indicators)
   •	Kiểm tra Licensing Windows/Office: Phát hiện KMS server không được phép
   •	Quét Scheduled Tasks: Tìm task nghi ngờ chứa từ khóa crack (kms, activator...)
   •	Quét Services: Tìm service nghi ngờ liên quan đến crack
   •	Quét Files: Tìm file nghi ngờ trong thư mục "hot" (Downloads, Desktop, TEMP)
   •	Tính điểm Crack Score dựa trên mức độ nghi ngờ

3. Enrichment với Kaspersky OpenTIP
   •	Nếu crack score cao, script sẽ hash các file nghi ngờ
   •	Gửi hash lên Kaspersky OpenTIP API để kiểm tra độ tin cậy
   •	Nhận kết quả phân tích (clean/malicious)

4. Đầu ra Logging
   •	Windows Event Log: Ghi kết quả đầy đủ dưới dạng JSON vào Event Log
   •	File Log Backup: Ghi thêm vào file JSON tại C:\ProgramData\
   •	Định dạng JSON chuẩn để Wazuh có thể parse và xử lý

Cấu trúc chi tiết:
 - Cấu hình chính:
   •	Allow Lists: Danh sách nhà phát hành được phép (Microsoft, Google...)
   •	Crack Keywords: Từ khóa phát hiện (kms, activator, patch...)
   •	Hot Folders: Thư mục thường chứa file crack
   •	Weights: Trọng số tính điểm cho từng loại vi phạm
   •	Scoring Thresholds: Ngưỡng phân loại Low/Medium/High
   
Các bước thực thi:
1.	Khởi tạo Event Log source
2.	Quét ứng dụng đã cài đặt → Tính compliance score
3.	Quét các chỉ số crack (KMS, tasks, services, files) → Tính crack score
4.	Nếu điểm cao, thực hiện enrichment với Kaspersky
5.	Ghi kết quả vào Event Log và file backup
6.	Xuất summary ra console

