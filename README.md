<p style="font-size: 20px; font-weight: bold;">Nội dung quan trọng</p>
📋 Tổng quan
Script này thực hiện quét toàn diện hệ thống Windows để:

  - Phát hiện phần mềm crack/activator trái phép

  - Đánh giá tuân thủ chính sách phần mềm

  - Tích hợp với Kaspersky OpenTIP để phân tích mối đe dọa

  - Xuất kết quả chuẩn JSON cho SIEM (Wazuh)

🚀 Tính năng chính
1. 🔍 Kiểm tra Tuân thủ (Compliance Inventory)
  - Quét ứng dụng đã cài đặt từ registry( Cách làm này giống với inventory thực hiện)

  - Phát hiện ứng dụng từ nhà phát hành không được phép

  - Phát hiện ứng dụng không có thông tin publisher

  - Tính điểm Compliance Score dựa trên mức độ vi phạm

2. ⚠️ Phát hiện Công cụ Crack (Crack Indicators)
  - Kiểm tra Licensing Windows/Office: Phát hiện KMS server không được phép

  - Quét Scheduled Tasks: Tìm task nghi ngờ chứa từ khóa crack

  - Quét Services: Tìm service liên quan đến crack

  - Quét Files: Tìm file nghi ngờ trong thư mục "hot" (Downloads, Desktop, TEMP)

  - Tính điểm Crack Score dựa trên mức độ nghi ngờ

3. 🔗 Enrichment với Kaspersky OpenTIP
  - Hash các file nghi ngờ khi crack score cao

  - Gửi hash lên Kaspersky OpenTIP API để kiểm tra độ tin cậy

  - Nhận kết quả phân tích (clean/malicious/unknown)

4. 📊 Đầu ra Logging
  - Windows Event Log: Ghi kết quả đầy đủ dưới dạng JSON

  - File Log Backup: Ghi thêm vào file JSON tại C:\ProgramData\

  - Định dạng JSON chuẩn để Wazuh có thể parse và xử lý
