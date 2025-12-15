<p style="font-size: 40px; font-weight: bold;">Nội dung quan trọng</p>
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

  - Gửi hash lên Kaspersky OpenTIP API để kiểm tra độ tin cậy : Lý do chọn Kaspersky: không giới hạn api, tài khoản miễn phí, mạnh về phát hiện crack.

  - Nhận kết quả phân tích (clean/malicious/unknown)

4. 📊 Đầu ra Logging
  - Windows Event Log: Ghi kết quả đầy đủ dưới dạng JSON
<img width="1903" height="1011" alt="image" src="https://github.com/user-attachments/assets/567bc9e1-e6a8-4360-815d-8e1d570c3b9f" />

  - File Log Backup: Ghi thêm vào file JSON tại C:\ProgramData\


{"timestamp":"2025-12-15T22:13:39.1774857+07:00","scores":{"crack":{"reasons":["Non-approved KMS host: kms.digiboy.ir"],"value":10,"severity":"high"},"compliance":{"reasons":["Unauthorized publisher apps detected","Apps with missing publisher info"],"value":6,"severity":"high"}},"user":"LAPTOP-U3OFSFV8\\Admin","type":"crack_audit_v3","host":"LAPTOP-U3OFSFV8","indicators":{"licensing":{"Service":{"KeyManagementServiceMachine":"kms.digiboy.ir","KeyManagementServicePort":1688,"DiscoveredKeyManagementServiceMachineName":"","DiscoveredKeyManagementServiceMachinePort":0,"ClientMachineID":"b7e96c79-d762-4644-8a58-1312eef8414a"},"Products":[{"Name":"Office 16, Office16MondoVL_KMS_Client edition","LicenseStatus":1,"Description":"Office 16, VOLUME_KMSCLIENT channel","PartialProductKey":"XQBR2"},{"Name":"Office 16, Office16O365HomePremR_Grace edition","LicenseStatus":5,"Description":"Office 16, RETAIL(Grace) channel","PartialProductKey":"KHGM9"},{"Name":"Windows(R), CoreSingleLanguage edition","LicenseStatus":1,"Description":"Windows(R) Operating System, OEM_DM channel","PartialProductKey":"PR4BP"}]},"suspicious_services":null,"unauthorized_apps":[{"DisplayName":"Java Auto Updater","Publisher":"Oracle Corporation","DisplayVersion":"2.8.321.7","InstallLocation":""},{"DisplayName":"K-Lite Codec Pack 15.5.0 Full","Publisher":"KLCP","DisplayVersion":"15.5.0","InstallLocation":"C:\\Program Files (x86)\\K-Lite Codec Pack\\"},{"DisplayName":"Lightshot-5.5.0.7","Publisher":"Skillbrains","DisplayVersion":"5.5.0.7","InstallLocation":"C:\\Program Files (x86)\\Skillbrains\\lightshot\\"},{"DisplayName":"MySQL Installer","Publisher":"Oracle Corporation","DisplayVersion":"1.6.11.0","InstallLocation":""},{"DisplayName":"MySQL Installer","Publisher":"Oracle Corporation","DisplayVersion":"1.6.12.0","InstallLocation":""},{"DisplayName":"Npcap","Publisher":"Nmap Project","DisplayVersion":"1.83","InstallLocation":"C:\\Program Files\\Npcap"},{"DisplayName":"Overwolf","Publisher":"Overwolf Ltd.","DisplayVersion":"0.291.0.2","InstallLocation":"E:\\overwolf\\"},{"DisplayName":"Pro Evolution Soccer 6","Publisher":"KONAMI","DisplayVersion":"1.00.0000","InstallLocation":"D:\\pes-6"},{"DisplayName":"Python Launcher","Publisher":"Python Software Foundation","DisplayVersion":"3.13.9150.0","InstallLocation":""},{"DisplayName":"Safe Exam Browser","Publisher":"ETH Zürich","DisplayVersion":"3.7.0.682","InstallLocation":null}],"unknown_publisher_apps":{"DisplayName":"Anki","Publisher":null,"DisplayVersion":null,"InstallLocation":null},"suspicious_files":{"Name":"wazuh-crack-audit.log","Path":"C:\\ProgramData\\wazuh-crack-audit.log","Size":2392,"LastModified":"2025-12-14T16:44:31.1430161Z"},"suspicious_tasks":null},"enrichment":{},"metadata":{"total_apps_scanned":47,"scan_duration":"0","script_version":"3.0"}}

  - Định dạng JSON chuẩn để Wazuh có thể parse và xử lý

Bên phía wazuh-server:
Kiểm tra với logtest:
<img width="1849" height="758" alt="image" src="https://github.com/user-attachments/assets/c71281a1-a124-4ec1-b4fe-59fe8b1a685f" />

<img width="1837" height="758" alt="image" src="https://github.com/user-attachments/assets/621dc028-3847-48ad-acb1-74b2a5b63e80" />


Ảnh về alert hiển thị trên wazuh:
<img width="1845" height="856" alt="image" src="https://github.com/user-attachments/assets/9751be6d-5db5-4fc9-8b63-52acbc42cd46" />


Chi tiết về alert:
<img width="1689" height="437" alt="image" src="https://github.com/user-attachments/assets/08358369-689a-4d0c-afac-2dc1178d2335" />

  - Máy chủ KMS ngoài luồng (kms.digiboy.ir:1688) : Máy tính đang kết nối đến một máy chủ KMS công cộng, không được kiểm soát trên Internet để kích hoạt Windows/Office. Đây chính là phần mềm crack.

  - Trạng thái kích hoạt đáng ngờ : LicenseStatus: 1 (Licensed) trên phiên bản Volume (KMS) của Office, nhưng lại đi cùng LicenseStatus: 5 (Non-Genuine) trên bản Retail. Điều này cho thấy hệ thống đã bị can thiệp, có thể đã cài đè crack lên bản quyền hợp pháp.

  - Phần mềm không được phê duyệt: Danh sách unauthorized_apps bao gồm các công cụ có thể dùng để bẻ khóa (Npcap), phần mềm giải trí cá nhân (Game PES 6), hoặc phiên bản cũ không an toàn (MySQL Installer bản 1.6).
