# Decoding TLS v1.2 Protocol Handshake With Wireshark

> There are two main goals of this article are: (1) Explaining the TLS v1.2 handshake protocol step by step. (2)Capture and examine a TLS stream in Wireshark.
## 使用 Wireshark 解碼 TLS v1.2 協議握手
我們不僅要解釋 TLS v1.2 握手協議的工作原理，還將使用 Wireshark 解碼 TLS v1.2 協議握手。本文的主要目標有兩個： (1) 逐步解釋 TLS v1.2 握手協議。(2) 在 Wireshark 中捕獲並檢查 TLS 流。

僅出於演示目的，我們將通過安全的 HTTPS 連接在 Chrome 瀏覽器上訪問 Pluralsight（公共學習平台）網站。因為 TLS 握手僅適用於 HTTPS 通信。HTTP 和 HTTPS 的區別在於，在 HTTP 中只會發生 TCP 握手，而在 HTTPS TCP 和 TLS 的情況下，兩次握手都會發生。

**TCP 三向握手協議：**
---------------

在 HTTP 中，TLS 握手會在[TCP 握手](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/three-way-handshake-via-tcpip)成功完成後發生。TCP 握手過程是一個單獨的主題，因此我們不在本文中介紹。簡而言之，TCP 握手是一個三步過程。首先，客戶端向服務器發送 SYN 數據包。其次，服務器發送 SYN + ACK 響應客戶端。最後，客戶端向服務器發送確認。

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/TCP-three-way-handshake-1024x256.png?ezimgfmt=rs:825x206/rscb1/ng:webp/ngcb1)

192.168.0.114 是客戶端機器。199.38.167.35 是目的地複數。

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/TCP-three-way-handshake-in-wireshark-1024x45.png?ezimgfmt=rs:825x36/rscb1/ng:webp/ngcb1)

**TLS v1.2**協議**握手：**
---------------------

一旦 TCP 三向握手完成。TLS 握手將以客戶端問候開始。

### 第 1 步：客戶您好

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/TLSv1.2-client-hello-message-1024x256.png?ezimgfmt=rs:825x206/rscb1/ng:webp/ngcb1)

客戶端向服務器發送客戶端問候消息。在客戶端 hello 消息中，客戶端將其支持的 TLS 版本、UTC 時間、28 字節隨機數、會話 ID、服務器的 URL 和支持的密碼套件發送到服務器。

Wireshark 演示：

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/TLSv1.2-client-hello-paclet-in-wireshark-1024x495.png?ezimgfmt=rs:825x399/rscb1/ng:webp/ngcb1)

如果您查看 Wireshark，您將在三向握手後立即看到一個客戶端 hello 數據包。您還可以在數據包中看到 TLS 版本、28 字節隨機數、所有支持的密碼套件和會話 ID。

### 第 2 步：服務器你好

服務器收到客戶端問候後，將檢查客戶端發送的支持的 TLS 版本和密碼套件。並且，服務器將選擇客戶端和服務器都支持的最高 TLS 版本。服務器還將會話 ID、UTC 時間、28 字節隨機數和選定的密碼套件包含在服務器 hello 消息中，並將其發送給客戶端。

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/TLSv1.2-server-hello-message-1024x256.png?ezimgfmt=rs:825x206/rscb1/ng:webp/ngcb1)

Wireshark 演示：

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/TLSv1.2-server-hello-paclet-in-wireshark-1024x495.png?ezimgfmt=rs:825x399/rscb1/ng:webp/ngcb1)

您將在 client hello 之後看到的下一個數據包是 server hello。

### 第 3 步：證書、服務器加密密鑰和服務器問候完成

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/Certificate-Server-Encryption-Key-and-Server-Hello-Done-message-1024x256.png?ezimgfmt=rs:825x206/rscb1/ng:webp/ngcb1)

發送服務器hello消息後。服務器將向客戶端發送包含[密鑰交換過程中](https://thesecmaster.com/a-mathematical-explanation-of-the-diffie-hellman-key-exchange-protocol/)使用的 p 和 g 值[、](https://thesecmaster.com/a-mathematical-explanation-of-the-diffie-hellman-key-exchange-protocol/)服務器加密密鑰和服務器問候完成消息的證書。

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/Certificate-Server-Encryption-Key-and-Server-Hello-Done-woreshark-packet-1024x495.png?ezimgfmt=rs:825x399/rscb1/ng:webp/ngcb1)

### 第 4 步：客戶端加密密鑰、更改密碼規範並完成

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/Client-Encrypted-Key-Change-Cipher-Spec-and-Finished-1024x256.png?ezimgfmt=rs:825x206/rscb1/ng:webp/ngcb1)

客戶端收到服務器加密後的密鑰。它將使用客戶端加密密鑰進行響應。它還發送更改密碼規範。這意味著它有足夠的信息來開始加密通信，並且從現在開始將加密發送數據。到目前為止，通信是平面文本。此通信將在加密後發生。服務器收到更改密碼規範消息後，它期望來自客戶端的加密數據。

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/Client-Encrypted-Key-Change-Cipher-Spec-and-Finished-wireshark-packet-1-1024x495.png?ezimgfmt=rs:825x399/rscb1/ng:webp/ngcb1)

第 5 步：更改密碼規範並完成
---------------

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/Change-Cipher-Spec-and-Finished-message-1024x256.png?ezimgfmt=rs:825x206/rscb1/ng:webp/ngcb1)

這將是服務器要發送的最後一條消息，其中包括更改密碼規範和完成消息。這表明所有功能消息都將被加密。

![](https://www.thesecmaster.com/ezoimgfmt/thesecmaster.com/wp-content/uploads/2021/03/Change-Cipher-Spec-and-Finished-wireshark-packet-1024x495.png?ezimgfmt=rs:825x399/rscb1/ng:webp/ngcb1)

這樣就完成了TLS v1.2協議握手過程。



[Source](https://www.thesecmaster.com/decoding-tls-v1-2-protocol-handshake-with-wireshark/)