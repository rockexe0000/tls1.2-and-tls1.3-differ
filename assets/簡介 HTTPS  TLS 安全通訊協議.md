# 簡介 HTTPS / TLS 安全通訊協議

> HTTPS 也稱 HTTP over TLS、HTTP over SSL、HTTP Secure，是透過計算機網路安全 通訊協議 (Protocol)。
在 摘要密碼學與資訊安全 整理了部分的關於 TLS 協議的資料，本文重新整理我自己對於 HTTPS 這個通訊協議的理解。


How SSL Wo

* * *

HTTPS 也稱 `HTTP over TLS`、`HTTP over SSL`、`HTTP Secure`，是透過計算機網路安全 `通訊協議 (Protocol)`。

在 [摘要密碼學與資訊安全](chrome-extension://cjedbglnccaioiolemnfhjncicchinao/2020/03/07/ComputerScience/Cryptography/) 整理了部分的關於 TLS 協議的資料，本文重新整理我自己對於 HTTPS 這個通訊協議的理解。

* * *

整體來看看 SSL/TLS 是怎麼運作的。

[![How SSL Works?](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/HowSSLWorks.png)](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/HowSSLWorks.png "How SSL Works?")

圖中包含了幾個角色：

*   Certificate Authoriy (CA): 數位憑證認證機構，是負責發放和管理 `數位憑證` 的權威機構。
*   Browser Vendor: 瀏覽器的供應者，像是 Google、Microsoft、Apple
*   Client App: 目標瀏覽的應用程式
*   Web Server: 網站服務器

整個流程如下：

1.  CA (Godaddy): 發一張 root certificate 給所有 browser 開發者
2.  Browser Vendor (Google, Mozilla): root certificate 會包在 App (ex 瀏覽器) 發布給使用者。
3.  CSR (certificate signing request): 瀏覽器對 CA 發出 CSR 請求
    *   目的是針對目前 WebSite 的 Domain 做認證
4.  CA 回傳簽可的憑證 (Signed Certificate)
    *   代表 WebSite Domain 的合法性
5.  Client App (browser) 對 Web Server 發出請求
6.  Web Server 回傳請求給 Client App
7.  Client App 驗證 WebSite 的 Domain Certificate

* * *

下圖是 SSL 整個通訊協議過程的流程圖：

[![SSL Communication Flow Diagram](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/SSL-Communication.jpg)](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/SSL-Communication.jpg "SSL Communication Flow Diagram")

*   `階段一 (Authentication)`：使用 Public / Asymmetric Key Encryption Algorithms.
    *   `Step 1`: Client 送出 Hello 訊息到 Server
    *   `Step 2`: Server 收到 Hello 後回覆 Hello 訊息
    *   `Step 3`: Client 驗證 Server 回傳的 SSL Certificate
    *   `Step 4`: (Optional) Client 傳送 SSL Certifiate 給 Server
    *   `Step 5`: (Optional) Server 驗證 Client 回傳的 SSL Certifiate
*   `階段二 (Key Exchange)`：使用 Public / Asymmetric Key Encryption Algorithms/Key Exchange protocol.
    *   `Step 6`: Client 送出 Key Exchange 的請求
    *   `Step 7`: 改變 Cipher Spec
    *   `Step 8`: Client 端完成請求
    *   `Step 9`: Server 端依照請求，改變 Cipher Spec
    *   `Step 10`: Server 端完成請求
*   `階段三 (Encrypted Data Transfer)`：使用 Private / Symmetric Key Encryption Algorithms
    *   `Step 11`: 使用對稱式加密傳輸資料。

前面階段一、二 稱 `SSL Handshake Protocol`，主要目的是認證 Server 是否合法，進而決定資料傳輸過程使用的對稱式金鑰；階段三則稱為 `SSL Record Protocol`，主要目的就是在安全的傳輸過程，使用 `對稱式加密演算法` 傳輸資料。

* * *

[](#階段一：Authentication-Handsharke "階段一：Authentication (Handsharke)")階段一：Authentication (Handsharke)
---------------------------------------------------------------------------------------------------

這個階段在 `公開傳輸` 的過程，使用 `非對稱加密演算法`。

*   `Step 1`: Client 送出 Hello 到 Server，包含以下訊息：
    1.  `SSL Version`: 版本號碼可以是 sslv3, tls1.0, tls1.1, tls1.2
    2.  [Cipher Suites](https://en.wikipedia.org/wiki/Cipher_suite) : 使用在 TLS 時的 演算法集合名稱，詳細後面描述
    3.  如果 `金鑰交換階段` 要使用 RSA ，那麼會再產生一個 Client Random Number.
*   `Step 2`: Server 準備回給 Client 的 Hello 訊息，其中包含了：
    1.  SSL Version
    2.  Cipher Suites
    3.  支援、且同意的資料壓縮方法
    4.  SSL Certificate: 這是整個步驟中最重要的資訊。
        *   如果之後 `金鑰交換階段` 使用 RSA ，則會再產生一個隨機數 (Server Random Number)，用在金要交換階段生成對稱金鑰用。
    5.  (optional) Client Certificate
    6.  Hello Done:
*   `Step 3`:
    1.  Client 收到 Server 回傳的 SSL Certificate，就會檢查是哪個 CA 簽發的憑證
    2.  然後從 Browser 的 Cert Store 取出對應的數位簽章，從中取得 Public Key，與 SSL Certificate 的 Public Key 比對。
    3.  如果有問題，表示發生 [中間人攻擊, Man-in-the-middle attack (MITM)](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
*   `Step 4`: (optional) Client 發送 Certificate 給 Server
*   `Step 5`: (optional) Server 驗證 Client 的 Ceritifcate

### [](#Cipher-Suites "Cipher Suites")Cipher Suites

在 `Step 1` Client 送出 Hello 訊息時，依照 SSL Version 的訊息，會包含一些此版本支援的 `協議與演算法組合`，這個組合稱為 `Cipher Suites`，這個組合會被用在整個 SSL Session 過程中。Cipher Suites 的名稱大概長得像下面這樣：

*   TLS\_ECDHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256
*   TLS\_ECDHE\_ECDSA\_WITH\_CHACHA20\_POLY1305\_SHA256
*   TLS\_ECDHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256
*   TLS\_RSA\_WITH\_AES\_128\_GCM\_SHA256

上述的 Cipher Suite 名稱在 RFC 有標準定義命名規則，上述的範例是 TLS 使用的標準規則，定義在 [RFC 2246, TLS v1.0](https://datatracker.ietf.org/doc/html/rfc2246) , [RFC 4346, TLS v1.1](https://datatracker.ietf.org/doc/html/rfc4346) , [RFC 5246, TLS v1.2](https://datatracker.ietf.org/doc/html/rfc5246) , and [RFC 8446, TLS v1.3](https://datatracker.ietf.org/doc/html/rfc8446) 。

命名格式如下：

> `L1`\_`L2`\_`L3`\_WITH\_`L4`\_`L5`\_`L6`

*   `L1`: 使用哪一個傳輸層通訊協議，有 TLS、SSL。
*   `L2`: 描述使用哪個 [Key Exchange](https://en.wikipedia.org/wiki/Key_exchange) 演算法，像是 RSA、DH (Diffie–Hellman)
    *   `ECDHE` 全名 `Elliptic Curve Diffie-Hellman Ephemeral`，中文 `橢圓曲線迪菲-赫爾曼密鑰交換`，是一種 `匿名密鑰協議 (Key-agreement protocol)`。
    *   這是 [Diffie–Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) 的變種，採用 `橢圓曲線密碼學` 來加強性能與安全性。
    *   `ECDH` 則是
*   `L3`: 交握過程的認證機制
    *   `RSA`
*   `L4`: session cipher，加密的 Size
    *   範例：`AES_128`
*   `L5`: 對稱式加密演算法法的操作模式
    *   `GCM` type of encryption (cipher-block dependency and additional options)
*   `SHA` (SHA2)hash function. For a digest of 256 and higher. Signature mechanism. indicates the message authentication algorithm which is used to authenticate a message.
*   `256` Digest size (bits).

> 附註：Cipher Suite 的命名規則，在 RFC 與部分實作有所差異，OpenSSL and [s2n, c99](https://github.com/aws/s2n-tls) 則使用另一種命名方式。相關對照表可以參考 [Supported protocols and ciphers between viewers and CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html#secure-connections-openssl-rfc-cipher-names) 的整理。

下圖是 AWS ELB / CLB 中的 SSL Cipher Suite 設定截圖：

[![](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/AWS-CLB-CipherSuite.png)](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/AWS-CLB-CipherSuite.png)

更多 ELB Security Policy 定義參閱: [Predefined SSL security policies for Classic Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html)

* * *

[](#階段二：Key-Exchange "階段二：Key Exchange")階段二：Key Exchange
--------------------------------------------------------

同階段一，也是在 `公開傳輸` 的過程，使用 `非對稱加密演算法`。這個階段的目的：

> 產生一個用來在 `階段三` 資料交換時，使用的 `對稱式加密演算法` 的 `對稱式金鑰 (Shared Secret)`

在一個公開透明的傳輸通道要產生金曜、然後傳輸，最常見的方法是 RSA 或者 `Deffie Hellman` 演算法。

*   `Step 6`: Client 送出 Key Exchange 的請求
*   `Step 7`: 改變 Cipher Spec
*   `Step 8`: Client 端完成請求
*   `Step 9`: Server 端依照請求，改變 Cipher Spec
*   `Step 10`: Server 端完成請求

### [](#RSA-Key-Exchange "RSA Key Exchange")RSA Key Exchange

*   `Pre-master secret`: 使用 RSA 取得金鑰，那麼在 `Step1` 就會產生 `Random Number`，然後使用 Server 憑證裡的公鑰加密，這個 Random Number 稱為 `Pre-master secret (PMS)`
*   `Client's Random Number`: Client 端產生的一組隨機碼
*   `Server's Random Number`: Server 端產生的一組隨機碼

透過這三個數字的隨機性，就可以產生 `資料傳輸階段` 時，`對稱式加密演算法` 所需要的 `加密金鑰 (Master Secret)`。

但是用 RSA 並不具備 PFS 特性，所以現在大多使用 DH 演算法。

### [](#Forward-Secrecy "Forward Secrecy")Forward Secrecy

中文翻譯成 `向前保密`，有時候也稱為 `完全向前保密 (Perfect Forward Secrecy, PFS)`，是密碼學中通訊協議的安全屬性。

TLS 基於 DHE (迪菲-赫爾曼金鑰交換) 演算法，就滿足 PFS 的特性，以下是滿足的演算法：

*   DHE-RSA
*   DHE-DSA
*   DHE-ECDSA

基於 ECDHE (橢圓曲線迪菲-赫爾曼金鑰交換) 的安全通訊，包含了：

*   ECDHE-RSA
*   ECDHE-ECDSA

> 更多參閱 Wikipedia 說明: [Forward Secrecy](https://en.wikipedia.org/wiki/Forward_secrecy)

### [](#Diffie-Hellman-Key-Exchange "Diffie-Hellman Key Exchange")Diffie-Hellman Key Exchange

大多時候簡稱 `DH 演算法`，是一種安全協議，主要目的：

> 雙方在沒有任何預先條件之下，透過公開的管道 (Public Channel, Unsafe) 建立一個金鑰，這個金鑰可以在後續的通訊過程作為加密金鑰來加密資料。

與 RSA 不一樣的是，DH 演算法具備了 `向前安全性 (Forward Secrecy)`，所以被廣泛運用在通訊傳輸的安全加密。

> DH 演算法詳細推演過程，參閱 [Wikipedia](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)

DH 演算法的弱點就是 `中間人攻擊`，因為整個演算法並沒有跟 `身份驗證` 有關的資訊，所以理想的做法就是要有個機制可以做身份識別，這也就是為什麼用自簽憑證的 HTTPS 瀏覽器會看出現警告訊息的原因。

* * *

[](#階段三：Encrypted-Data-Transfer-Record-Protocol "階段三：Encrypted Data Transfer / Record Protocol")階段三：Encrypted Data Transfer / Record Protocol
---------------------------------------------------------------------------------------------------------------------------------------------

進入資料傳輸階段，這個階段也稱為 `Record protocol`，使用 `對稱加密演算法` 加密瀏覽器與伺服器之間傳輸的資料。這個過程必須滿足以下特性：

1.  `保密性 (Confidentiality)`: 透過對稱式加密達到保密性，使用之前提到的 `Master Secret` 做資料加密。
2.  `完整性 (Integrity)`: 透過 [MAC (Message Authentication Code)](https://zh.wikipedia.org/zh-tw/%E8%A8%8A%E6%81%AF%E9%91%91%E5%88%A5%E7%A2%BC) 確認，MAC 則是透過 Hash 演算法計算得來。

下圖是 Record Protocol 的結構：

[![](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/Record-Protocol.jpeg)](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/Record-Protocol.jpeg)  
圖片來源：[SSL Record Protocol](https://www.youtube.com/watch?v=bSMRf0lAuzw)

結構與流程說明如下：

1.  Application Data: 應用程式資料會被拆分成若干份 Fragment
2.  Fragment: 每個傳輸資料會被拆分成幾個區塊後，個別傳送，這個區塊稱為 Fragment
    *   每個 Fragment 會經過壓縮演算法進行資料壓縮
3.  MAC: 用來確認每個 Fragment 的完整性驗證碼
    *   每個壓縮過後的資料，透過 Hash 計算出 MAC 值
    *   這個 MAC 值附加在壓縮資料之後
4.  Encrypt: 取得 Fragment 的 MAC 之後，使用 Secret Key 加密這兩個
5.  SSL Record Header: 最後附上 Record Header

* * *

為了瞭解 整個 HTTPS / TLS 通訊過程真實的狀況，我用 Wireshark 抓了一些封包，紀錄整個 Handshark 過程的資訊，與後面的整理比較。

下圖是透過 Browser Brave 連線 199.232.192.134 這個網站，使用 Wireshark 3.4.7-0-ge42cbf6a415 在 macOS 10.15.7 抓的封包：

[](#階段一：Client-Hello "階段一：Client Hello")階段一：Client Hello
--------------------------------------------------------

Client (Browser) to Server，在 `Client Hello` 部分有以下資訊:

*   Handshake Type: Client Hello (1)
*   Version: TLS 1.2 (0x0303)
*   Random: 7bcc7dce161a90f5fe5c83aaea001fb9cc3dcf532be85448534a4d0ef3d7578e
*   Session ID: 8bbaaaff25ea8066c42ebc05f9059b310c27dbb86b973439d88bda2405613682
*   Cipher Suites (16 suites)

[![](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/example/01_client-hello.png)](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/example/01_client-hello.png)

[](#階段一、二：Server-Hello-Change-Cipher-Spec-Encrypted-Handshake-Message "階段一、二：Server Hello, Change Cipher Spec, Encrypted Handshake Message")階段一、二：Server Hello, Change Cipher Spec, Encrypted Handshake Message
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Server to Client，在 `Server Hello` 部分可以看出以下資訊：

*   Handshake Type: Server Hello (2)
*   Version: TLS 1.2 (0x0303)
*   Cipher Suite: TLS\_ECDHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256 (0xc02f)
*   Random: b3b00f857658ec49606ca3bcd3aaae6768b1b045898731e3675e0dc866bd11fa
    *   Cipher Suite 使用 ECDHE\_RSA
*   Compression Method: null (0)

[![](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/example/02_s2c_server-hello_change-cipher-spec_encrypted-handshake-message.png)](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/example/02_s2c_server-hello_change-cipher-spec_encrypted-handshake-message.png)

Client (Browser) to Server:

[![](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/example/03_c2s_change-cipher-spec_encrypted-handshake-message.png)](https://rickhw.github.io/images/ComputerScience/HTTPS-TLS/example/03_c2s_change-cipher-spec_encrypted-handshake-message.png)

[](#Wireshark-的-Filers "Wireshark 的 Filers")Wireshark 的 Filers
--------------------------------------------------------------

一些使用 Wireshark 過程的記錄：

Filter:

*   `ip.addr == 142.251.43.19 && tls.record.version == 0x0303`
*   `ip.addr == 142.251.43.19 && ssl.record.version == 0x0303`

其中：

*   0x0300 SSL 3.0
*   0x0301 TLS 1.0
*   0x0302 TLS 1.1
*   0x0303 TLS 1.2
*   0x0304 TLS 1.3

參考：[Wireshark - Why TLS version is different in Record Layer and Handshake Protocol](https://www.analysisman.com/2021/06/wireshark-tls1.2.html)

[](#透過-openssl-了解-TLS-狀況 "透過 openssl 了解 TLS 狀況")透過 openssl 了解 TLS 狀況
--------------------------------------------------------------------

整個 TLS 的過程，大多都可以透過 openssl 做實驗，以下整理可以做的動作。

<table><tbody><tr><td><pre><span>1</span><br><span>2</span><br><span>3</span><br><span>4</span><br><span>5</span><br><span>6</span><br><span>7</span><br><span>8</span><br><span>9</span><br><span>10</span><br><span>11</span><br><span>12</span><br><span>13</span><br><span>14</span><br><span>15</span><br><span>16</span><br><span>17</span><br><span>18</span><br><span>19</span><br><span>20</span><br><span>21</span><br><span>22</span><br><span>23</span><br><span>24</span><br><span>25</span><br><span>26</span><br><span>27</span><br><span>28</span><br><span>29</span><br><span>30</span><br><span>31</span><br><span>32</span><br><span>33</span><br><span>34</span><br><span>35</span><br><span>36</span><br><span>37</span><br><span>38</span><br><span>39</span><br><span>40</span><br><span>41</span><br><span>42</span><br><span>43</span><br><span>44</span><br><span>45</span><br><span>46</span><br><span>47</span><br><span>48</span><br><span>49</span><br><span>50</span><br><span>51</span><br><span>52</span><br><span>53</span><br><span>54</span><br><span>55</span><br><span>56</span><br><span>57</span><br><span>58</span><br><span>59</span><br><span>60</span><br><span>61</span><br><span>62</span><br><span>63</span><br><span>64</span><br><span>65</span><br><span>66</span><br><span>67</span><br><span>68</span><br><span>69</span><br><span>70</span><br><span>71</span><br><span>72</span><br><span>73</span><br><span>74</span><br><span>75</span><br><span>76</span><br><span>77</span><br><span>78</span><br><span>79</span><br><span>80</span><br><span>81</span><br><span>82</span><br><span>83</span><br><span>84</span><br><span>85</span><br><span>86</span><br><span>87</span><br><span>88</span><br><span>89</span><br><span>90</span><br><span>91</span><br><span>92</span><br><span>93</span><br><span>94</span><br><span>95</span><br><span>96</span><br><span>97</span><br><span>98</span><br><span>99</span><br><span>100</span><br><span>101</span><br><span>102</span><br><span>103</span><br><span>104</span><br><span>105</span><br><span>106</span><br><span>107</span><br><span>108</span><br><span>109</span><br><span>110</span><br><span>111</span><br><span>112</span><br><span>113</span><br><span>114</span><br><span>115</span><br><span>116</span><br><span>117</span><br></pre></td><td><pre><span>~$ openssl version</span><br><span>LibreSSL 2.8.3</span><br><span></span><br><span></span><br><span>~$ openssl ciphers -v</span><br><span>ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(256) Mac=AEAD</span><br><span>ECDHE-ECDSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(256) Mac=AEAD</span><br><span>ECDHE-RSA-AES256-SHA384 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA384</span><br><span>ECDHE-ECDSA-AES256-SHA  SSLv3 Kx=ECDH     Au=ECDSA Enc=AES(256)  Mac=SHA1</span><br><span></span><br><span>... 略 ...</span><br><span></span><br><span>ECDHE-RSA-DES-CBC3-SHA  SSLv3 Kx=ECDH     Au=RSA  Enc=3DES(168) Mac=SHA1</span><br><span>ECDHE-ECDSA-DES-CBC3-SHA SSLv3 Kx=ECDH     Au=ECDSA Enc=3DES(168) Mac=SHA1</span><br><span>EDH-RSA-DES-CBC3-SHA    SSLv3 Kx=DH       Au=RSA  Enc=3DES(168) Mac=SHA1</span><br><span>DES-CBC3-SHA            SSLv3 Kx=RSA      Au=RSA  Enc=3DES(168) Mac=SHA1</span><br><span></span><br><span></span><br><span></span><br><span>❯ openssl s_client -connect <a href="http://rickhw.github.com/" rel="nofollow"><span>rickhw</span><span>.</span><span>github</span><span>.</span><span>com</span></a>:443</span><br><span></span><br><span>CONNECTED(00000006)</span><br><span>depth=2 C = US, O = DigiCert Inc, OU = <a href="http://www.digicert.com/" rel="nofollow"><span>www</span><span>.</span><span>digicert</span><span>.</span><span>com</span></a>, CN = DigiCert High Assurance EV Root CA</span><br><span>verify <span>return</span>:1</span><br><span>depth=1 C = US, O = DigiCert Inc, OU = <a href="http://www.digicert.com/" rel="nofollow"><span>www</span><span>.</span><span>digicert</span><span>.</span><span>com</span></a>, CN = DigiCert SHA2 High Assurance Server CA</span><br><span>verify <span>return</span>:1</span><br><span>depth=0 C = US, ST = California, L = San Francisco, O = <span>"GitHub, Inc."</span>, CN = <a href="http://www.github.com/" rel="nofollow"><span>www</span><span>.</span><span>github</span><span>.</span><span>com</span></a></span><br><span>verify <span>return</span>:1</span><br><span>---</span><br><span>Certificate chain</span><br><span> 0 s:/C=US/ST=California/L=San Francisco/O=GitHub, Inc./CN=www.github.com</span><br><span>   i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 High Assurance Server CA</span><br><span> 1 s:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 High Assurance Server CA</span><br><span>   i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA</span><br><span>---</span><br><span>Server certificate</span><br><span>-----BEGIN CERTIFICATE-----</span><br><span>MIIHMDCCBhigAwIBAgIQAkk+B/qeN1otu8YdlEMPzzANBgkqhkiG9w0BAQsFADBw</span><br><span>MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3</span><br><span>d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNz</span><br><span></span><br><span>... 略 ...</span><br><span></span><br><span>YaRIpRMRdj4stG6CkPJpfSauWa19kReZ6hTQR5f89L6x50us7GuWlmH6EmVFIbhf</span><br><span>9EO02QA3CcU7bE1iLWMHmKcU6ythmgsvNRU5TikxvF77JFv7n1/y8GLrprmKpB6Q</span><br><span>Df4PA8S9ROX9Rzgwe3KTIM6qeKU=</span><br><span>-----END CERTIFICATE-----</span><br><span>subject=/C=US/ST=California/L=San Francisco/O=GitHub, Inc./CN=www.github.com</span><br><span>issuer=/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 High Assurance Server CA</span><br><span>---</span><br><span>No client certificate CA names sent</span><br><span>Server Temp Key: ECDH, X25519, 253 bits</span><br><span>---</span><br><span>SSL handshake has <span>read</span> 3673 bytes and written 289 bytes</span><br><span>---</span><br><span>New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES128-GCM-SHA256</span><br><span>Server public key is 2048 bit</span><br><span>Secure Renegotiation IS supported</span><br><span>Compression: NONE</span><br><span>Expansion: NONE</span><br><span>No ALPN negotiated</span><br><span>SSL-Session:</span><br><span>    Protocol  : TLSv1.2</span><br><span>    Cipher    : ECDHE-RSA-AES128-GCM-SHA256</span><br><span>    Session-ID: 26C9C570ABA03D7D03BADA74248CEF20FDD5279B6A9EAA4D5128E072EF587E5F</span><br><span>    Session-ID-ctx:</span><br><span>    Master-Key: 49196F3EE337F88CDBF64E8EE41DF9BC283DAAD6C5E2A9C7544933A3847FC1904B15842413AE6A15FF2FDB328C9BD37B</span><br><span>    TLS session ticket lifetime hint: 7200 (seconds)</span><br><span>    TLS session ticket:</span><br><span>    0000 - d1 d1 01 52 63 e8 4d 9d-27 06 48 21 bc 74 06 8d   ...Rc.M.<span>'.H!.t..</span></span><br><span><span>    0010 - a6 63 66 6f d3 0e a9 94-31 a4 92 17 27 6a 56 cd   .cfo....1...'</span>jV.</span><br><span>    0020 - 99 5f cc da 8c 21 f1 75-fc 62 45 8a d9 95 ef d4   ._...!.u.bE.....</span><br><span>    0030 - 1d 05 fd 6d fb 8b 01 7e-29 5e 43 85 16 a2 59 73   ...m...~)^C...Ys</span><br><span>    0040 - 4a a7 6d f4 ee e9 1d 05-76 f9 3a ac 54 0d b7 13   J.m.....v.:.T...</span><br><span>    0050 - 00 73 f7 56 cb ff 96 c8-b6 05 1e 79 65 df 2f 51   .s.V.......ye./Q</span><br><span>    0060 - 55 c1 2d fb b8 9e 29 81-84 1f 74 24 67 b6 05 3b   U.-...)...t<span>$g</span>..;</span><br><span>    0070 - 0e ae 4d 9a b6 80 b4 21-be 37 4b 3a 6a 66 fb 51   ..M....!.7K:jf.Q</span><br><span>    0080 - bd 3c d4 5b 58 f2 8e 90-a4 8a c6 ac d8 db f1 25   .&lt;.[X..........%</span><br><span>    0090 - ba 6c 15 e8 af 7b c5 e8-82 98 13 db 9e 26 07 5a   .l...{.......&amp;.Z</span><br><span></span><br><span>    Start Time: 1629555199</span><br><span>    Timeout   : 7200 (sec)</span><br><span>    Verify <span>return</span> code: 0 (ok)</span><br><span></span><br><span></span><br><span>~$ openssl s_client -connect <a href="http://rickhw.github.com/" rel="nofollow"><span>rickhw</span><span>.</span><span>github</span><span>.</span><span>com</span></a>:443 -tls1_2</span><br><span></span><br><span>... 略 ...</span><br><span>New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES128-GCM-SHA256</span><br><span>Server public key is 2048 bit</span><br><span>Secure Renegotiation IS supported</span><br><span>Compression: NONE</span><br><span>Expansion: NONE</span><br><span>No ALPN negotiated</span><br><span>SSL-Session:</span><br><span>    Protocol  : TLSv1.2</span><br><span>    Cipher    : ECDHE-RSA-AES128-GCM-SHA256</span><br><span>    Session-ID: 210CB9C73B2ACB4C91A6A07A753342FEB900AB7E6245DAD438689E8FA3FBFDED</span><br><span>    Session-ID-ctx:</span><br><span>    Master-Key: 28A18A970DD37D9B84F79ED46D027998ECF2DCF9EDD01A376A7A0A8B4F57D15053789B1A63B720362A6F4AED7189C020</span><br><span>    TLS session ticket lifetime hint: 7200 (seconds)</span><br><span>    TLS session ticket:</span><br><span>    0000 - d1 d1 01 52 63 e8 4d 9d-27 06 48 21 bc 74 06 8d   ...Rc.M. .H!.t..</span><br><span>    0010 - 7d 09 ff 8d 7a 2f 85 ac-e7 bc 38 33 7d 37 f2 f6   }...z/....83}7..</span><br><span>    0020 - 9e 5c c2 69 e7 d8 5e 63-d6 b8 72 b1 6f 57 6a 42   .\.i..^c..r.oWjB</span><br><span>    0030 - 0e da 75 21 f3 c0 5d 01-65 07 bf 91 bd ba fb a8   ..u!..].e.......</span><br><span>    0040 - 56 db 7f 82 b9 bd 23 26-b2 8b 53 e4 1e 99 7b e1   V.....</span><br><span>    0050 - 3f 9e 45 05 3e d2 a7 f8-ae 0a df 00 48 75 70 fd   ?.E.&gt;.......Hup.</span><br><span>    0060 - b2 e9 21 0a c8 a7 4d 66-65 f8 9c 9f b2 c2 3c c1   ..!...Mfe.....&lt;.</span><br><span>    0070 - 52 5d 06 9b 5e 22 67 b2-36 a2 c0 3f bf d7 6b 3e   R]..^<span>"g.6..?..k&gt;</span></span><br><span><span>    0080 - 22 f0 3f 6b 3c 59 0a a6-2d 85 00 19 11 81 bb 7f   "</span>.?k&lt;Y..-.......</span><br><span>    0090 - b4 7b a6 97 96 9f 00 42-8a ae e3 a3 32 9b 8d ff   .{.....B....2...</span><br><span></span><br><span>    Start Time: 1629555327</span><br><span>    Timeout   : 7200 (sec)</span><br><span>    Verify <span>return</span> code: 0 (ok)</span><br><span>---</span><br></pre></td></tr></tbody></table>

除了 openssl，也可以使用 cURL:

<table><tbody><tr><td><pre><span>1</span><br><span>2</span><br><span>3</span><br><span>4</span><br><span>5</span><br><span>6</span><br><span>7</span><br><span>8</span><br><span>9</span><br><span>10</span><br><span>11</span><br></pre></td><td><pre><span>~$ curl --version</span><br><span>curl 7.64.1 (x86_64-apple-darwin19.0) libcurl/7.64.1 (SecureTransport) LibreSSL/2.8.3 zlib/1.2.11 nghttp2/1.39.2</span><br><span>Release-Date: 2019-03-27</span><br><span>Protocols: dict file ftp ftps gopher http https imap imaps ldap ldaps pop3 pop3s rtsp smb smbs smtp smtps telnet tftp</span><br><span>Features: AsynchDNS GSS-API HTTP2 HTTPS-proxy IPv6 Kerberos Largefile libz MultiSSL NTLM NTLM_WB SPNEGO SSL UnixSockets</span><br><span></span><br><span></span><br><span>~$ curl -s -S -v -o /dev/null \</span><br><span>    --tls-max 1.2 \</span><br><span>    --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \</span><br><span>    <a href="https://rickhw.github.com/" rel="nofollow"><span>https</span><span>://</span><span>rickhw</span><span>.</span><span>github</span><span>.</span><span>com</span></a></span><br></pre></td></tr></tbody></table>

* * *

想設計出一個安全的通訊協議，最好的方法，就是參考現在在線上運行多年的標準協議。

那些我們使用多年，卻完全不知道怎麼運做的協議，越是經的起考驗、值得研究的。很久以前就想整理關於 HTTPS / TLS 通訊協議的知識，研究過整個 TLS 協議之後，對於設計安全通訊協議算是有初步基礎的認識，過程中也更加強了整理 [摘要密碼學與資訊安全](chrome-extension://cjedbglnccaioiolemnfhjncicchinao/2020/03/07/ComputerScience/Cryptography/) 一文中不解的部分。

近利用一些瑣碎時間，片段的把資訊組起來，找了很多資料、抓封包分析了解。探索過程其實是很享受、且有趣的，而且更加地知道自己的不足，更加知道前人努力的完整性。

`資訊安全` 一直以來都是 `動詞`，但是要具備 `能力 (Ability)` 執行這些動作，所要具備的 `領域專業知識 (Know How)` 與 `技能 (Skills)` 是一個都不能少的，否則就只是紙上談兵，說空話的江湖郎中。在整理 [AWS KMS](chrome-extension://cjedbglnccaioiolemnfhjncicchinao/2020/03/02/AWS/Study-Notes-KMS/) 以及 Secret Management 的時候，就覺得應該往前推把 [基礎密碼學](chrome-extension://cjedbglnccaioiolemnfhjncicchinao/2020/03/07/ComputerScience/Cryptography/) 做一些複習與研究，彌補自己對於這些知識的不足。而在研讀密碼學的過程，覺得應該要與實務結合，過程中因為時事，整理了 `Data Encryption` 的概念 (Data in Transit、at Rest、in Used) ，岔到了資訊安全去了。後來覺得要能夠精準掌握這些密碼覺得應用，還是應該從掌握協議設計切入，所以選擇了現金網路通訊最重要的安全通訊協議 TLS 切入，所以就有了這一篇 `簡介 HTTPS / TLS 安全通訊協議` 整理。

網路上其實有很多整理很好的文章，本文剛開始是參考 [那些關於SSL/TLS的二三事(九) — SSL (HTTPS) Communication](https://medium.com/@clu1022/%E9%82%A3%E4%BA%9B%E9%97%9C%E6%96%BCssl-tls%E7%9A%84%E4%BA%8C%E4%B8%89%E4%BA%8B-%E4%B9%9D-ssl-communication-31a2a8a888a6) 為起點，過程中以此延伸找尋更多資料，更是實際從抓封包、夠過 openssl 實際應用，得到驗證。

這只是開始，還有很多要補充以及學習的！

* * *

[](#站內文章 "站內文章")站內文章
--------------------

*   [摘要密碼學與資訊安全](chrome-extension://cjedbglnccaioiolemnfhjncicchinao/2020/03/07/ComputerScience/Cryptography/)
*   [Study Notes - Key Management Service](chrome-extension://cjedbglnccaioiolemnfhjncicchinao/2020/03/02/AWS/Study-Notes-KMS/)
*   [如何用 G Guite 整合 AWS Single Sign-On](chrome-extension://cjedbglnccaioiolemnfhjncicchinao/2019/05/30/AWS/Federated-SSO-to-AWS-using-GSuite/)
*   [Study Notes - AWS S3](chrome-extension://cjedbglnccaioiolemnfhjncicchinao/2016/04/07/AWS/Study-Notes-S3/)

[](#參考資料 "參考資料")參考資料
--------------------

*   [The First Few Milliseconds of an HTTPS Connection](http://www.moserware.com/2009/06/first-few-milliseconds-of-https.html?repost!)
*   [Supported protocols and ciphers between viewers and CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html#secure-connections-openssl-rfc-cipher-names)
*   [Key management and Diffie-Hellman Key Exchange (CSS322, Lecture 21, 2013)](https://www.youtube.com/watch?v=yM8_YMLnqLo)
*   [为什么 HTTPS 需要 7 次握手以及 9 倍时延 · Why’s THE Design?](https://draveness.me/whys-the-design-https-latency)
*   [那些關於SSL/TLS的二三事(九) — SSL (HTTPS)Communication](https://medium.com/@clu1022/%E9%82%A3%E4%BA%9B%E9%97%9C%E6%96%BCssl-tls%E7%9A%84%E4%BA%8C%E4%B8%89%E4%BA%8B-%E4%B9%9D-ssl-communication-31a2a8a888a6)
*   [那些關於SSL/TLS的二三事(二) — How SSL works?](https://medium.com/@clu1022/%E9%82%A3%E4%BA%9B%E9%97%9C%E6%96%BCssl-tls%E7%9A%84%E4%BA%8C%E4%B8%89%E4%BA%8B-%E4%BA%8C-how-ssl-works-a9d6720bdd48)
*   [Wireshark - Why TLS version is different in Record Layer and Handshake Protocol](https://www.analysisman.com/2021/06/wireshark-tls1.2.html)
*   [Man in the middle attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
*   [HTTPS 温故知新（二） —— TLS 记录层协议](https://halfrost.com/https_record_layer/)
*   [Predefined SSL security policies for Classic Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html)
*   [深入理解 TLS/SSL 安全加密協定](https://www.facebook.com/will.fans/videos/374050803968418)

[](#RFC "RFC")RFC
-----------------

*   [RFC 8446 - TLS v1.3](https://datatracker.ietf.org/doc/html/rfc8446)
*   [RFC 5246 - TLS v1.2](https://datatracker.ietf.org/doc/html/rfc5246)
*   [RFC 4346 - TLS v1.1](https://datatracker.ietf.org/doc/html/rfc4346)
*   [RFC 2246 - TLS v1.0](https://datatracker.ietf.org/doc/html/rfc2246)

[](#Wikipedia "Wikipedia")Wikipedia
-----------------------------------

*   [Cipher Suites](https://en.wikipedia.org/wiki/Cipher_suite)
*   [Key exchange](https://en.wikipedia.org/wiki/Key_exchange)
*   [Elliptic-curve Diffie–Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
*   [Diffie–Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
*   [訊息鑑別碼, MAC](https://zh.wikipedia.org/zh-tw/%E8%A8%8A%E6%81%AF%E9%91%91%E5%88%A5%E7%A2%BC)

* * *


[Source](https://rickhw.github.io/2021/08/20/ComputerScience/HTTPS-TLS/)