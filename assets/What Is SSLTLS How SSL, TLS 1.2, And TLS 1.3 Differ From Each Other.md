# What Is SSL/TLS? How SSL, TLS 1.2, And TLS 1.3 Differ From Each Other?

> This article will answer all these fundamental questions about SSL/TLS, and we start from what is SSL/TLS protocol? History of SSL/TLS protocol and mainly TLS handshake process.

SSL/TLS 今天非常流行。沒有它，任何互聯網通信都無法正常工作。儘管它很受歡迎，但許多人仍然不太了解 SSL/TLS。他們沒有回答基本的問題，比如什麼是 SSL/TLS？SSL 和 TLS 相同嗎？哪個是 SSL/TLS 協議的當前版本？SSL/TLS 如何保護互聯網？我們認為最好先了解一下 SSL/TLS 的基礎知識。本文將回答所有這些關於 SSL/TLS 的基本問題，我們從什麼是 SSL/TLS 協議開始？SSL/TLS 協議的歷史，主要是 TLS 握手過程。

**什麼是 SSL/TLS？**
----------------

SSL/TLS 是一種網絡加密協議，可在 Internet 上提供加密通信。Netscape 是 1990 年著名的網絡瀏覽器公司，首先開發了 SSL 並將其添加到他們的瀏覽器中。後來它被包括 Netscape 和 Microsoft 在內的一組公司的 Internet 工程任務組稱為 TLS。SSL 1.0 從未向公眾發布。SSL 的旅程始於 1994 年。 

非常感謝 PowerCert 動畫視頻頻道製作此動畫視頻。

**SSL/TSL 歷史：**
---------------

SSL/TLS 的歷史很早就可以追溯到萬維網的說法。讓我們按時間順序看一下 SSL/TLS 的旅程：

1.  SSL/TLS 的旅程始於 1994 年 Netscape Navigator 發布 SSLv2 時。
2.  幾個月後，Netscape 在 SSLv2 中發現了一個巨大的漏洞，因此他們在 1995 年發布了 SSLv3。
3.  1996 年，Internet Engineering Task Force 組建了一個小組，聚集了包括 Netscape 和 Microsoft 在內的多家公司，研究 Web 瀏覽器加密的標準化版本。該小組決定在 1999 年將名稱從 SSL 更改為 TLS。這就是 TLSv1.0 發布的方式（RFC 2246）。從技術上講，SSL v3 和 TLS v1.0 是相同的。
4.  研究人員在 TLSv1.0 協議中發現了幾個漏洞。還發現TLSv1.1容易受到BEAST攻擊。2006 年發布了新版本的 TSLv1.2 (RFC 4546)，解決了所有漏洞。
5.  隨著一些改革的日子一天天過去，TLS v1.2 (RFC 5246) 於 2008 年發布，並於 2013 年納入所有主要瀏覽器。
6.  TLSv1.3 的初稿創建於 2017 年，並於 2018 年發布（RFC 8446）。

**密碼套件：**
---------

這是在處理 SSL/TLS 時需要了解的重要事項之一。密碼套件是一組有助於保護 TLS 會話的算法。一個密碼套件由三種密碼算法組成。

1.  [密鑰交換算法](https://thesecmaster.com/a-mathematical-explanation-of-the-diffie-hellman-key-exchange-protocol/)：該算法用於通過不安全的公共網絡（如 Internet）在客戶端和服務器之間安全地交換對稱密鑰。
2.  [批量加密算法](https://blog.storagecraft.com/5-common-encryption-algorithms/)：批量加密算法用於加密客戶端和服務器之間交換的應用程序數據。
3.  [消息驗證碼](https://en.wikipedia.org/wiki/Message_authentication_code)：用於執行握手完整性檢查。這個過程從握手過程中涉及的每條消息中取出一部分頭信息，將它們組合起來，並生成一個摘要消息。此摘要消息將與另一方共享，以確保握手過程未被篡改。

在此處訪問鏈接以了解支持的密碼套件和協議版本： [支持的密碼套件和協議版本](https://help.fortinet.com/fweb/586/Content/FortiWeb/fortiweb-admin/supported_cipher_suites.htm)

**DH密鑰交換流程：**
-------------

加密是使用 SSL/TLS 的主要原因。“密鑰”是加密的主要實體。沒有密鑰，加密就無法工作。所以我們認為展示[密鑰交換](https://thesecmaster.com/a-mathematical-explanation-of-the-diffie-hellman-key-exchange-protocol/)背後的邏輯很重要。

加密協議主要分為兩大類——對稱加密和非對稱加密。實際加密發生在非對稱加密中，因為它使用兩個密鑰，私鑰和公鑰。 

讓我們看看非對稱加密協議中的密鑰交換是如何發生的：

讓我們假設“a”是客戶端的私鑰。'b' 是服務器的私鑰。兩個大素數，“p”和“g”是將與客戶端和服務器共享的公鑰。

創建加密密鑰的數學公式是 g^a mod p。

階段1：

步驟 1：當客戶端請求連接到服務器時。服務器發送帶有“p”和“g”值的公共證書。

步驟 2：客戶端生成客戶端加密密鑰。

g^a mod p = A

步驟 3：服務器生成其加密密鑰。

g^b 模 p = B

第 4 步：客戶端和服務器都交換他們的加密密鑰。

階段2：

步驟 5：服務器和客戶端都使用相同的數學函數來計算密鑰。

客戶端密鑰：B^a mod p = K

服務器密鑰：A^b mod p = K

K 用作對稱密鑰。

**TLS v1.2：**
-------------

由於 TLS v1.0、TLS v1.1 和 TLS v1.2 之間沒有顯著差異。最重要的是，TLS v1.2 更接近宇宙。我們認為解釋 TLS v1.2 握手過程很好。在 TLS v1.2 中有大量消息在客戶端和服務器之間來回移動。我們將在逐步過程中查看這些內容。詳細過程請訪問： [Decoding TLS v1.2 protocol Handshake with Wireshark](https://thesecmaster.com/decoding-tls-v1-2-protocol-handshake-with-wireshark/)

**第 1 步：** 整個握手過程從客戶端向服務器發送“client hello”消息開始。此消息包含加密信息，例如支持的 TLS 協議、所有支持的密碼套件、28 字節隨機數、UTC 時間、會話 ID 和服務器的 URL。

**步驟2：** 響應Client的“client hello”消息，Server發送“server hello”消息。此消息包括服務器從客戶端提供的協議中選擇的最高支持的 TLS 協議 CipherSuite。服務器還發送其證書以及會話 ID、UTC 時間和另一個 28 字節的隨機數。

**第 3 步：** 客戶端驗證服務器的證書。驗證後，它發送一個隨機字節串，稱為“pre-master secret”，並使用服務器證書的公鑰對其進行加密。

**第 4 步：** 服務器收到預主密鑰後，客戶端和服務器都生成一個主密鑰和會話密鑰（臨時密鑰）。這些會話密鑰將用於對稱加密數據。

**第 5 步：** 客戶端現在向服務器發送“更改密碼規範”消息，讓它知道它將使用會話密鑰切換到對稱加密。與此同時，它還發送“客戶端完成”消息。

**步驟6：** 響應客戶端的“更改密碼規範”消息，服務器將其安全狀態切換為對稱加密。服務器通過發送“服務器完成”消息來結束握手。

要完成所有這些過程，可能需要 0.25 到 0.5 秒。在 HTTPS 中，第二部分的前半部分是在交換應用程序數據之前完成 TCP 和 TLS 握手協議。這就是 HTTPS 站點加載時間比 HTTP 更長的原因。

**TLS v1.3：**
-------------

TLS 協議的最新版本是 v1.3。這個版本背後的主要思想是通過減少客戶端和服務器之間的來回消息來減少握手過程的時間。這種縮短的握手過程使應用程序數據的交換以比舊版 TLS 協議更快的方式開始。

**第 1 步： ** TLS 1.3 握手也與 TLS 1.2 的情況一樣，以“Client Hello”消息開始。客戶端當然會發送支持的密碼套件列表並猜測服務器可能選擇哪種密鑰協商協議。客戶端還發送其用於該特定密鑰協商協議的密鑰份額。

**第二步：** 服務器回复“Client Hello”消息，回複選擇的密鑰協商協議。“Server Hello”消息還包含服務器的密鑰共享、其證書和“Server Finished”消息。

**步驟 3：** 現在，客戶端檢查服務器共享的證書，生成對稱密鑰，因為它具有服務器的密鑰共享，並發送“客戶端完成”消息。從這一點開始，客戶端和服務器都開始通過加密消息進行通信。

在 TLS v1.3 中，整個過程從六步縮短為三步。這將節省大約 25% 到 50% 的時間來完成 TLS 過程。

**問：**
------

**SSL/TLS 是什麼？**

SSL/TLS 是一種網絡加密協議，可在 Internet 上提供加密通信。Netscape 是 1990 年著名的網絡瀏覽器公司，首先開發了 SSL 並將其添加到他們的瀏覽器中。後來它被包括 Netscape 和 Microsoft 在內的一組公司的 Internet 工程任務組稱為 TLS。SSL 1.0 從未向公眾發布。SSL 的旅程始於 1994 年。

**TLS 和 SSL 有什麼區別？**

從技術上講，SSL v3 和 TLS v1.0 是相同的。1996 年，Internet Engineering Task Force 組建了一個小組，聚集了包括 Netscape 和 Microsoft 在內的多家公司，研究 Web 瀏覽器加密的標準化版本。該小組決定在 1999 年將名稱從 SSL 更改為 TLS。這就是 TLSv1.0 發布的方式（RFC 2246）。

**SSL TLS 如何工作？**

簡而言之，這些協議適用於握手過程。請仔細閱讀 TLS 握手過程以了解 SSL/TLS 協議背後的邏輯。

**SSL 或 TLS 哪個更好？**

由於 SSL 是 TLS 的體面。當然，TLS 比 SSL 更複雜、更好。SSL 已棄用。新的 Web 瀏覽器將不支持 SSL。

**SSL TLS 是哪個 OSI 層？**

雖然，這個名字迫使你說傳輸層。實際上，它在功能上非常適合 OSI 中的會話層。




[Source](https://www.thesecmaster.com/what-is-ssl-tls-how-ssl-tls-1-2-and-tls-1-3-differ-from-each-other/)