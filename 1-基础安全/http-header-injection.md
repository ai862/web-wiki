# HTTP头注入攻击技术文档

## 1. 概述

### 1.1 定义
HTTP头注入攻击（HTTP Header Injection）是一种Web应用程序安全漏洞，攻击者通过在HTTP请求或响应头中注入恶意内容，从而影响服务器或客户端的行为。这种攻击可能导致多种安全问题，包括会话劫持、跨站脚本攻击（XSS）、缓存污染、以及重定向攻击等。

### 1.2 背景
HTTP头是HTTP协议中用于传递元数据的重要组成部分，常见的HTTP头包括`Cookie`、`User-Agent`、`Referer`、`Location`等。Web应用程序在处理这些头信息时，如果未能正确验证和过滤用户输入，攻击者便有机会注入恶意内容，进而操纵HTTP头的行为。

## 2. 攻击原理

### 2.1 基本流程
HTTP头注入攻击的核心原理是攻击者通过构造恶意输入，将额外的HTTP头或控制字符（如换行符`\r\n`）注入到HTTP请求或响应中。这些注入的内容会被服务器或客户端解析为合法的HTTP头，从而导致非预期的行为。

### 2.2 关键点
- **换行符注入**：HTTP头之间通过换行符`\r\n`分隔。攻击者通过注入换行符，可以在HTTP头中插入新的头字段或修改现有头字段。
- **输入验证缺失**：Web应用程序在处理用户输入时，未能正确验证和过滤输入内容，导致恶意内容被注入到HTTP头中。
- **上下文差异**：HTTP头注入的效果取决于注入的上下文。例如，注入到`Location`头可能导致重定向攻击，而注入到`Set-Cookie`头可能导致会话劫持。

## 3. 攻击分类

### 3.1 请求头注入
请求头注入是指攻击者在HTTP请求头中注入恶意内容。常见的攻击场景包括：
- **User-Agent注入**：攻击者通过修改`User-Agent`头，注入恶意内容以触发服务器端的漏洞。
- **Referer注入**：攻击者通过修改`Referer`头，注入恶意内容以影响服务器的行为。

### 3.2 响应头注入
响应头注入是指攻击者在HTTP响应头中注入恶意内容。常见的攻击场景包括：
- **Location注入**：攻击者通过注入`Location`头，将用户重定向到恶意网站。
- **Set-Cookie注入**：攻击者通过注入`Set-Cookie`头，操纵用户的会话信息。

### 3.3 混合注入
混合注入是指攻击者同时在请求头和响应头中注入恶意内容。这种攻击通常更为复杂，可能涉及多个攻击向量。

## 4. 技术细节

### 4.1 换行符注入
换行符`\r\n`是HTTP头注入的关键。攻击者通过注入换行符，可以在HTTP头中插入新的头字段。例如：

```http
GET /example HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0\r\nX-Malicious-Header: Attack
```

在上述示例中，攻击者通过注入`\r\n`，在`User-Agent`头后插入了一个恶意的`X-Malicious-Header`头。

### 4.2 攻击向量示例

#### 4.2.1 Location头注入
假设一个Web应用程序在处理用户输入时，将用户输入的内容直接插入到`Location`头中：

```php
<?php
$redirect_url = $_GET['url'];
header("Location: " . $redirect_url);
?>
```

攻击者可以构造如下URL进行攻击：

```
http://example.com/redirect.php?url=http://evil.com%0d%0aSet-Cookie: sessionid=12345
```

服务器生成的HTTP响应头如下：

```http
HTTP/1.1 302 Found
Location: http://evil.com
Set-Cookie: sessionid=12345
```

攻击者通过注入`%0d%0a`（URL编码的`\r\n`），在`Location`头后插入了一个`Set-Cookie`头，从而操纵用户的会话信息。

#### 4.2.2 Set-Cookie头注入
假设一个Web应用程序在处理用户输入时，将用户输入的内容直接插入到`Set-Cookie`头中：

```php
<?php
$cookie_value = $_GET['value'];
setcookie("sessionid", $cookie_value);
?>
```

攻击者可以构造如下URL进行攻击：

```
http://example.com/setcookie.php?value=12345%0d%0aX-Malicious-Header: Attack
```

服务器生成的HTTP响应头如下：

```http
HTTP/1.1 200 OK
Set-Cookie: sessionid=12345
X-Malicious-Header: Attack
```

攻击者通过注入`%0d%0a`，在`Set-Cookie`头后插入了一个恶意的`X-Malicious-Header`头。

## 5. 防御思路和建议

### 5.1 输入验证和过滤
- **严格验证用户输入**：确保所有用户输入的内容符合预期的格式和类型，避免将用户输入直接插入到HTTP头中。
- **过滤控制字符**：在将用户输入插入到HTTP头之前，过滤掉所有可能被滥用的控制字符，如换行符`\r\n`。

### 5.2 输出编码
- **输出编码**：在将用户输入插入到HTTP头之前，对输入内容进行编码，确保其不会被解析为HTTP头的一部分。

### 5.3 使用安全的API
- **使用安全的API**：避免直接操作HTTP头，使用安全的API来处理HTTP头信息。例如，使用`header()`函数时，确保传入的参数是安全的。

### 5.4 安全配置
- **配置Web服务器**：确保Web服务器的配置能够防止HTTP头注入攻击。例如，配置服务器以拒绝包含非法字符的HTTP请求。

### 5.5 安全测试
- **定期进行安全测试**：通过渗透测试和代码审计，定期检查Web应用程序是否存在HTTP头注入漏洞。

## 6. 总结
HTTP头注入攻击是一种严重的安全威胁，攻击者通过注入恶意内容，可以操纵HTTP头的行为，导致多种安全问题。防御HTTP头注入攻击的关键在于严格验证和过滤用户输入，使用安全的API，并进行定期的安全测试。通过采取这些措施，可以有效降低HTTP头注入攻击的风险。

---

*文档生成时间: 2025-03-11 13:14:22*
