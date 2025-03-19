# 邮件头注入攻击技术文档

## 1. 概述

### 1.1 定义
邮件头注入攻击（Email Header Injection）是一种利用Web应用程序中邮件发送功能的漏洞，通过注入恶意内容到邮件头字段，从而操纵邮件发送行为的安全攻击。攻击者可以利用该漏洞发送垃圾邮件、钓鱼邮件，甚至进行进一步的网络攻击。

### 1.2 背景
邮件头注入攻击通常发生在Web应用程序未对用户输入进行严格验证和过滤的情况下。攻击者通过构造特殊的输入数据，将额外的邮件头字段注入到邮件中，从而控制邮件的发送行为。这种攻击不仅影响应用程序的安全性，还可能导致邮件服务器的滥用。

## 2. 原理

### 2.1 邮件头结构
邮件头是邮件的重要组成部分，包含发件人、收件人、主题、日期等信息。邮件头字段通常以键值对的形式出现，例如：

```
From: sender@example.com
To: recipient@example.com
Subject: Hello World
```

### 2.2 注入原理
邮件头注入攻击的核心原理是利用Web应用程序在处理用户输入时未进行严格的验证和过滤。攻击者通过在输入字段中插入换行符（`\r\n`）和额外的邮件头字段，将恶意内容注入到邮件头中。例如：

```
From: sender@example.com
To: recipient@example.com
Subject: Hello World
Bcc: attacker@example.com
```

在上述示例中，攻击者通过在`Subject`字段中插入换行符和`Bcc`字段，将`attacker@example.com`添加到邮件的密送列表中。

## 3. 分类

### 3.1 基于注入位置的分类
邮件头注入攻击可以根据注入位置的不同进行分类：

- **From字段注入**：攻击者在`From`字段中注入恶意内容，伪造发件人信息。
- **To字段注入**：攻击者在`To`字段中注入恶意内容，添加额外的收件人。
- **Subject字段注入**：攻击者在`Subject`字段中注入恶意内容，修改邮件主题。
- **Bcc字段注入**：攻击者在`Bcc`字段中注入恶意内容，添加密送收件人。

### 3.2 基于攻击目的的分类
邮件头注入攻击可以根据攻击目的的不同进行分类：

- **垃圾邮件发送**：攻击者通过注入大量收件人地址，利用应用程序发送垃圾邮件。
- **钓鱼攻击**：攻击者通过伪造发件人信息，发送钓鱼邮件诱骗用户。
- **信息泄露**：攻击者通过注入`Bcc`字段，将邮件内容发送到指定地址，窃取敏感信息。

## 4. 技术细节

### 4.1 攻击向量
邮件头注入攻击的常见攻击向量包括：

- **用户输入字段**：如注册表单、反馈表单、订阅表单等。
- **HTTP请求参数**：如GET或POST请求中的参数。
- **Cookie**：如通过Cookie注入邮件头字段。

### 4.2 注入示例
以下是一个典型的邮件头注入攻击示例：

```php
<?php
$to = $_POST['to'];
$subject = $_POST['subject'];
$message = $_POST['message'];

$headers = "From: sender@example.com\r\n";
$headers .= "To: $to\r\n";
$headers .= "Subject: $subject\r\n";

mail($to, $subject, $message, $headers);
?>
```

假设攻击者在`subject`字段中输入以下内容：

```
Hello World\r\nBcc: attacker@example.com
```

最终的邮件头将变为：

```
From: sender@example.com
To: recipient@example.com
Subject: Hello World
Bcc: attacker@example.com
```

### 4.3 注入技巧
攻击者可以通过以下技巧进行邮件头注入：

- **换行符注入**：使用`\r\n`插入新的邮件头字段。
- **多行注入**：在单个字段中插入多个换行符，注入多个邮件头字段。
- **编码绕过**：使用URL编码或Base64编码绕过输入过滤。

## 5. 防御思路

### 5.1 输入验证
对用户输入进行严格的验证和过滤，确保输入内容符合预期格式。例如，使用正则表达式验证邮件地址格式，禁止输入换行符等特殊字符。

```php
if (!preg_match('/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $email)) {
    die("Invalid email address");
}
```

### 5.2 输出编码
在将用户输入插入到邮件头之前，对输入内容进行编码处理，防止恶意内容被解释为邮件头字段。例如，使用`htmlspecialchars`函数对输入内容进行HTML实体编码。

```php
$subject = htmlspecialchars($_POST['subject'], ENT_QUOTES, 'UTF-8');
```

### 5.3 使用安全的邮件库
使用经过安全审计的邮件库或框架，避免手动构造邮件头。例如，使用PHPMailer库发送邮件，自动处理邮件头的构造和验证。

```php
require 'PHPMailer/PHPMailerAutoload.php';

$mail = new PHPMailer;
$mail->setFrom('sender@example.com');
$mail->addAddress('recipient@example.com');
$mail->Subject = $_POST['subject'];
$mail->Body = $_POST['message'];

if (!$mail->send()) {
    echo 'Mailer Error: ' . $mail->ErrorInfo;
} else {
    echo 'Message sent!';
}
```

### 5.4 日志监控
记录邮件发送的日志，监控异常发送行为。例如，记录每次邮件发送的收件人、发件人、主题等信息，及时发现并处理异常情况。

```php
$log = date('Y-m-d H:i:s') . " - From: sender@example.com, To: $to, Subject: $subject\n";
file_put_contents('mail.log', $log, FILE_APPEND);
```

## 6. 结论

邮件头注入攻击是一种常见且危害较大的Web安全漏洞，攻击者可以通过注入恶意内容控制邮件发送行为，导致垃圾邮件、钓鱼攻击等问题。为了有效防御邮件头注入攻击，开发人员应严格验证和过滤用户输入，使用安全的邮件库，并加强日志监控。通过采取综合的防御措施，可以有效降低邮件头注入攻击的风险，保障Web应用程序的安全性。

---

*文档生成时间: 2025-03-11 13:49:02*
