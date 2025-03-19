

# GraphQL内省攻击防御指南

## 1. 攻击原理与风险
GraphQL内省攻击利用API的内省（Introspection）功能获取完整的Schema信息，包括类型定义、查询/变更操作及字段描述。攻击者通过发送`__schema`或`__type`等系统级查询，可构建完整的API结构映射，进而发起精准的注入攻击、信息泄露或逻辑漏洞利用。

## 2. 核心防御原则
### 2.1 最小化暴露原则
仅暴露业务必需的数据结构与功能，消除非必要的信息泄露风险源。

### 2.2 分层权限控制
基于角色实施细粒度访问控制，将内省功能与业务操作权限解耦。

### 2.3 动态防御机制
结合运行时分析与静态策略，建立多层防御体系。

---

## 3. 关键防御策略

### 3.1 禁用生产环境内省功能
**实施方法**：
```graphql
# GraphQL服务端配置示例（Apollo Server）
const server = new ApolloServer({
  introspection: process.env.NODE_ENV !== 'production'
});
```
**注意事项**：
- 开发/测试环境保留内省用于调试
- 配合环境变量实现自动化配置
- 验证配置是否生效：发送`{ __schema { types { name } } }`应返回错误

### 3.2 精细化权限控制
**分层授权模型**：
```yaml
# 基于角色的访问控制（RBAC）示例
permissions:
  - role: anonymous
    allowed_operations: [query]
    blocked_fields: [__schema, __type]
  - role: developer
    allowed_operations: [query, introspection]
```

**实现方式**：
- 中间件拦截内省查询
- JWT/OAuth2声明包含权限标记
- 结合GraphQL指令系统实现字段级控制

### 3.3 查询白名单机制
**持久化查询（Persisted Queries）**：
```python
# Django实现示例
from graphene_django.views import PersistedQueryView

class CustomPersistedView(PersistedQueryView):
    allowed_queries = {
        "userProfile": "query { user { id name } }",
        "postList": "query { posts { title content } }"
    }
```

**优势**：
- 限制客户端自由构建查询
- 防止任意内省请求
- 降低服务器解析开销

### 3.4 查询深度/复杂度限制
**防御配置**：
```javascript
// GraphQL Yoga配置示例
const server = createServer({
  validationRules: [
    depthLimit(3),          // 最大查询深度
    complexityLimit(1000)   // 复杂度分数阈值
  ]
});
```

**深度计算示例**：
```graphql
query {
  user {          # 深度1
    posts {       # 深度2
      comments {  # 深度3
        author    # 深度4（触发阻断）
      }
    }
  }
}
```

### 3.5 监控与异常检测
**日志记录策略**：
```nginx
# Nginx日志格式配置
log_format graphql '$remote_addr - $request_id - $query_depth - $query_complexity';
```

**监控指标**：
- 单位时间内的内省请求频率
- 非常规查询模式识别
- 异常客户端IP行为分析

### 3.6 Schema加固
**SDL处理示例**：
```ruby
# 移除描述信息的预处理脚本
schema = Schema.execute(introspection_query)
schema.types.each { |t| t.description = nil }
File.write('public/schema.graphql', schema.to_definition)
```

**加固措施**：
- 删除生产环境Schema描述信息
- 禁用类型系统扩展
- 关闭调试端点（如GraphiQL）

---

## 4. 进阶防护技术

### 4.1 查询成本分析
```python
# 基于自定义权值的成本计算
class QueryCostAnalyzer:
    def get_cost(self, node):
        if node.name.value == '__schema': 
            return 1000  # 显著提高内省操作成本
        return len(node.selection_set.selections)
```

### 4.2 动态令牌验证
**查询签名机制**：
```
客户端生成：
SHA256(查询语句 + 时间戳 + 客户端密钥)

服务端验证：
1. 校验签名有效性
2. 验证时间戳窗口（±5分钟）
3. 阻断重复请求
```

### 4.3 运行时防护
```javascript
// 请求拦截中间件
app.use('/graphql', (req, res, next) => {
  const query = req.body.query;
  if (/(__schema|__type)/.test(query)) {
    res.locals.block_reason = 'Introspection attempt detected';
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});
```

---

## 5. 运维实践清单

1. **环境隔离**：
   - 生产环境禁用GraphiQL/Playground
   - 分离开发与生产Schema

2. **CI/CD集成**：
   ```yaml
   # 流水线安全检查
   - name: Introspection Test
     run: |
       curl -X POST -H "Content-Type: application/json" \
       -d '{"query":"{__schema{types{name}}}"}' \
       $API_ENDPOINT | grep -q "Introspection disabled" || exit 1
   ```

3. **应急响应**：
   - 建立内省攻击特征库
   - 预设自动阻断规则
   - 保留原始查询日志用于取证

---

## 6. 总结
有效的防御需结合技术控制与管理策略：
1. 通过禁用内省、权限控制消除基础风险
2. 采用查询白名单、复杂度限制构建主动防御
3. 依托监控系统实现持续威胁检测
4. 定期进行渗透测试验证防护有效性

建议每季度审查Schema暴露面，评估第三方GraphQL工具（如Apollo Engine）的配置安全性，保持防御机制与业务演进同步。

---

*文档生成时间: 2025-03-13 11:49:08*
