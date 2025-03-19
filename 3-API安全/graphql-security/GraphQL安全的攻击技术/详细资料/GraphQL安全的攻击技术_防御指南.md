

# GraphQL安全攻击技术防御指南

## 一、GraphQL安全挑战概述
GraphQL的灵活性和自描述特性使其面临独特的安全风险。其单端点设计、嵌套查询能力和动态请求结构为攻击者提供了多种潜在攻击面。本指南聚焦8类核心攻击技术及其防御方案。

## 二、攻击技术分类与防御策略

### 1. 注入攻击（Injection）
**攻击原理**：
- 利用未过滤的输入参数执行恶意操作
- 常见类型：SQL注入、NoSQL注入、命令注入、XSS

**典型案例**：
```graphql
query {
  user(filter: "id = 1; DROP TABLE users--") {
    id
  }
}
```

**防御措施**：
- 实施输入验证（正则表达式匹配、类型检查）
- 使用参数化查询（避免拼接原始输入）
- 限制自定义`@directive`的执行权限
- 对输出内容进行HTML编码（防御XSS）

### 2. 信息泄露（Introspection Abuse）
**攻击原理**：
- 利用内省查询`__schema`获取API元数据
- 暴露敏感字段、隐藏接口或调试端点

**防御措施**：
```yaml
# Apollo Server配置示例
production:
  introspection: false
  playground: false
  debug: false
```
- 按环境区分内省功能开关
- 实现字段级白名单控制
- 自定义内省查询响应（返回模糊化错误信息）

### 3. 拒绝服务攻击（DoS）
**攻击原理**：
- 构造深度嵌套查询（超过10层）
- 发起循环引用查询（类型A→B→A...）
- 巨型查询（单次请求返回10万+对象）

**防御策略**：
| 防御维度      | 推荐阈值        | 实施方式                |
|---------------|-----------------|-------------------------|
| 查询深度       | ≤6层           | `graphql-depth-limit`   |
| 查询复杂度     | ≤1000 points    | `graphql-cost-analysis` |
| 分页限制       | max 100条/请求  | Schema字段定义验证      |
| 请求超时       | 10秒           | 网关层全局控制         |

### 4. 批量查询攻击（Batching Abuse）
**攻击模式**：
```graphql
# 单请求发起100次用户查询
query ($ids: [ID!]!) {
  users(ids: $ids) { 
    email 
  }
}
```

**防御方案**：
- 限制数组参数最大长度（如`max: 20`）
- 实施请求频率控制（令牌桶算法）
- 关键操作强制要求`CAPTCHA`验证
- 监控异常批量请求模式（如相同结构高频次请求）

### 5. CSRF攻击
**风险场景**：
- 浏览器自动发送预检请求（OPTIONS）
- 未验证来源的变更操作（mutation）

**防御机制**：
```http
# 强制检查请求头
Origin: https://trusted-domain.com
Referer: https://trusted-domain.com/path
```
- 启用`SameSite=Strict`的Cookie策略
- 敏感操作必须携带CSRF Token
- 禁用CORS通配符配置（`Access-Control-Allow-Origin: *`）

### 6. 服务端请求伪造（SSRF）
**攻击载体**：
```graphql
mutation {
  importData(url: "http://internal-api/admin") 
}
```

**防护方案**：
- 解析输入URL的协议/域名/IP白名单
- 禁用`file://`、`gopher://`等危险协议
- 使用正则表达式过滤内部地址（`10\.\d+\.\d+\.\d+`）
- 配置网络层出站规则（禁止服务器访问内部网络）

### 7. 权限逃逸（Authorization Bypass）
**漏洞模式**：
- 未验证的接口拼接攻击（GraphQL Federation）
- 通过别名重复访问受限字段

**防御实践**：
```graphql
type Query {
  user(id: ID!): User @auth(requires: ADMIN)
  # 防御别名攻击
  _hidden_user: User @deprecated(reason: "internal")
}
```
- 实施基于角色的字段级权限控制（RBAC/ABAC）
- 使用`@auth`指令验证每个字段的访问权限
- 定期审计Schema变更记录

### 8. 缓存投毒攻击
**攻击方式**：
- 利用相同查询结构返回不同用户数据
- 注入恶意缓存控制头

**防御建议**：
```nginx
# Nginx缓存分区配置
proxy_cache_key $scheme$request_method$host$uri$args$http_authorization;
```
- 按用户身份划分缓存分区
- 禁用敏感查询的缓存（通过`Cache-Control: no-store`）
- 验证`Vary`头包含身份验证信息

## 三、增强型防御体系

### 1. SDL安全规范
```graphql
# 安全Schema设计示例
directive @rateLimit(
  max: Int
  window: String
) on FIELD_DEFINITION

type Query {
  highRiskQuery: Data 
    @rateLimit(max: 5, window: "1m")
    @auth(requires: ADMIN)
}
```

### 2. 运行时保护
- 部署GraphQL防火墙（如Escape、Hasura Shield）
- 实施请求签名（HMAC算法）
- 关键操作日志全量审计

### 3. 持续安全实践
- 自动化Schema变更审查（GitOps流程）
- 定期执行模糊测试（如GitLab的GQL Fuzzer）
- 第三方依赖漏洞扫描（如检查graphql-js版本）

## 四、总结
构建GraphQL安全防御体系需采用分层防御策略：在Schema设计阶段实施安全控制，在运行时进行动态防护，并通过持续监控完善防护机制。建议企业参考OWASP GraphQL Cheat Sheet，结合具体业务场景制定防御方案，每季度进行红蓝对抗演练验证防护有效性。

---

*文档生成时间: 2025-03-13 09:57:28*
