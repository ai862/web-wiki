

# GraphQL内省攻击的检测与监控技术指南

## 一、技术原理解析
### 1.1 内省机制本质
GraphQL内省（Introspection）是协议规范中的核心功能，通过__schema元字段暴露服务端类型系统。攻击者利用该特性构造如下典型查询：

```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}
```

底层实现依赖AST（抽象语法树）解析，服务端接收到查询后会递归遍历类型描述树，生成包含所有可用类型、字段、参数的JSON响应。

### 1.2 攻击原理
攻击者通过自动化工具或手工构造特殊查询，获取完整的API架构信息。关键风险点包括：
- 未授权访问__schema对象
- 未对嵌套查询深度进行限制
- 未过滤敏感类型（如Mutation类型）

## 二、高级攻击变种
### 2.1 别名绕过
通过字段别名规避简单关键词过滤：
```graphql
query {
  alias1: __schema {
    alias2: types {
      name
    }
  }
}
```

### 2.2 分片攻击
利用查询分片绕过深度检测：
```graphql
query {
  __schema {
    queryType { ...F1 }
    mutationType { ...F2 }
  }
}

fragment F1 on __Type {
  name
  fields {
    name
  }
}

fragment F2 on __Type {
  name
}
```

### 2.3 持久化查询绕过
针对使用Persisted Queries的端点：
```bash
curl -X POST -H "Content-Type: application/json" -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"hash"}}}' http://target/graphql
```

## 三、检测方法论
### 3.1 主动探测技术
使用自动化工具扫描：
```bash
# 使用GraphQLmap
python3 graphqlmap.py -u http://target/graphql -dump

# 使用Clairvoyance
clairvoyance -v -o schema.json -w wordlist.txt http://target/graphql
```

### 3.2 流量特征分析
关键检测指标：
- 请求体包含__schema、__type等保留字段
- 异常查询深度（>5层嵌套）
- 高频类型枚举请求（QPS>50）

### 3.3 模式对比法
基线检测流程：
1. 生成标准模式：graphql-inspector diff http://prod/graphql http://staging/graphql
2. 对比运行时查询模式
3. 检测未登记的类型访问

## 四、监控与防御方案
### 4.1 WAF规则示例（ModSecurity）
```conf
SecRule REQUEST_BODY "@rx (?i)__schema|__type|__typename" \
    "id:1001,\
    phase:2,\
    deny,\
    msg:'GraphQL Introspection Attempt'"
```

### 4.2 运行时防护代码（Node.js示例）
```javascript
const { validate } = require('graphql');

function introspectionBlockMiddleware(req, res, next) {
  const query = req.body.query;
  const ast = parse(query);
  
  const isIntrospection = ast.definitions.some(definition => {
    return definition.selectionSet.selections.some(selection => {
      return selection.name.value.startsWith('__');
    });
  });
  
  if (isIntrospection) {
    res.status(403).json({ error: 'Introspection disabled' });
  } else {
    next();
  }
}
```

### 4.3 监控指标体系
| 指标类型       | 采集方式             | 告警阈值       |
|----------------|----------------------|----------------|
| 内省查询次数   | Nginx日志分析        | >5次/分钟      |
| 类型枚举速率   | Prometheus计数器     | >100类型/请求  |
| 异常字段访问   | ELK日志分析          | 未登记字段出现 |

## 五、实战演练环境
### 5.1 实验环境搭建
使用Docker部署脆弱环境：
```bash
docker run -d -p 5000:5000 dolevf/edge-graphql-vulnerable-app
```

### 5.2 攻击步骤演示
1. 发现GraphQL端点
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}' \
  http://localhost:5000/graphql
```

2. 执行分片查询
```graphql
query IntrospectionQuery {
  __schema {
    types {
      name
      kind
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

3. 自动化工具利用
```bash
inql -t http://localhost:5000/graphql -generate-html
```

### 5.3 防御测试验证
1. 启用查询成本分析：
```yaml
# graphql-cost-analysis配置
costLimit: 1000
depthCost: 2
complexityCost: 1
```

2. 测试防护效果：
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name } } }"}' \
  http://localhost:5000/graphql
# 预期返回403错误
```

## 六、企业级监控方案
### 6.1 架构设计
```
+-----------------+     +-----------------+     +---------------+
| 流量采集层      | --> | 实时分析引擎    | --> | 可视化平台    |
| (Nginx/Haproxy) |     (Apache Kafka)    |     (Grafana)      |
+-----------------+     +-----------------+     +---------------+
```

### 6.2 Splunk搜索示例
```splunk
source="graphql_logs" 
| stats count by query 
| search query="*__schema*" 
| eval risk_level=if(match(query, "__schema"), "CRITICAL", "LOW")
```

### 6.3 行为分析模型
```python
from sklearn.ensemble import IsolationForest

# 特征矩阵包含：[查询长度, 嵌套深度, 保留字段数]
X = [[1024, 8, 5], [256, 3, 0], ...]
clf = IsolationForest(contamination=0.1)
clf.fit(X)
```

## 七、工具链整合
### 7.1 开源工具对比
| 工具名称       | 检测能力             | 企业级集成       |
|----------------|----------------------|------------------|
| GraphQL Armor | 实时阻断             | API Gateway插件  |
| Escape        | 查询分析             | Kubernetes原生   |
| Tinfoil       | 模式监控             | Splunk集成       |

### 7.2 商业解决方案
1. AWS AppSync：内置查询深度限制（默认12层）
2. Apollo Studio：提供模式变更警报
3. Hasura Pro：实时查询分析仪表盘

## 八、附录：检测规则库
### 8.1 Sigma规则
```yaml
title: GraphQL Introspection Attempt
logsource:
  category: webserver
detection:
  keywords:
    - "__schema"
    - "__type"
    - "__typename"
  condition: keywords
falsepositives:
  - Development environments
level: high
```

### 8.2 YARA规则
```text
rule graphql_introspection {
  strings:
    $schema = "__schema" nocase
    $type = "__type" nocase
  condition:
    any of them and filesize < 50KB
}
```

本指南从攻击原理到防御实践，覆盖了GraphQL内省攻击检测与监控的核心技术要点。建议企业结合自身技术栈，选择至少三种检测手段形成纵深防御体系，并定期进行红蓝对抗演练验证防护效果。

---

*文档生成时间: 2025-03-13 11:53:52*
