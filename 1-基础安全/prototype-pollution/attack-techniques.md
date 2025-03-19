### 前端原型链污染攻击技术详解

#### 1. 什么是前端原型链污染？
前端原型链污染（Prototype Pollution）是一种利用JavaScript原型链机制的安全漏洞。JavaScript中的每个对象都有一个原型（`__proto__`），通过原型链，对象可以继承其原型的属性和方法。攻击者通过篡改对象的原型，可以在目标应用中注入恶意代码或修改现有逻辑，从而实现攻击。

#### 2. 原型链污染的原理
在JavaScript中，对象的原型链是通过`__proto__`属性或`Object.prototype`来定义的。当访问一个对象的属性时，如果该对象本身没有该属性，JavaScript会沿着原型链向上查找，直到找到该属性或到达原型链的顶端（`null`）。

攻击者通过向对象的原型链中注入恶意属性或方法，可以影响所有继承自该原型的对象。例如，如果攻击者能够修改`Object.prototype`，那么所有JavaScript对象都会继承这些修改，从而可能导致严重的安全问题。

#### 3. 常见攻击手法
以下是几种常见的前端原型链污染攻击手法：

##### 3.1 通过对象合并操作污染原型链
对象合并操作（如`Object.assign`或`_.merge`）是前端开发中常见的操作，用于将多个对象的属性合并到一个对象中。如果攻击者能够控制合并的源对象，可以通过向源对象中添加`__proto__`属性来污染目标对象的原型链。

**示例代码：**
```javascript
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

let target = {};
let source = JSON.parse('{"__proto__":{"isAdmin":true}}');
merge(target, source);

console.log({}.isAdmin); // true
```
在这个例子中，攻击者通过控制`source`对象，成功地将`isAdmin`属性注入到`Object.prototype`中，导致所有对象都继承了`isAdmin`属性。

##### 3.2 通过JSON.parse污染原型链
`JSON.parse`是前端开发中常用的方法，用于将JSON字符串解析为JavaScript对象。如果攻击者能够控制输入的JSON字符串，可以通过在JSON字符串中包含`__proto__`属性来污染原型链。

**示例代码：**
```javascript
let obj = JSON.parse('{"__proto__":{"isAdmin":true}}');
console.log({}.isAdmin); // true
```
在这个例子中，攻击者通过控制输入的JSON字符串，成功地将`isAdmin`属性注入到`Object.prototype`中。

##### 3.3 通过库函数污染原型链
许多前端库（如Lodash、jQuery等）提供了便捷的对象操作函数，但这些函数在处理对象时可能存在原型链污染的风险。如果攻击者能够控制这些函数的输入，可以通过这些函数污染原型链。

**示例代码：**
```javascript
let _ = require('lodash');
let obj = _.merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'));
console.log({}.isAdmin); // true
```
在这个例子中，攻击者通过控制`_.merge`函数的输入，成功地将`isAdmin`属性注入到`Object.prototype`中。

#### 4. 利用方式
前端原型链污染可以被利用来实现多种攻击，以下是一些常见的利用方式：

##### 4.1 权限提升
通过污染原型链，攻击者可以向所有对象注入权限相关的属性或方法，从而提升自己的权限。例如，攻击者可以注入`isAdmin`属性，使得所有对象都继承该属性，从而绕过权限检查。

**示例代码：**
```javascript
let obj = JSON.parse('{"__proto__":{"isAdmin":true}}');
if ({}.isAdmin) {
    // 执行管理员操作
}
```
在这个例子中，攻击者通过污染原型链，成功地将`isAdmin`属性注入到所有对象中，从而绕过权限检查。

##### 4.2 代码注入
通过污染原型链，攻击者可以向所有对象注入恶意代码，从而在目标应用中执行任意代码。例如，攻击者可以注入`toString`方法，使得所有对象在调用`toString`方法时执行恶意代码。

**示例代码：**
```javascript
let obj = JSON.parse('{"__proto__":{"toString":function(){alert('XSS');}}}');
({}).toString(); // 弹出XSS警告框
```
在这个例子中，攻击者通过污染原型链，成功地将恶意代码注入到`toString`方法中，从而在目标应用中执行任意代码。

##### 4.3 数据篡改
通过污染原型链，攻击者可以篡改目标应用中的数据，从而影响应用的正常逻辑。例如，攻击者可以注入`toJSON`方法，使得所有对象在序列化为JSON时返回篡改后的数据。

**示例代码：**
```javascript
let obj = JSON.parse('{"__proto__":{"toJSON":function(){return {"isAdmin":true};}}}');
console.log(JSON.stringify({})); // {"isAdmin":true}
```
在这个例子中，攻击者通过污染原型链，成功地将`toJSON`方法注入到所有对象中，从而篡改目标应用中的数据。

#### 5. 防御措施
为了防止前端原型链污染攻击，可以采取以下防御措施：

##### 5.1 避免使用不安全的对象合并操作
在合并对象时，应避免直接使用`Object.assign`或`_.merge`等不安全的操作，而是使用安全的合并方法，如`Object.create(null)`或`Object.defineProperty`。

**示例代码：**
```javascript
function safeMerge(target, source) {
    for (let key in source) {
        if (source.hasOwnProperty(key)) {
            target[key] = source[key];
        }
    }
    return target;
}

let target = Object.create(null);
let source = JSON.parse('{"__proto__":{"isAdmin":true}}');
safeMerge(target, source);

console.log({}.isAdmin); // undefined
```
在这个例子中，通过使用`Object.create(null)`和`hasOwnProperty`检查，成功避免了原型链污染。

##### 5.2 使用安全的JSON解析方法
在解析JSON字符串时，应使用安全的解析方法，如`JSON.parse`的`reviver`参数，或使用第三方库（如`json5`）来解析JSON字符串。

**示例代码：**
```javascript
let obj = JSON.parse('{"__proto__":{"isAdmin":true}}', (key, value) => {
    if (key === '__proto__') {
        return undefined;
    }
    return value;
});
console.log({}.isAdmin); // undefined
```
在这个例子中，通过使用`reviver`参数，成功避免了原型链污染。

##### 5.3 使用安全的库函数
在使用前端库时，应选择安全的库函数，并确保库函数在处理对象时不会污染原型链。例如，可以使用`lodash`的`_.mergeWith`函数，并自定义合并逻辑。

**示例代码：**
```javascript
let _ = require('lodash');
let obj = _.mergeWith({}, JSON.parse('{"__proto__":{"isAdmin":true}}'), (objValue, srcValue, key) => {
    if (key === '__proto__') {
        return undefined;
    }
    return srcValue;
});
console.log({}.isAdmin); // undefined
```
在这个例子中，通过使用`_.mergeWith`函数，并自定义合并逻辑，成功避免了原型链污染。

#### 6. 总结
前端原型链污染是一种严重的安全漏洞，攻击者通过篡改对象的原型链，可以在目标应用中注入恶意代码或修改现有逻辑，从而实现攻击。为了防止前端原型链污染攻击，应避免使用不安全的对象合并操作，使用安全的JSON解析方法，并选择安全的库函数。通过采取这些防御措施，可以有效降低前端原型链污染的风险。

---

*文档生成时间: 2025-03-11 16:15:31*






















