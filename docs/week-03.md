# Week 03 - 正则与敏感信息提取（手机号）

## 目标
- 完成“从响应体提取字符串”的最小闭环
- 重点是响应体 byte → str 的编码处理
- 成果标准是从测试页面抓到手机号


## 日期
- 2026-02-09

## 环境
- 本地测试URL http://127.0.0.1:8000/week03_test2.html测试用例
- 脚本路径：`/Users/an/Documents/burp suite passive scanner/extensions/week3_regex.py`
- 浏览器：Burp 内嵌浏览器 


## 步骤记录
- 使用 IProxyListener 拦截 response
- 通过 `helpers.analyzeResponse` 获取 bodyOffset
- 用 `helpers.bytesToString` 做 bytes → str
- 仅处理文本类 Content-Type
- 访问测试页面http://127.0.0.1:8000/week03_test2.html验证
- 正则匹配手机号并输出命中

## 验收结果
- 成功从测试页面响应体中匹配手机号
- Output3（doc/asset） 中出现 `[HIT] <URL> -> <1387798855>`

## 证据
- Output 命中截图：`docs/assets/output3
- 测试页面地址：`http://127.0.0.1:8000/week3_test2.html`

