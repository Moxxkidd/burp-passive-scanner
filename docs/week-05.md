# Week 05 - 正则库扩展

## 目标
- 覆盖真实场景的高价值敏感信息
- 重点：身份证校验码逻辑、API Key 特征、内网 IP 范围


## 范围
- 中国大陆身份证（18 位 + 校验码 + 省份码 + 出生日期校验）
- 内网 IP（10/8, 172.16/12, 192.168/16, 127.0.0.1）
- API Key（AWS / Google / GitHub / Slack / Stripe）

## 步骤
- 扩展 PATTERNS 列表，按类型定义正则
- 加入身份证校验码 + 省份码 + 出生日期校验
- 内网 IP 通过校验函数过滤
- 使用testforscanner2.html测试
- 命中后输出为 Burp Issues

## 结果
- Issues 中出现 “Sensitive Info: <type>” 条目

## 证据（截图/日志）
- 见asset/scanner2 output1，2，3
  

