# Burp Passive Sensitive Scanner (Jython)

Burp Suite 被动扫描插件，用于在响应中低误报识别敏感信息（手机号、身份证、API Key、内网 IP 等），并在 Burp Issues 中给出告警与高亮定位。

## 目标
- 最小成本完成 Jython 版 Burp 扩展
- 低误报正则 + 性能优化
- 可读、可复现、可展示的项目留痕

## 里程碑
- 环境配置与 Hello World
- HTTP 流量与 URL 打印
- 正则提取手机号
- 接入 Passive Scanner
- 正则扩展、误报控制、性能优化、高亮与配置化
- 重构注释、README 完善、发布与可选 BApp

## 使用方式
- Burp Suite > Extensions > Options 配置 Jython
- Extensions > Installed 加载本插件脚本




