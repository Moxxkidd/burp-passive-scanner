# Burp Passive Sensitive Scanner (Jython)

Burp Suite 被动扫描插件，用于在响应中低误报识别敏感信息（手机号、身份证、API Key、内网 IP 等），并在 Burp Issues 中给出告警与高亮定位。

## 目标
- 最小成本完成 Jython 版 Burp 扩展
- 低误报正则 + 性能优化
- 可读、可复现、可展示的项目留痕

## 里程碑（计划）
- Week 1: 环境配置与 Hello World
- Week 2: 解析 HTTP 流量与 URL 打印
- Week 3: 正则提取手机号
- Week 4: 接入 Passive Scanner
- Week 5-8: 正则扩展、误报控制、性能优化、高亮与配置化
- Week 9-12: 重构注释、README 完善、发布与可选 BApp

## 使用方式（待补充）
- Burp Suite > Extensions > Options 配置 Jython
- Extensions > Installed 加载本插件脚本

## 留痕与记录
- 进度记录见 `PROGRESS.md`
- 周报记录见 `docs/`
- 版本记录见 `CHANGELOG.md`

## 仓库说明
- 这是私有仓库（GitHub: Moxxkidd），用于长期留痕与简历展示

