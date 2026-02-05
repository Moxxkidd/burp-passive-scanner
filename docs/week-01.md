# Week 01 - 环境配置与 Hello World

## 目标
- Burp 能识别 Jython 环境
- 扩展加载成功
- Output 中出现 "Hello Burp"

## 环境信息
- Burp Suite 版本：
- Jython 版本：2.7.x (Standalone JAR)
- 操作系统：macOS

## 步骤记录
1. 获取 `jython-standalone-2.7.x.jar` 并放置到固定路径
2. Burp > Extensions > Options 配置 Jython JAR 路径
3. 编写最小扩展脚本（仅 IBurpExtender + 输出日志）
4. Extensions > Installed 加载插件
5. Output 验证 "Hello Burp"

## 验收结果
- [ ] 扩展状态为 Loaded
- [ ] Output 出现 "Hello Burp"
- [ ] Errors 无报错

## 证据（截图/日志）
- Output 截图：`docs/assets/week-01-output.png`
- Errors 截图（如有）：`docs/assets/week-01-errors.png`

## 问题与解决
- 问题：
- 解决：

## 备注
- Week 1 只验证环境链路，不做任何 HTTP 逻辑

