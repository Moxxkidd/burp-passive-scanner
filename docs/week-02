# Week 02 HTTP流量

## 目标
- 理解 request/response 区分
- 只处理 response 阶段
- 访问已知 URL 时打印该 URL 

## 日期
- 2026-02-10

##环境
- 虚拟环境路径：/Users/an/Documents/burp suite passive scanner/extensions/.venv
- 脚本路径：intercept.py

## 步骤
1.由于当前用的全局 Python 环境里有旧的 x86_64 依赖，只能用创建一个虚拟环境的 mitmproxy，安装mitmproxy，
取得证书，完成脚本intercept.py 
2.启动 mitmdump 并加载 intercept.py
3.配置代理为127.0.0.1 端口8080
4.访问 http://mitm.it 下载并在钥匙串中设为“始终信任”
5.访问任意HTTPS URL
6.终端看到过滤后的只带URL的输出

## 结果
只在 response 阶段打印 URL
已知 URL 能稳定输出
mitmproxy 能正常拦截 HTTPS 流量

## 证据
见asset里的截图mitmdump1
