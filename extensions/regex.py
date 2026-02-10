# -*- coding: utf-8 -*-

from burp import IBurpExtender, IProxyListener
from java.io import PrintWriter
import re

# 最小手机号正则（中国 11 位，号段 13-19）
PHONE_RE = re.compile(r"1[3-9]\d{9}")

# 只处理文本类响应，避免二进制内容误判
TEXT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
)

class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        # 保存 Burp 的回调和工具对象
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # 输出到 Burp 
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # 设置扩展名称
        callbacks.setExtensionName("Week3 Regex Extract")

        # 注册代理监听，启用 processProxyMessage 回调
        callbacks.registerProxyListener(self)

        # 加载成功的提示
        self._stdout.println("[Week3] Regex extractor loaded")

    def processProxyMessage(self, messageIsRequest, message):
        # 只处理 response，跳过 request
        if messageIsRequest:
            return

        message_info = message.getMessageInfo()
        response = message_info.getResponse()
        if response is None:
            return

        # 解析响应，拿到 headers 和 body offset
        analyzed = self._helpers.analyzeResponse(response)
        headers = analyzed.getHeaders()

        # 不是文本类响应就跳过
        if not self._is_text_response(headers):
            return

        # 取出响应体 bytes
        body_offset = analyzed.getBodyOffset()
        body_bytes = response[body_offset:]

        # bytes -> str
        body = self._helpers.bytesToString(body_bytes)

        # 正则匹配手机号
        matches = PHONE_RE.findall(body)
        if matches:
            url = message_info.getUrl()
            for m in matches:
                # 输出命中结果
                self._stdout.println("[HIT] %s -> %s" % (url, m))

    def _is_text_response(self, headers):
        # 根据 Content-Type 判断是否文本
        for h in headers:
            if h.lower().startswith("content-type:"):
                ct = h.split(":", 1)[1].strip().lower()
                for t in TEXT_TYPES:
                    if ct.startswith(t):
                        return True
                return False
        # 没有 Content-Type 时默认不处理
        return False
