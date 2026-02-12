# -*- coding: utf-8 -*-
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
import re

PHONE_RE = re.compile(r"1[3-9]\d{9}")
TEXT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
)

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName("Week4 Passive Scanner")
        callbacks.registerScannerCheck(self)
        self._stdout.println("[Week4] Scanner loaded")

    def doPassiveScan(self, baseRequestResponse):
        resp = baseRequestResponse.getResponse()
        if resp is None:
            return None

        analyzed = self._helpers.analyzeResponse(resp)
        headers = analyzed.getHeaders()
        if not self._is_text_response(headers):
            return None

        body_offset = analyzed.getBodyOffset()
        body_bytes = resp[body_offset:]
        body = self._helpers.bytesToString(body_bytes)

        matches = PHONE_RE.findall(body)
        if not matches:
            return None

        issues = []
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        for m in matches:
            issues.append(SensitiveInfoIssue(baseRequestResponse, url, m))
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        return 0

    def _is_text_response(self, headers):
        for h in headers:
            if h.lower().startswith("content-type:"):
                ct = h.split(":", 1)[1].strip().lower()
                for t in TEXT_TYPES:
                    if ct.startswith(t):
                        return True
                return False
        return False

class SensitiveInfoIssue(IScanIssue):
    def __init__(self, baseRequestResponse, url, match):
        self._base = baseRequestResponse
        self._url = url
        self._match = match

    def getUrl(self): return self._url
    def getIssueName(self): return "Possible Phone Number"
    def getIssueType(self): return 0
    def getSeverity(self): return "Information"
    def getConfidence(self): return "Tentative"
    def getIssueBackground(self): return "Response contains a string matching phone number pattern."
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return "Matched value: %s" % self._match
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self._base]
    def getHttpService(self): return self._base.getHttpService()
