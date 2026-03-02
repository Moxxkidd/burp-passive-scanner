# -*- coding: utf-8 -*-
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
import re
import time

# ---------- Filters ----------
IGNORE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".zip", ".pdf"
)

ALLOW_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "application/x-javascript",
)

MAX_BODY_BYTES = 1000000      # 1MB
MAX_HITS_PER_RESPONSE = 5
LOG_EVERY = 200               # 每处理 200 次打印统计

# ---------- ID card validation (CN Mainland) ----------
PROVINCE_CODES = set([
    "11","12","13","14","15",
    "21","22","23",
    "31","32","33","34","35","36","37",
    "41","42","43","44","45","46",
    "50","51","52","53","54",
    "61","62","63","64","65"
])

WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
CHECKMAP = "10X98765432"

def idcard_valid(s):
    s = s.upper()
    if len(s) != 18 or not s[:17].isdigit():
        return False

    if s[:2] not in PROVINCE_CODES:
        return False

    y = int(s[6:10])
    m = int(s[10:12])
    d = int(s[12:14])
    if y < 1900 or y > 2099:
        return False
    if m < 1 or m > 12:
        return False
    mdays = [31,28,31,30,31,30,31,31,30,31,30,31]
    if (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0):
        mdays[1] = 29
    if d < 1 or d > mdays[m-1]:
        return False

    total = 0
    for i in range(17):
        total += int(s[i]) * WEIGHTS[i]
    return CHECKMAP[total % 11] == s[-1]

def ip_is_private(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except:
        return False
    for n in nums:
        if n < 0 or n > 255:
            return False
    if nums[0] == 10:
        return True
    if nums[0] == 127:
        return True
    if nums[0] == 192 and nums[1] == 168:
        return True
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return True
    return False

PATTERNS = [
    {
        "name": "ID Card (CN Mainland)",
        "regex": re.compile(r"\b\d{17}[\dXx]\b"),
        "validator": idcard_valid,
        "severity": "Medium",
        "confidence": "Firm",
    },
    {
        "name": "Private IP",
        "regex": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "validator": ip_is_private,
        "severity": "Low",
        "confidence": "Firm",
    },
    {
        "name": "AWS Access Key",
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "validator": None,
        "severity": "High",
        "confidence": "Tentative",
    },
    {
        "name": "Google API Key",
        "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "validator": None,
        "severity": "High",
        "confidence": "Tentative",
    },
    {
        "name": "GitHub Token",
        "regex": re.compile(r"\bgh[pous]_[0-9A-Za-z]{36}\b"),
        "validator": None,
        "severity": "High",
        "confidence": "Tentative",
    },
    {
        "name": "Slack Token",
        "regex": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "validator": None,
        "severity": "High",
        "confidence": "Tentative",
    },
    {
        "name": "Stripe Secret",
        "regex": re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
        "validator": None,
        "severity": "High",
        "confidence": "Tentative",
    },
]

def url_has_ignored_ext(url):
    if url is None:
        return False
    try:
        path = url.getPath().lower()
    except:
        return False
    for ext in IGNORE_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stats = {
            "scanned": 0,
            "skip_ext": 0,
            "skip_type": 0,
            "skip_size": 0,
            "hits": 0,
        }
        callbacks.setExtensionName("Filters & Perf")
        callbacks.registerScannerCheck(self)
        self._stdout.println("Scanner loaded")

    def doPassiveScan(self, baseRequestResponse):
        self._stats["scanned"] += 1

        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        if url_has_ignored_ext(url):
            self._stats["skip_ext"] += 1
            self._maybe_log()
            return None

        resp = baseRequestResponse.getResponse()
        if resp is None:
            self._maybe_log()
            return None

        analyzed = self._helpers.analyzeResponse(resp)
        headers = analyzed.getHeaders()
        if not self._is_text_response(headers):
            self._stats["skip_type"] += 1
            self._maybe_log()
            return None

        body_offset = analyzed.getBodyOffset()
        body_bytes = resp[body_offset:]
        if len(body_bytes) > MAX_BODY_BYTES:
            self._stats["skip_size"] += 1
            self._maybe_log()
            return None

        body = self._helpers.bytesToString(body_bytes)

        issues = []
        hit_count = 0
        for p in PATTERNS:
            for m in p["regex"].finditer(body):
                value = m.group(0)
                if p["validator"] and not p["validator"](value):
                    continue
                issues.append(SensitiveIssue(baseRequestResponse, url, p, value))
                hit_count += 1
                self._stats["hits"] += 1
                if hit_count >= MAX_HITS_PER_RESPONSE:
                    break
            if hit_count >= MAX_HITS_PER_RESPONSE:
                break

        self._maybe_log()
        if not issues:
            return None
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
                for t in ALLOW_TYPES:
                    if ct.startswith(t):
                        return True
                return False
        return False

    def _maybe_log(self):
        if self._stats["scanned"] % LOG_EVERY == 0:
            self._stdout.println(
                "scanned=%d skip_ext=%d skip_type=%d skip_size=%d hits=%d"
                % (self._stats["scanned"], self._stats["skip_ext"],
                   self._stats["skip_type"], self._stats["skip_size"], self._stats["hits"])
            )

class SensitiveIssue(IScanIssue):
    def __init__(self, baseRequestResponse, url, pattern, value):
        self._base = baseRequestResponse
        self._url = url
        self._pattern = pattern
        self._value = value

    def getUrl(self): return self._url
    def getIssueName(self): return "Sensitive Info: %s" % self._pattern["name"]
    def getIssueType(self): return 0
    def getSeverity(self): return self._pattern["severity"]
    def getConfidence(self): return self._pattern["confidence"]
    def getIssueBackground(self): return "Response contains a string matching a sensitive pattern."
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return "Matched value: %s" % self._value
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self._base]
    def getHttpService(self): return self._base.getHttpService()
