from mitmproxy import http

def get_url(flow: http.HTTPFlow) -> str:
    # helper：从 response 对应的 request 中拿 URL
    return flow.request.pretty_url

class OnlyResponse:
    def response(self, flow: http.HTTPFlow):
        # 明确只在 response 阶段处理
        if flow.response is None:
            return
        url = get_url(flow)
        print(f"URL: {url}", flush=True)


addons = [OnlyResponse()]
