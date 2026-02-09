from burp import IBurpExtender


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Hello Burp")
        self._callbacks.printOutput("Hello Burp")
