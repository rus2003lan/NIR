from burp import IBurpExtender, IContextMenuFactory
from burp import IHttpRequestResponse
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener

from javax.swing import JMenuItem
from java.util import List, ArrayList

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request Data Extractor")
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)
        callbacks.registerScannerListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)
        print("Request Data Extractor Loaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            #headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            body = messageInfo.getRequest()[body_offset:]
            body = self._helpers.bytesToString(body)

            print("URL: {}".format(url))
            #print("Headers: {}".format(headers))
            print("Body: {}".format(body))
            print("="*50)
            print()

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Extract Request Data", actionPerformed=self.onClick)
        menu_list.add(menu_item)
        return menu_list

    def onClick(self, event):
        print("Extract Request Data Clicked")