"""."""

from __future__ import annotations

from array import array
from typing import Literal

import java
from burp import (
    IBurpExtenderCallbacks,
    IExtensionHelpers,
    IHttpRequestResponse,
    IHttpService,
    IParameter,
    IRequestInfo,
    IResponseInfo,
    IScanIssue,
)


class HttpRequest:
    """."""

    raw: array
    info: IRequestInfo
    headers: list[str]
    body: array

    def __init__(self: HttpRequest, request: array, helper: IExtensionHelpers) -> None:
        """."""

        self._helper = helper
        self.info = helper.analyzeRequest(request)

        self.raw = request
        self.headers = self.info.getHeaders()
        self.body = request[self.info.getBodyOffset() :]

    def getParameter(self: HttpRequest, name: str) -> IParameter | None:
        """."""

        for param in self.info.getParameters():
            if param.getName() == name:
                return param
        return None

    def setAllParameters(self: HttpRequest, val: str) -> None:
        """Set all parameters to the given value."""

        for param in self.info.getParameters():
            self.raw = self._helper.updateParameter(self.raw, self._helper.buildParameter(param.getName(), val, param.getType()))
        self.__init__(self.raw, self._helper)

    def addParameter(self: HttpRequest, name: str, val: str) -> None:
        """Add new parameter."""

        self.raw = self._helper.addParameter(self.raw, self._helper.buildParameter(name, val, "String"))
        self.__init__(self.raw, self._helper)

    def removeParameter(self: HttpRequest, name: str) -> None:
        """Remove all parameters with the given name."""

        for param in self.info.getParameters():
            if param.getName() == name:
                self.raw = self._helper.removeParameter(self.raw, param)
        self.__init__(self.raw, self._helper)


class HttpResponse:
    """."""

    raw: array
    info: IResponseInfo
    headers: list[str]
    body: array

    def __init__(self: HttpResponse, response: array, helper: IExtensionHelpers) -> None:
        """."""

        self._helper = helper
        self.info = helper.analyzeResponse(response)

        self.raw = response
        self.headers = self.info.getHeaders()
        self.body = response[self.info.getBodyOffset() :]


class HttpMessage:
    """."""

    def __init__(
        self: HttpMessage,
        message: IHttpRequestResponse,
        callback: IBurpExtenderCallbacks,
        helper: IExtensionHelpers,
    ) -> None:
        """."""

        self._callback = callback
        self._helper = helper

        self.msg_obj = message
        self.service = message.getHttpService()
        self.url = self._helper.analyzeRequest(self.msg_obj).getUrl()

        self.request = HttpRequest(message.getRequest(), helper)
        self.response = HttpResponse(message.getResponse(), helper)

    def reload(self: HttpMessage) -> None:
        """Request will be sent and response will be updated."""

        self.request.headers = [header for header in self.request.headers if not header.startswith("If-Modified-Since:")]
        self.request.headers = [header for header in self.request.headers if not header.startswith("If-None-Match:")]
        self.request.raw = array("b", ("\r\n".join(self.request.headers) + "\r\n\r\n").encode()) + self.request.body
        self.__init__(self._callback.makeHttpRequest(self.service, self.request.raw), self._callback, self._helper)
        self._helper.buildHttpMessage


class ExtensionIssue(IScanIssue):
    """."""

    def __init__(
        self: ExtensionIssue,
        host: IHttpService,
        url: str,
        msg: list[IHttpRequestResponse],
        name: str,
        detail: str,
        severity: Literal["High", "Medium", "Low", "Information", "False positive"],
        confidence: Literal["Certain", "Firm", "Tentative"],
    ) -> None:
        """."""
        self._host = host
        self._url = url
        self._msg = msg
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self: ExtensionIssue) -> java:
        """Returns the URL for which the issue was generated."""

        return self._url

    def getIssueName(self: ExtensionIssue) -> str:
        """Returns the name of the issue type (e.g. "SQL injection")."""

        return self._name

    def getIssueType(self: ExtensionIssue) -> int:
        """."""
        return 0

    def getSeverity(self: ExtensionIssue) -> Literal["High", "Medium", "Low", "Information", "False positive"]:
        """Returns the issue severity level."""

        return self._severity

    def getConfidence(self: ExtensionIssue) -> Literal["Certain", "Firm", "Tentative"]:
        """Returns the issue confidence level."""

        return self._confidence

    def getIssueBackground(self: ExtensionIssue) -> str | None:
        """Returns a background description for this type of issue, or `null` if none applies. A limited set of HTML tags may be used."""

        pass

    def getRemediationBackground(self: ExtensionIssue) -> str | None:
        """Returns a background description of the remediation for this type of issue, or `null` if none applies. A limited set of HTML tags may be used."""

        pass

    def getIssueDetail(self: ExtensionIssue) -> str:
        """."""

        return self._detail

    def getRemediationDetail(self: ExtensionIssue) -> str | None:
        """Returns detailed information about the remediation for this specific instance of the issue, or `null` if none applies. A limited set of HTML tags may be used."""

        pass

    def getHttpMessages(self: ExtensionIssue) -> list[IHttpRequestResponse]:
        """Returns the HTTP messages on the basis of which the issue was generated."""

        return self._msg

    def getHttpService(self: ExtensionIssue) -> IHttpService:
        """Returns the HTTP service for which the issue was generated."""

        return self._host


class Logger:
    """."""

    def __init__(self: Logger) -> None:
        """."""
        pass

    def info(self: Logger, msg: str) -> None:
        """."""
        print("[Info] " + msg)

    def warn(self: Logger, msg: str) -> None:
        """."""
        print("[Warn] " + msg)

    def error(self: Logger, msg: str) -> None:
        """."""
        print("[Error] " + msg)


logger = Logger()
