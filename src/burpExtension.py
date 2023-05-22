"""AutoParamScanner."""

from __future__ import annotations

import json

from burp import (
    IBurpExtender,
    IBurpExtenderCallbacks,
    IHttpListener,
    IHttpRequestResponse,
)
from burpHelper import HttpMessage, logger
from paramScanner import ParamScanner


class BurpExtender(IBurpExtender, IHttpListener):
    """Interface for Burp to call to extension."""

    def registerExtenderCallbacks(self: BurpExtender, callbacks: IBurpExtenderCallbacks) -> None:
        """
        `registerExtenderCallbacks` is invoked when the extension is loaded.

        :param callbacks:
            This interface is used by Burp Suite to pass to extensions a set of callback
            methods that can be used by extensions to perform various actions within Burp.
        """

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        try:
            with open("../config/rule.json") as f:  # trunk-ignore(ruff/PTH123)
                config = json.load(f)

            logger.info("Config file exists")

            self._paramScanner = ParamScanner.fromConfigFile(config)

        except FileNotFoundError:
            self._paramScanner = ParamScanner(issues=set())
        except json.JSONDecodeError:
            logger.error("Config file is not in JSON format")
            return
        except TypeError:
            logger.error("Config file structure not correct. It must be a list of defined issues")
            return
        else:
            logger.info("Config file loaded successfully")

        self._callbacks.setExtensionName("AutoParamScanner")
        self._callbacks.registerHttpListener(self)

        print("Extension load successful!")
        print("Author: Meterglost")

        return

    def processHttpMessage(self: BurpExtender, tool: int, is_request: bool, message: IHttpRequestResponse) -> None:
        """
        `processHttpMessage` is invoked when an HTTP request is about to be issued, and when an HTTP response has been received.

        :param tool:
            A flag indicating the Burp tool that issued the request.
            Burp tool flags are defined in the `IBurpExtenderCallbacks` interface.

        :param is_request:
            Flags whether the method is being invoked for a request or response.

        :param message:
            Details of the request / response to be processed.
            Extensions can call the setter methods on this object to update the current message and so modify Burp's behavior.
        """

        if is_request:
            return

        if tool not in [
            self._callbacks.TOOL_TARGET,
            self._callbacks.TOOL_PROXY,
        ]:
            return

        self._paramScanner.check(HttpMessage(message, self._callbacks, self._helpers))
