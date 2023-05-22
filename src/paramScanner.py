"""."""

from __future__ import annotations

from typing import Any, Literal, get_args

from burpHelper import ExtensionIssue, HttpMessage, logger

RuleInpType = Literal["replace"]
RuleOutType = Literal["exact", "contain"]
IssueType = Literal["all", "any"]


class ParamScannerRuleInput:
    """."""

    inptype: RuleInpType
    inpvalue: str

    def __init__(self: ParamScannerRuleInput, inptype: RuleInpType, inpvalue: str) -> None:
        """."""

        if not isinstance(inptype, str):
            raise TypeError
        if inptype not in get_args(RuleInpType):
            raise ValueError

        self.inptype = inptype

        if not isinstance(inpvalue, str):
            raise TypeError

        self.inpvalue = inpvalue

    @staticmethod
    def fromDict(inp: dict) -> ParamScannerRuleInput:
        """."""

        if not isinstance(inp, dict):
            raise TypeError

        if any(
            (
                "type" not in inp,
                "value" not in inp,
            )
        ):
            raise ValueError

        if any(
            (
                not isinstance(inp["type"], str),
                not isinstance(inp["value"], str),
            )
        ):
            raise TypeError

        if inp["type"] not in ["replace"]:
            raise ValueError

        return ParamScannerRuleInput(inp["type"], inp["value"])


class ParamScannerRuleOutput:
    """."""

    outtype: RuleOutType
    outvalue: str

    def __init__(self: ParamScannerRuleInput, outtype: RuleOutType, outvalue: str) -> None:
        """."""

        if not isinstance(outtype, str):
            raise TypeError

        self.outtype = outtype

        if not isinstance(outvalue, str):
            raise TypeError

        self.outvalue = outvalue

    @staticmethod
    def fromDict(out: dict) -> ParamScannerRuleOutput:
        """."""

        if not isinstance(out, dict):
            raise TypeError

        if "type" not in out:
            raise ValueError
        if "value" not in out:
            raise ValueError

        if not isinstance(out["type"], str):
            raise TypeError
        if not isinstance(out["value"], str):
            raise TypeError

        if out["type"] not in ["exact", "contain"]:
            raise ValueError

        return ParamScannerRuleOutput(out["type"], out["value"])


class ParamScannerRule:
    """."""

    inp: ParamScannerRuleInput
    out: ParamScannerRuleOutput
    enable: bool

    def __init__(self: ParamScannerRule, inp: ParamScannerRuleInput, out: ParamScannerRuleOutput, enable: bool) -> None:
        """."""

        if not isinstance(inp, ParamScannerRuleInput):
            raise TypeError

        self.inp = inp

        if not isinstance(out, ParamScannerRuleOutput):
            raise TypeError

        self.out = out

        if not isinstance(enable, bool):
            raise TypeError

        self.enable = enable

    @staticmethod
    def fromDict(rule: dict) -> ParamScannerRule:
        """."""

        if not isinstance(rule, dict):
            raise TypeError

        if any(
            (
                "input" not in rule,
                "output" not in rule,
                "enable" not in rule,
            )
        ):
            raise ValueError

        inp = ParamScannerRuleInput.fromDict(rule["input"])
        out = ParamScannerRuleOutput.fromDict(rule["output"])
        enable = rule["enable"]

        return ParamScannerRule(inp, out, enable)

    def check(self: ParamScannerRule, message: HttpMessage) -> bool:
        """."""

        if self.inp.inptype == "replace":
            message.request.setAllParameters(self.inp.inpvalue)

        message.reload()

        if self.out.outtype == "exact":
            if message.response.body.tobytes().decode() == self.out.outvalue:
                return True
        elif self.out.outtype == "contain":
            if message.response.body.tobytes().decode().find(self.out.outvalue) != -1:
                return True

        return False


class ParamScannerIssue:
    """."""

    name: str
    desc: str
    rules: set[ParamScannerRule]
    checktype: IssueType
    enable: bool

    def __init__(
        self: ParamScannerIssue,
        name: str,
        desc: str,
        rules: set[ParamScannerRule],
        checktype: IssueType,
        enable: bool,
    ) -> None:
        """."""

        if not isinstance(name, str):
            raise TypeError

        self.name = name

        if not isinstance(desc, str):
            raise TypeError

        self.desc = desc

        if not isinstance(rules, set):
            raise TypeError

        self.rules = rules

        if not isinstance(checktype, str):
            raise TypeError

        self.checktype = checktype

        if not isinstance(enable, bool):
            raise TypeError

        self.enable = enable

    @staticmethod
    def fromDict(issue: dict) -> ParamScannerIssue:
        """."""

        if not isinstance(issue, dict):
            raise TypeError("Not an instance of dict")

        if any(
            (
                "name" not in issue,
                "desc" not in issue,
                "rule" not in issue,
                "type" not in issue,
                "enable" not in issue,
            )
        ):
            raise ValueError

        if any(
            (
                not isinstance(issue["name"], str),
                not isinstance(issue["desc"], str),
                not isinstance(issue["rule"], list),
                not isinstance(issue["type"], str),
                not isinstance(issue["enable"], bool),
            )
        ):
            raise TypeError

        newissue = ParamScannerIssue(issue["name"], issue["desc"], set(), issue["type"], issue["enable"])

        for rule in issue["rule"]:
            newissue.addRule(rule)

        return newissue

    def addRule(self: ParamScannerIssue, rule: ParamScannerRule) -> None:
        """Add new issue definition."""

        try:
            if not isinstance(rule, ParamScannerRule):
                rule = ParamScannerRule.fromDict(rule)
            self.rules.add(rule)
        except (ValueError, TypeError) as err:
            logger.error("ParamScannerRule" + repr(self.name) + " : " + repr(err))

    def check(self: ParamScannerIssue, message: HttpMessage) -> None:
        """Check if any rule of issue is match."""

        if self.checktype == "any":
            for rule in self.rules:
                if rule.enable and rule.check(message):
                    break
            else:
                return
        elif self.checktype == "all":
            for rule in self.rules:
                if rule.enable and not rule.check(message):
                    return

        message._callback.addScanIssue(
            ExtensionIssue(
                message.service,
                message.url,
                [message.msg_obj],
                self.name,
                self.desc,
                "Medium",
                "Firm",
            )
        )


class ParamScanner:
    """."""

    issues: set[ParamScannerIssue]

    def __init__(self: ParamScanner, issues: set[ParamScannerIssue]) -> None:
        """."""

        if not isinstance(issues, set):
            raise TypeError

        self.issues = issues

    @staticmethod
    def fromConfigFile(config: list) -> ParamScanner:
        """."""

        if not isinstance(config, list):
            raise TypeError

        newscanner = ParamScanner(set())

        for issue in config:
            newscanner.addIssue(issue)

        return newscanner

    def addIssue(self: ParamScanner, issue: ParamScannerIssue | dict | Any) -> None:
        """."""

        try:
            if not isinstance(issue, ParamScannerIssue):
                issue = ParamScannerIssue.fromDict(issue)
            self.issues.add(issue)
        except (ValueError, TypeError) as err:
            logger.error("ParamScannerIssue" + " : " + repr(err))

    def check(self: ParamScanner, message: HttpMessage) -> bool:
        """Check if any issue is found."""

        for issue in self.issues:
            if issue.enable:
                issue.check(message)
