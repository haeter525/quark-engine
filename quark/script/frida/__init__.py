# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from dataclasses import dataclass
import functools
import json
from typing import Callable, List, Union

from frida.core import Session as FridaSession
import pkg_resources
from quark.script import Method
from quark.script.objection import convertMethodToString


class Dispatcher:
    def __init__(self, fridaSession: FridaSession) -> None:
        self.fridaSession = fridaSession
        self.methodHookDict = {}

    def hookMethod(
        self, methodHook: "MethodHook", watchParameters: bool = False
    ):
        """Hook the target method with the Frida session.

        :param methodHook: MethodHook object that describes the method to hook
        :param watchParameters: Return Args information if True, defaults to
         False
        """
        key = (methodHook.methodCallee, methodHook.overloadFilter)

        self.methodHookDict[key] = methodHook.callback
        self.script.exports.hook_method(
            methodHook.methodCallee, methodHook.overloadFilter, watchParameters
        )

    def _on_message(self, message: dict, _):
        if message["type"] == "error":
            print(message["description"])
            return

        payload = message["payload"]
        payload = json.loads(payload)

        payloadType = payload.get("type", None)

        if payloadType == "captureInvocation" and "callee" in payload:
            methodCallee = tuple(payload["callee"])
            paramValueList = payload["paramValues"]

            self.methodHookDict[methodCallee](paramValueList)

        elif payloadType == "HookFailed":
            methodCallee = payload["callee"]
            del self.methodHookDict[methodCallee]


@functools.lru_cache
def _injectInitScript(fridaSession: FridaSession) -> Dispatcher:
    dispatcher = Dispatcher(fridaSession)

    jsCodePath = pkg_resources.resource_filename(
        "quark.script.frida", "agent.js"
    )
    with open(jsCodePath, "r") as jsCode:
        script = dispatcher.fridaSession.create_script(jsCode.read())
        script.on("message", dispatcher._on_message)
        script.load()

    dispatcher.script = script

    return dispatcher


@dataclass
class MethodHook:
    methodCallee: str
    overloadFilter: str
    callback: Callable[[List[str]], None]


def hookMethod(
    fridaSession: FridaSession,
    method: Union[Method, str],
    overloadFilter: str = "",
    callback: Callable[[List[str]], None] = None,
    watchArgs: bool = False,
) -> None:
    """Hook the target method with the Frida session.

    :param fridaSession: frida session used to hook the target API.
    :param method: the target API
    :param overloadFilter: string that holds the args used by the target API,
     defaults to ""
    :param callback: function that will be executed when the API is called,
     defaults to None
    :param watchArgs: Return Args information if True, defaults to False
    :return: None
    """
    if isinstance(method, Method):
        method, overloadFilter = convertMethodToString(method)

    dispatcher = _injectInitScript(fridaSession)
    methodHook = MethodHook(method, overloadFilter, callback)

    dispatcher.hookMethod(methodHook, watchArgs)

    return methodHook
