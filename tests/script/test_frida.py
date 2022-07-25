# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
from unittest.mock import Mock, patch
from quark.core.struct.methodobject import MethodObject
from quark.script import Method
from quark.script.frida import Dispatcher, MethodHook, hookMethod


def testHookMethod():
    targetMethod = (
        "com.google.progress.WifiCheckTask.checkWifiCanOrNotConnectServer"
    )
    overloadFilter = "java.lang.String"
    watchArgs = True

    with patch("quark.script.frida._injectInitScript") as mockedInjectScript:
        mockedInjectScript.side_effect = Dispatcher

        with patch(
            "quark.script.frida.Dispatcher.hookMethod"
        ) as mockedHookMethod:
            callback = Mock()
            hookMethod(
                None, targetMethod, overloadFilter, callback, watchArgs=True
            )

            mockedInjectScript.assert_called_once()
            mockedHookMethod.assert_called_once_with(
                MethodHook(targetMethod, overloadFilter, callback), watchArgs
            )


def testHookMethodWithMethodObject():
    method = Method(
        None,
        MethodObject(
            "Lcom/google/progress/WifiCheckTask;",
            "checkWifiCanOrNotConnectServer",
            "(Ljava/lang/String;)Z",
        ),
    )

    with patch("quark.script.frida._injectInitScript") as mockedInjectScript:
        mockedInjectScript.side_effect = Dispatcher

        with patch(
            "quark.script.frida.Dispatcher.hookMethod"
        ) as mockedHookMethod:
            callback = Mock()
            hookMethod(None, method, callback=callback, watchArgs=True)

            mockedInjectScript.assert_called_once()
            mockedHookMethod.assert_called_once_with(
                MethodHook(
                    (
                        "com.google.progress.WifiCheckTask."
                        "checkWifiCanOrNotConnectServer"
                    ),
                    "java.lang.String",
                    callback,
                ),
                True,
            )


class TestDispatcher:
    @staticmethod
    def testHookMethod():
        mockedScript = Mock()
        mockedHookMethodImp = mockedScript.exports.hook_method

        dispatcher = Dispatcher(None)
        dispatcher.script = mockedScript

        targetMethod = (
            "com.google.progress.WifiCheckTask.checkWifiCanOrNotConnectServer"
        )
        overloadFilter = "java.lang.String"
        callback = Mock()
        watchArgs = True

        methodHook = MethodHook(targetMethod, overloadFilter, callback)

        dispatcher.hookMethod(methodHook, watchArgs)

        mockedHookMethodImp.assert_called_once_with(
            targetMethod, overloadFilter, watchArgs
        )
