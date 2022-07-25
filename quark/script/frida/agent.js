// -*- coding: utf-8 -*-
// This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
// See the file 'LICENSE' for copying permission.

/*global Java, send, rpc*/
function watchMethodImpl(method, methodName, overloadFilter, printArgs) {
    const argumentTypes = method.argumentTypes.map((arg) => arg.className);
    if (argumentTypes.join(",") !== overloadFilter) {
        return null;
    }

    method.implementation = function () {
        let result = {
            "type": "captureInvocation",
            "callee": [
                methodName, overloadFilter
            ]
        };

        if (printArgs && argumentTypes.length > 0) {
            // Arguments
            const argumentValues = [];
            for (const arg of arguments) {
                argumentValues.push((arg || "(none)").toString());
            }

            result["paramValues"] = argumentValues;
        }

        const returnValue = method.apply(this, arguments);
        send(JSON.stringify(result));

        return returnValue;
    };

    return null;
}

function quarkScriptWatchMethod(methodName, overloadFilter, printArgs) {
    if (!methodName) {
        return;
    }

    const lastsperatorIndex = methodName.lastIndexOf(".");
    const clazzName = methodName.substring(0, lastsperatorIndex);
    const methodName = methodName.substring(lastsperatorIndex + 1);

    if (overloadFilter == null) {
        overloadFilter = "";
    }

    Java.perform(() => {
        const targetClazz = Java.use(clazzName);
        if (typeof targetClazz[`${methodName}`] === "undefined") {
            const result = {
                "type": "HookFailed",
                "callee": [
                    methodName, overloadFilter
                ]
            };

            send(JSON.stringify(result));
            return;
        }

        targetClazz[`${methodName}`].overloads.forEach((method) =>
            watchMethodImpl(method, methodName, overloadFilter, printArgs)
        );
    });
}

rpc.exports["hookMethod"] = (method, overloadFilter, printArgs) => quarkScriptWatchMethod(method, overloadFilter, printArgs);