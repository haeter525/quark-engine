// -*- coding: utf-8 -*-
// This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
// See the file 'LICENSE' for copying permission.

/*global Java, send, rpc*/
function quarkScriptWatchMethodImpl(methodObj, fullNameStr, overloadFilter, printArgs) {
    const argumentTypes = methodObj.argumentTypes.map((arg) => arg.className);
    if (argumentTypes.join(",") === overloadFilter) {
        methodObj.implementation = function () {
            let result = {
                "type": "captureInvocation",
                "callee": [fullNameStr, overloadFilter],
                "paramValues": []
            };

            if (printArgs && argumentTypes.length > 0) {
                // Arguments
                for (const arg of arguments) {
                    result["paramValues"].push((arg || "(none)").toString());
                }
            }

            send(JSON.stringify(result));
            return methodObj.apply(this, arguments);
        };
    }

    return null;
}

function quarkScriptWatchMethod(fullNameStr, overloadFilter, printArgs) {
    if ( fullNameStr == null ) {
        return;
    }

    const lastsperatorIndex = fullNameStr.lastIndexOf(".");
    const clazzName = fullNameStr.substring(0, lastsperatorIndex);
    const methodName = fullNameStr.substring(lastsperatorIndex + 1);

    if (overloadFilter == null) {
        overloadFilter = "";
    }

    Java.perform(() => {
        const targetClazz = Java.use(clazzName);
        if (typeof targetClazz[`${methodName}`] === "undefined") {
            const result = {
                "type": "HookFailed",
                "callee": [
                    fullNameStr, overloadFilter
                ]
            };

            send(JSON.stringify(result));
            return;
        }

        targetClazz[`${methodName}`].overloads.forEach((m) =>
            quarkScriptWatchMethodImpl(m, fullNameStr, overloadFilter, printArgs)
        );
    });
}

rpc.exports["hookMethod"] = (methodName, overloadFilter, printArgs) => quarkScriptWatchMethod(methodName, overloadFilter, printArgs);