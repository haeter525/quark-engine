from quark.script.objection import Objection

SAMPLE_PATH = "VulnDroid.apk"
TARGET_METHOD = [
    "Lcom/Mihir/VulnDroid/localstorage/AESUtils;",
    "toByte",
    "(Ljava/lang/String;)LB",
]

obj = Objection("127.0.0.1:8888")

obj.execute(
    TARGET_METHOD,
    ["BC8596B3B8EEB6EC62B524CE05DE3B0D"],
)

print("\nSee the results in Objection's terminal.")
