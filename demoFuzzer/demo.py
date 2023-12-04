from quark.script.objection import Objection

SAMPLE_PATH = "VulnDroid.apk"
TARGET_METHOD = [
    "Lcom/Mihir/VulnDroid/localstorage/AESUtils;",
    "encrypt",
    "(Ljava/lang/String;)Ljava/lang/String;",
]

obj = Objection("127.0.0.1:8888")

obj.execute(
    TARGET_METHOD,
    ["Test String"],
)

print("\nSee the results in Objection's terminal.")
