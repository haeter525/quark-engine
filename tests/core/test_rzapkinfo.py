# TODO - 確認何者需要測試，何者不須

import pytest
import zipfile
import os

from quark.core.rzapkinfo import RizinImp
from quark.core.struct.methodobject import MethodObject


@pytest.fixture(scope="module")
def apk_path():
    return "/home/haeter/Documents/Quark/apk-malware-samples/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"


@pytest.fixture(scope="class")
def dex_file():
    APK_SOURCE = (
        "https://github.com/quark-engine/apk-malware-samples" "/raw/master/Ahmyth.apk"
    )
    APK_NAME = "/home/haeter/Documents/Quark/apk-malware-samples/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
    DEX_NAME = "classes.dex"

    with zipfile.ZipFile(APK_NAME, "r") as zip:
        zip.extract(DEX_NAME)

    yield DEX_NAME

    os.remove(DEX_NAME)
    os.remove(APK_NAME)


@pytest.fixture(scope="class")
def rizin(apk_path):
    return RizinImp(apk_path)


class TestRzApkinfo:
    def test_init(rizin):
        print(rizin)

    def test_convert_type_to_type_signature(self, rizin):
        raw_type_list = [
            "void",
            "boolean",
            "byte",
            "char",
            "short",
            "int",
            "long",
            "float",
            "double",
            "double[]",
            "String",
            "[String",
            "[[String",
            "String[][]",
            "android.accessibilityservice.AccessibilityServiceInfo",
            "[android.accessibilityservice.AccessibilityServiceInfo",
            "[[android.accessibilityservice.AccessibilityServiceInfo",
        ]

        type_sig_list = [
            rizin._convert_type_to_type_signature(raw_type)
            for raw_type in raw_type_list
        ]

        assert type_sig_list == [
            "V",
            "Z",
            "B",
            "C",
            "S",
            "I",
            "J",
            "F",
            "D",
            "[D",
            "Ljava/lang/String;",
            "[Ljava/lang/String;",
            "[[Ljava/lang/String;",
            "[[Ljava/lang/String;",
            "Landroid/accessibilityservice/AccessibilityServiceInfo;",
            "[Landroid/accessibilityservice/AccessibilityServiceInfo;",
            "[[Landroid/accessibilityservice/AccessibilityServiceInfo;",
        ]

    def test_get_methods_classified(self, rizin):
        method_dict = rizin._get_methods_classified(0)

        expected_method1 = MethodObject(
            class_name="Landroid/support/v4/accessibilityservice/AccessibilityServiceInfoCompatJellyBeanMr2;",
            name="getCapabilities",
            descriptor="(Landroid/accessibilityservice/AccessibilityServiceInfo;)I",
        )
        # {
        #     "name": "int getCapabilities(android.accessibilityservice.AccessibilityServiceInfo)",
        #     "demname": "int getCapabilities(android.accessibilityservice.AccessibilityServiceInfo)",
        #     "flagname": "sym.android.support.v4.accessibilityservice.AccessibilityServiceInfoCompatJellyBeanMr2_getCapabilities_2",
        #     "realname": "getCapabilities",
        #     "ordinal": 482,
        #     "bind": "GLOBAL",
        #     "size": 10,
        #     "type": "METH",
        #     "vaddr": 165932,
        #     "paddr": 165932,
        #     "is_imported": false
        # },

        # Descriptor - type C
        # Classname - Overload

        assert expected_method1.class_name in method_dict
        assert expected_method1 in method_dict[expected_method1.class_name]

        expected_method = MethodObject(
            class_name="Landroid/support/v4/accessibilityservice/AccessibilityServiceInfoCompat$AccessibilityServiceInfoVersionImpl;",
            name="getCapabilities",
            descriptor="(Landroid/accessibilityservice/AccessibilityServiceInfo;)I",
        )
        # {
        #     "name": "getCapabilities(Landroid/accessibilityservice/AccessibilityServiceInfo;)I",
        #     "flagname": "sym.android.support.v4.accessibilityservice.AccessibilityServiceInfoCompat_AccessibilityServiceInfoVersionImpl_getCapabilities",
        #     "realname": "getCapabilities",
        #     "ordinal": 459,
        #     "bind": "LOCAL",
        #     "size": 0,
        #     "type": "METH",
        #     "vaddr": 0,
        #     "paddr": 0,
        #     "is_imported": false
        # },

        # Descriptor - type A
        # Classname - Subclass

        assert expected_method.class_name in method_dict
        assert expected_method in method_dict[expected_method.class_name]

        expected_method = MethodObject(
            class_name="Ljava/util/concurrent/FutureTask;",
            name="get",
            descriptor="()Ljava/lang/Object;",
        )
        #   {
        #     "name": "imp.get()Ljava/lang/Object;",
        #     "flagname": "sym.imp.java.util.concurrent.FutureTask_get",
        #     "realname": "get",
        #     "ordinal": 0,
        #     "bind": "WEAK",
        #     "size": 0,
        #     "type": "METH",
        #     "vaddr": 0,
        #     "paddr": 0,
        #     "is_imported": true
        #   },

        # Descriptor - type A
        # Classname - Normal, Prefix
        assert expected_method.class_name in method_dict
        assert expected_method in method_dict[expected_method.class_name]

        expected_method = MethodObject(
            class_name="Lcom/example/google/service/WebServiceCalling;",
            name="Request",
            descriptor="(Landroid/os/Handler; Ljava/lang/String; Ljava/lang/String;)V",
        )
        #   {
        #     "name": "void Request(android.os.Handler, String, String)",
        #     "demname": "void Request(android.os.Handler, String, String)",
        #     "flagname": "sym.com.example.google.service.WebServiceCalling_Request",
        #     "realname": "Request",
        #     "ordinal": 5204,
        #     "bind": "LOCAL",
        #     "size": 98,
        #     "type": "METH",
        #     "vaddr": 366440,
        #     "paddr": 366440,
        #     "is_imported": false
        #   },

        assert expected_method.class_name in method_dict
        assert expected_method in method_dict[expected_method.class_name]

    def test_upperfunc(self, rizin):
        api = rizin.find_method("Landroid/support/v4/widget/SlidingPaneLayout$SlidingPanelLayoutImplJB;", "<init>", "()V")

        expect_function = MethodObject(
            "Landroid/support/v4/widget/SlidingPaneLayout;",
            "<clinit>",
            "()V",
        )
        #   {
        #     "from": 282476,
        #     "type": "CALL",
        #     "opcode": "invoke-direct {v1}, Landroid/support/v4/widget/SlidingPaneLayout$SlidingPanelLayoutImplJB;-><init>()V",
        #     "fcn_addr": 282436,
        #     "fcn_name": "method.static.constructor.Landroid_support_v4_widget_SlidingPaneLayout_._clinit___V",
        #     "flag": "entry63",
        #     "refname": "section.code.android.support.v4.widget.SlidingPaneLayout_SlidingPanelLayoutImplJB._init"
        #   }

        upper = list(rizin.upperfunc(api))[0]

        assert upper == expect_function

    def test_lowerfunc(self, rizin):
        method = rizin.find_method(
            "Lcom/example/google/service/WebServiceCalling;",
            "Send",
            "(Landroid/os/Handler; Ljava/lang/String;)V",
        )

        expect_method = rizin.find_method(
            "Landroid/support/v4/app/SuperNotCalledException;",
            "<init>",
            "(Ljava/lang/String;)V",
        )
        expect_offset = 16

        upper_methods = rizin.lowerfunc(method)

        assert (expect_method, expect_offset) in upper_methods
