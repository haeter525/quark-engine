# -*- coding: utf-8 -*-
# This file is part of Quark-Engine:
# https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import re
import functools
from collections import defaultdict
from os import PathLike
import re
from typing import Dict, Iterator, List, Optional, Set, Union

from shuriken import Dex, Apk
from shuriken.dex import hdvmmethodanalysis_t

from quark.core.interface.baseapkinfo import BaseApkinfo, XMLElement
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.tools import descriptor_to_androguard_format
from quark.utils.tools import remove_dup_list


class ShurikenImp(BaseApkinfo):
    """Information about apk based on Shuriken-Analyzer analysis"""

    __slots__ = ("apk", "dalvikvmformat", "analysis")

    def __init__(self, apk_filepath: Union[str, PathLike]):
        super().__init__(apk_filepath, "shuriken")

        if self.ret_type == "APK":
            self.analysis = Apk(apk_filepath, create_xrefs=True)
        elif self.ret_type == "DEX":
            self.analysis = Dex(apk_filepath)
            self.analysis.disassemble_dex()
            self.analysis.create_dex_analysis(1)
            self.analysis.analyze_classes()
        else:
            raise ValueError("Unsupported File type.")

    @property
    def permissions(self) -> List[str]:
        pass

    @property
    def application(self) -> XMLElement:
        """Get the application element from the manifest file.

        :return: an application element
        """
        pass

    @property
    def activities(self) -> List[XMLElement]:
        pass

    @property
    def receivers(self) -> List[XMLElement]:
        """
        Return all receivers from the given APK.

        :return: a list of all receivers
        """
        pass

    @property
    def android_apis(self) -> Set[MethodObject]:
        if self.ret_type == "APK":
            allMethods = list(self.all_methods)

            androidApis = (
                method for method in allMethods if method.cache.is_android_api
            )

            return set(androidApis)

        elif self.ret_type == "DEX":
            methods = set()
            for i in range(self.analysis.get_number_of_classes()):
                rawClass = self.analysis.get_class_by_id(i)
                className = rawClass.class_name.decode()
                classAnalysis = self.analysis.get_analyzed_class(className)
                for j in range(classAnalysis.n_of_methods):
                    methodAnalysis = classAnalysis.methods[j].contents
                    if methodAnalysis.is_android_api:
                        methods.add(
                            self._convert_to_method_object(methodAnalysis)
                        )
            return methods

        else:
            raise ValueError("Unsupported File type.")

    @property
    def custom_methods(self) -> Set[MethodObject]:
        if self.ret_type == "APK":
            allMethods = list(self.all_methods)

            customMethods = (
                method for method in allMethods if not method.cache.external
            )

            return set(customMethods)

        elif self.ret_type == "DEX":
            methods = set()
            for i in range(self.analysis.get_number_of_classes()):
                rawClass = self.analysis.get_class_by_id(i)
                className = rawClass.class_name.decode()
                classAnalysis = self.analysis.get_analyzed_class(className)
                for j in range(classAnalysis.n_of_methods):
                    methodAnalysis = classAnalysis.methods[j].contents
                    if methodAnalysis.external:
                        methods.add(
                            self._convert_to_method_object(methodAnalysis)
                        )
            return methods

        else:
            raise ValueError("Unsupported File type.")

    @property
    def all_methods(self) -> Set[MethodObject]:
        methods = set()
        if self.ret_type == "APK":
            for dexIdx in range(self.analysis.get_number_of_dex_files()):
                dexFile = self.analysis.get_dex_file_by_index(dexIdx)
                for i in range(
                    self.analysis.get_number_of_classes_for_dex_file(dexFile)
                ):
                    rawClass = self.analysis.get_hdvmclass_from_dex_by_index(
                        dexFile, i
                    )
                    className = rawClass.class_name.decode()
                    classAnalysis = self.analysis.get_analyzed_class_from_apk(
                        className
                    )
                    for j in range(int(classAnalysis.n_of_methods)):
                        methodAnalysis = classAnalysis.methods[j].contents
                        methods.add(
                            self._convert_to_method_object(methodAnalysis)
                        )

        elif self.ret_type == "DEX":
            for i in range(self.analysis.get_number_of_classes()):
                rawClass = self.analysis.get_class_by_id(i)
                className = rawClass.class_name.decode()
                classAnalysis = self.analysis.get_analyzed_class(className)
                for j in range(classAnalysis.n_of_methods):
                    methodAnalysis = classAnalysis.methods[j].contents
                    methods.add(self._convert_to_method_object(methodAnalysis))

        else:
            raise ValueError("Unsupported File type.")

        return methods

    @functools.lru_cache
    def _getMethodsClassified(self):
        """
        Parse all methods in the specified Dex and convert them into a
        dictionary. The dictionary takes their belonging classes as the keys.
        Then, it categorizes them into lists.

        :return: a dictionary taking a class name as the key and a list of
        MethodObject as the corresponding value.
        """
        methodDict = defaultdict(list)
        for method in self.all_methods:
            if method:
                methodDict[method.class_name].append(method)

        # Remove duplicates
        for class_name, method_list in methodDict.items():
            methodDict[class_name] = remove_dup_list(method_list)

        return methodDict

    @functools.lru_cache()
    def find_method(
        self,
        class_name: Optional[str] = None,
        method_name: Optional[str] = None,
        descriptor: Optional[str] = None,
    ) -> List[MethodObject]:
        methods = self.all_methods

        if class_name:
            methods = filter(
                lambda m: re.match(re.escape(class_name), m.class_name),
                methods,
            )

        if method_name:
            methods = filter(
                lambda m: re.match(re.escape(method_name), m.name), methods
            )

        if descriptor:
            methods = filter(
                lambda m: re.match(re.escape(descriptor), m.descriptor),
                methods,
            )

        return list(methods)

    @functools.lru_cache()
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        if self.ret_type == "APK":
            methodAnalysis = method_object.cache

            rawMethods = (
                methodAnalysis.xreffrom[i].method.contents
                for i in range(methodAnalysis.n_of_xreffrom)
            )

            methods = [
                self._convert_to_method_object(raw) for raw in rawMethods
            ]

            return set(methods)

        elif self.ret_type == "DEX":
            methodAnalysis = method_object.cache
            upperFuncs = set()
            for i in range(methodAnalysis.n_of_xreffrom):
                upperFuncs.add(
                    self._convert_to_method_object(
                        methodAnalysis.xreffrom[i].method.contents
                    )
                )

            return upperFuncs

        else:
            raise ValueError("Unsupported File type.")

    @functools.lru_cache()
    def lowerfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        if self.ret_type == "APK":
            methodAnalysis = method_object.cache

            rawMethodWithIdx = (
                (
                    methodAnalysis.xrefto[i].method.contents,
                    methodAnalysis.xrefto[i].idx,
                )
                for i in range(methodAnalysis.n_of_xrefto)
            )

            methodWithIdx = [
                (self._convert_to_method_object(rawMethod), idx)
                for rawMethod, idx in rawMethodWithIdx
            ]

            return set(methodWithIdx)

        elif self.ret_type == "DEX":
            methodAnalysis = method_object.cache

            lowerFuncs = set()
            for i in range(methodAnalysis.n_of_xrefto):
                lowerFuncs.add(
                    self._convert_to_method_object(
                        methodAnalysis.xrefto[i].method.contents
                    )
                )

            return lowerFuncs

        else:
            raise ValueError("Unsupported File type.")

    def get_method_bytecode(
        self, method_object: MethodObject
    ) -> Iterator[BytecodeObject]:
        if self.ret_type == "APK":
            methodAnalysis = method_object.cache
            bytecodeBlocks = methodAnalysis.basic_blocks.contents

            numOfBlocks = bytecodeBlocks.n_of_blocks
            for block in bytecodeBlocks.blocks[:numOfBlocks]:

                numOfInstructions = block.n_of_instructions
                for instruction in block.instructions[:numOfInstructions]:
                    # TODO - Convert bytearray to BytecodeObject
                    yield instruction.disassembly
        elif self.ret_type == "DEX":
            pass

    def get_strings(self) -> str:
        pass

    @functools.lru_cache()
    def _construct_bytecode_instruction(self, instruction):
        """
        Construct a list of strings from the given bytecode instructions.

        :param instruction: instruction instance from androguard
        :return: a list with bytecode instructions strings
        """
        pass

    @functools.lru_cache()
    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> Dict[str, Union[BytecodeObject, str]]:
        pass

    @property
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        pass

    @property
    def subclass_relationships(self) -> Dict[str, Set[str]]:
        pass

    @staticmethod
    def _convert_to_method_object(
        methodAnalysis: hdvmmethodanalysis_t,
    ) -> MethodObject:
        return MethodObject(
            # access_flags=methodAnalysis.access_flags,
            class_name=methodAnalysis.class_name.decode(),
            name=methodAnalysis.name.decode(),
            descriptor=descriptor_to_androguard_format(
                methodAnalysis.descriptor.decode()
            ),
            cache=methodAnalysis,
        )
