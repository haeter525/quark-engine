# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
import re
import os.path
import subprocess
import json
from collections import defaultdict

from graphviz.dot import Digraph
from prettytable import PrettyTable

from quark.utils.colors import green, red

_GRAPH_SETTINGS = {
    "filename": "rules_classification",
    "comment": "A reference tree for parent functions",
    "format": "png",
    "graph_attr": {
        "center": "true",
        "label": "Reference Tree of Rule Classification",
        "labelloc": "top",
        "rankdir": "LR",
        "fontsize": "24",
        "fontname": "Courier New Bold",
        "fillcolor": "white",
        "shape": "box",
        "style": "rounded",
    },
    "node_attr": {
        "fontsize": "16",
        "fontname": "Courier New",
        "fontcolor": "red",
        "shape": "none",
    },
    "edge_attr": {"label": "calls"},
}


def get_rule_classification_data(call_graph_analysis_list, search_depth, extra_method_list):
    return _collect_crime_description(
        call_graph_analysis_list
    ), _search_cross_references(call_graph_analysis_list, search_depth, extra_method_list)


def _collect_crime_description(call_graph_analysis_list):
    report_dict = defaultdict(set)

    for item in call_graph_analysis_list:
        report_dict[item["parent"]].add(item["crime"])

    return report_dict


# @functools.lru_cache
def _search_cross_references(call_graph_analysis_list, search_depth, extra_method_set):
    reference_dict = defaultdict(set)

    if not call_graph_analysis_list:
        return reference_dict

    apkinfo = call_graph_analysis_list[0]["apkinfo"]
    parent_set = {item["parent"] for item in call_graph_analysis_list}

    for parent in parent_set:
        called_function_set = set()
        expand_queue = {parent}
        for _ in range(search_depth):
            for function in expand_queue:
                next_expand_queue = {
                    child_function for child_function, _ in apkinfo.lowerfunc(function)
                }
                called_function_set.update(next_expand_queue)
                expand_queue = next_expand_queue

        referenced_set = called_function_set.intersection(parent_set)
        referenced_set = extra_method_set.intersection(parent_set)
        referenced_set.discard(parent)

        reference_dict[parent] = referenced_set

    return reference_dict


def _convert_to_printable_dict(report_dict, reference_dict):
    printable_dict = defaultdict(list)

    for parent, reference_set in reference_dict.items():
        key = _get_function_display_name(parent)

        printable_dict[key].extend(
            [
                f"Call {_get_function_display_name(reference)}"
                for reference in reference_set
            ]
        )

    for parent, values in report_dict.items():
        key = _get_function_display_name(parent)
        printable_dict[key].extend(list(values))

    return printable_dict


def _get_function_display_name(function):
    return f"{function.class_name}{function.name}"


def output_parent_function_table(rule_classification_data_bundle):
    dd = _convert_to_printable_dict(*rule_classification_data_bundle)

    # Pretty Table Output

    for parent, crimes in dd.items():
        tb = PrettyTable()
        tb.field_names = [
            "Parent Function",
            f"{green(parent)}",
        ]
        tb.align = "l"

        for count, crime in enumerate(set(crimes), start=1):
            if count == 1:
                tb.add_row(["Crime Description", red(f"* {crime}")])
            else:
                tb.add_row(["", red(f"* {crime}")])
        print(tb)


def output_parent_function_json(rule_classification_data_bundle):
    dd = _convert_to_printable_dict(*rule_classification_data_bundle)

    # Json Output

    data = {"rules_classification": []}

    for parent, crimes in dd.items():
        data["rules_classification"].append(
            {
                "parent": parent,
                "crime": crimes,
            }
        )

    with open("rules_classification.json", "w") as outfile:
        json.dump(data, outfile)

def _get_library_node_name(library_name):
    return re.sub('[.<>+-=*]', '_', library_name)

def output_parent_function_graph(rule_classification_data_bundle, library_list, export_method_dict):
    report_dict, reference_dict = rule_classification_data_bundle

    identifier_dict = {
        parent: f"p{index}" for index, parent in enumerate(report_dict.keys())
    }

    dot = Digraph(**_GRAPH_SETTINGS)

    for parent, identifier in identifier_dict.items():
        descriptions = "\l".join(report_dict[parent]) + "\l"

        with dot.subgraph(
            name=f"cluster_{identifier}",
            graph_attr={
                "label": _get_function_display_name(parent),
                "fontsize": "16",
            },
        ) as sub:
            sub.node(identifier, label=descriptions)

    edge_list = []
    for parent, identifier in identifier_dict.items():
        edge_list.extend(
            [
                (identifier, identifier_dict[function])
                for function in reference_dict[parent]
            ]
        )

    dot.edges(edge_list)

    # Libraries
    with dot.subgraph(
        name="cluster_native_libraries",
        graph_attr={ "label": "Native libraries" },
        node_attr={ "shape": "none"},
        edge_attr={ "label": "includes"}
    ) as cluster_library:
        
        # Lind native API to libraries
        for library in library_list:
            # if not set(export_method_dict[library]).intersection(identifier_dict.keys):
            #     continue

            # Create library node
            node_name = _get_library_node_name(library.name)
            node_label = f"<<TABLE><TR><TD>{node_name}</TD></TR>"

            for behavior in library.behaviors.keys():
                node_label += f"<TR><TD>{behavior}</TD></TR>"

            node_label += '</TABLE>>'

            cluster_library.node(node_name, node_label)

            # Link imported libraries
            for imported in library.import_libraries:

                is_exist = False
                for exist in library_list:
                    if imported == exist.name:
                        is_exist = True
                        break

                if not is_exist:
                    continue

                imported_name = _get_library_node_name(imported)
                cluster_library.edge(node_name, imported_name)

            # Link export methods
            for method in export_method_dict[library]:
                if method in identifier_dict:
                    dot.edge(identifier_dict[method], node_name)

    dot.render()

class ELFLibrary:
    def __init__(self):
        self.name = None
        self.behaviors = defaultdict(list)
        self.path_list = []
        self.import_libraries = []
        self.export_methods = []

    def add_file(self, path):
        if not path.endswith('.so'):
            raise ValueError(f"File not supported.")

        result = subprocess.run(['elfparser-cli', '-f', path, '-c'], encoding='UTF-8', check=True, stdout=subprocess.PIPE)
        result_lines = result.stdout.splitlines()
        ELFLibrary._parse_behaviors(result_lines, self.behaviors)

        result = subprocess.run(['elfparser-cli', '-f', path, '-p'], encoding='UTF-8', check=True, stdout=subprocess.PIPE)
        result_lines = result.stdout.splitlines()

        ELFLibrary._parse_import_libraries(result_lines, self.import_libraries)
        ELFLibrary._parse_export_methods(result_lines, self.export_methods)

        self.path_list.append(path)

        if not self.name:
            self.name = os.path.basename(path)

    @staticmethod
    def _parse_behaviors(result_lines, behavior_dict):
        current_key = ""
        for line in result_lines:
            token_list = line.split('\t', 2)

            if len(token_list) == 2:
                current_key = token_list[1]
            elif len(token_list) == 3:
                behavior_dict[current_key].append(token_list[2])

    @staticmethod
    def _parse_import_libraries(result_lines, library_list):
        target_lines = filter(lambda l: "tag=NEEDED" in l, result_lines)
        library_list.extend(line.split('=')[2] for line in target_lines)

    @staticmethod
    def _parse_export_methods(result_lines, method_list):
        target_lines = filter(lambda l: "type=STT_FUNC, binding=STB_GLOBAL" in l and "name=Java_" in l, result_lines)

        for line in target_lines:
            raw_method = line[line.index('name=Java_')+len('name=Java_'):]
            method_pieces = raw_method.split('_')

            class_name = 'L' + '/'.join(method_list[:-1]) + ';'
            method_name = method_pieces[-1]
            method_list.append((class_name, method_name))