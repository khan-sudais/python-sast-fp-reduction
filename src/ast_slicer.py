import argparse
import ast
import json
from pathlib import Path


def _end_line(node):
    return getattr(node, "end_lineno", getattr(node, "lineno", 0))


def _loaded_names(node):
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }


def _target_names(node):
    names = set()
    if isinstance(node, ast.Name):
        names.add(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            names.update(_target_names(item))
    return names


def _defined_names(node):
    names = set()

    if isinstance(node, ast.Assign):
        for target in node.targets:
            names.update(_target_names(target))
    elif isinstance(node, ast.AnnAssign):
        names.update(_target_names(node.target))
    elif isinstance(node, ast.AugAssign):
        names.update(_target_names(node.target))
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        names.update(_target_names(node.target))
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                names.update(_target_names(item.optional_vars))
    elif isinstance(node, ast.NamedExpr):
        names.update(_target_names(node.target))
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.add(node.name)

    return names


class PythonProgramSlicer:
    def __init__(self, filepath):
        self.filepath = Path(filepath).resolve()
        self.source_code = self.filepath.read_text(encoding="utf-8", errors="ignore")
        self.lines = self.source_code.splitlines(keepends=True)
        self.tree = ast.parse(self.source_code, filename=str(self.filepath))
        self.parents = {}
        for parent in ast.walk(self.tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent

    def _enclosing_function(self, target_line):
        candidates = []
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.lineno <= target_line <= _end_line(node):
                    candidates.append(node)

        if not candidates:
            return None

        return min(candidates, key=lambda node: _end_line(node) - node.lineno)

    def _enclosing_class(self, node):
        current = self.parents.get(node)
        while current is not None:
            if isinstance(current, ast.ClassDef):
                return current
            current = self.parents.get(current)
        return None

    def _statement_records(self, function_node):
        records = []

        def visit_block(statements, controls):
            for statement in statements:
                records.append((statement, tuple(controls)))

                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue

                if isinstance(statement, ast.If):
                    visit_block(statement.body, controls + [statement])
                    visit_block(statement.orelse, controls + [statement])
                elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                    visit_block(statement.body, controls + [statement])
                    visit_block(statement.orelse, controls + [statement])
                elif isinstance(statement, (ast.With, ast.AsyncWith)):
                    visit_block(statement.body, controls + [statement])
                elif isinstance(statement, (ast.Try, ast.TryStar)):
                    visit_block(statement.body, controls + [statement])
                    visit_block(statement.orelse, controls + [statement])
                    visit_block(statement.finalbody, controls + [statement])
                    for handler in statement.handlers:
                        visit_block(handler.body, controls + [statement])
                elif isinstance(statement, ast.Match):
                    for case in statement.cases:
                        visit_block(case.body, controls + [statement])

        visit_block(function_node.body, [])
        return records

    def _target_statement(self, function_node, target_line):
        candidates = []
        for statement, _ in self._statement_records(function_node):
            if statement.lineno <= target_line <= _end_line(statement):
                candidates.append(statement)

        if not candidates:
            return None

        return min(
            candidates,
            key=lambda node: (_end_line(node) - node.lineno, -node.lineno),
        )

    def _control_header_lines(self, node):
        if isinstance(node, ast.If):
            body = node.body
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            body = node.body
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            body = node.body
        elif isinstance(node, (ast.Try, ast.TryStar)):
            body = node.body
        elif isinstance(node, ast.Match):
            first_case_line = min(
                (case.pattern.lineno for case in node.cases if hasattr(case.pattern, "lineno")),
                default=node.lineno,
            )
            return set(range(node.lineno, first_case_line + 1))
        else:
            return {node.lineno}

        if body:
            end = max(node.lineno, body[0].lineno - 1)
        else:
            end = node.lineno

        return set(range(node.lineno, end + 1))

    def _function_header_lines(self, node):
        if node.body:
            end = max(node.lineno, node.body[0].lineno - 1)
        else:
            end = node.lineno
        return set(range(node.lineno, end + 1))

    def _node_lines(self, node):
        return set(range(node.lineno, _end_line(node) + 1))

    def _format_lines(self, line_numbers):
        output = []
        for line_number in sorted(line_numbers):
            if 1 <= line_number <= len(self.lines):
                output.append(f"{line_number:4d}: {self.lines[line_number - 1]}")
        return "".join(output)

    def extract_variant_a(self, target_line, window=3):
        if target_line < 1 or target_line > len(self.lines):
            raise ValueError(
                f"target_line must be between 1 and {len(self.lines)}, got {target_line}"
            )

        start = max(1, target_line - window)
        end = min(len(self.lines), target_line + window)

        return {
            "variant": "A_ISOLATED_DIFF",
            "start_line": start,
            "end_line": end,
            "code": "".join(self.lines[start - 1 : end]),
        }

    def extract_variant_b(self, target_line):
        function_node = self._enclosing_function(target_line)
        if function_node is None:
            return self.extract_variant_a(target_line, window=5)

        records = self._statement_records(function_node)
        target_statement = self._target_statement(function_node, target_line)

        if target_statement is None:
            return self.extract_variant_a(target_line, window=5)

        controls_by_id = {id(statement): controls for statement, controls in records}
        relevant_nodes = {id(target_statement): target_statement}
        relevant_controls = {
            id(control): control
            for control in controls_by_id.get(id(target_statement), ())
        }

        required = _loaded_names(target_statement)
        for control in relevant_controls.values():
            required.update(_loaded_names(control))

        ordered = sorted(
            (statement for statement, _ in records if statement.lineno < target_statement.lineno),
            key=lambda node: (node.lineno, _end_line(node)),
            reverse=True,
        )

        for statement in ordered:
            defined = _defined_names(statement)
            if not defined.intersection(required):
                continue

            relevant_nodes[id(statement)] = statement
            required.difference_update(defined)
            required.update(_loaded_names(statement))

            for control in controls_by_id.get(id(statement), ()):
                relevant_controls[id(control)] = control
                required.update(_loaded_names(control))

        line_numbers = self._function_header_lines(function_node)

        for node in relevant_nodes.values():
            line_numbers.update(self._node_lines(node))

        for control in relevant_controls.values():
            line_numbers.update(self._control_header_lines(control))

        parameter_names = {
            arg.arg
            for arg in (
                list(function_node.args.posonlyargs)
                + list(function_node.args.args)
                + list(function_node.args.kwonlyargs)
            )
        }
        if function_node.args.vararg is not None:
            parameter_names.add(function_node.args.vararg.arg)
        if function_node.args.kwarg is not None:
            parameter_names.add(function_node.args.kwarg.arg)

        return {
            "variant": "B_INTRA_PROCEDURAL_SLICE",
            "function_name": function_node.name,
            "target_line": target_line,
            "slice_line_count": len(line_numbers),
            "parameters_referenced": sorted(required.intersection(parameter_names)),
            "code": self._format_lines(line_numbers),
        }

    def _call_name(self, call_node):
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        if isinstance(call_node.func, ast.Attribute):
            return call_node.func.attr
        return None

    def _caller_sites(self, callee_name):
        callers = []
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for child in ast.walk(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
                    continue
                if isinstance(child, ast.Call) and self._call_name(child) == callee_name:
                    callers.append((node, child))

        unique = {}
        for function_node, call_node in callers:
            unique[(function_node.name, call_node.lineno)] = (function_node, call_node)

        return list(unique.values())

    def extract_variant_c(self, target_line, max_depth=3):
        base_slice = self.extract_variant_b(target_line)
        target_function = self._enclosing_function(target_line)

        if target_function is None:
            return {
                "variant": "C_INTER_PROCEDURAL_TAINT_SLICE",
                "target_line": target_line,
                "call_depth": 0,
                "callers": [],
                "code": base_slice["code"],
            }

        class_node = self._enclosing_class(target_function)
        sections = []
        callers_output = []
        visited = {target_function.name}
        frontier = [(target_function.name, 0)]

        while frontier:
            callee_name, depth = frontier.pop(0)
            if depth >= max_depth:
                continue

            for caller_function, call_node in self._caller_sites(callee_name):
                edge_key = f"{caller_function.name}:{call_node.lineno}->{callee_name}"
                if edge_key in {item["edge"] for item in callers_output}:
                    continue

                caller_slice = self.extract_variant_b(call_node.lineno)
                callers_output.append(
                    {
                        "edge": edge_key,
                        "caller_function": caller_function.name,
                        "callee_function": callee_name,
                        "call_line": call_node.lineno,
                        "depth": depth + 1,
                    }
                )
                sections.append(
                    f"=== Caller depth {depth + 1}: "
                    f"{caller_function.name} -> {callee_name} "
                    f"(line {call_node.lineno}) ===\n"
                    f"{caller_slice['code']}"
                )

                if caller_function.name not in visited:
                    visited.add(caller_function.name)
                    frontier.append((caller_function.name, depth + 1))

        metadata = [
            "=== Target ===",
            f"Function: {target_function.name}",
            f"Line: {target_line}",
        ]

        if class_node is not None:
            metadata.append(f"Class: {class_node.name}")

        decorators = [
            ast.unparse(decorator)
            for decorator in target_function.decorator_list
        ]
        if decorators:
            metadata.append("Decorators: " + ", ".join(decorators))

        output_parts = ["\n".join(metadata), "=== Target slice ===", base_slice["code"]]
        output_parts.extend(sections)

        return {
            "variant": "C_INTER_PROCEDURAL_TAINT_SLICE",
            "function_name": target_function.name,
            "class_name": class_node.name if class_node is not None else None,
            "target_line": target_line,
            "max_depth": max_depth,
            "call_depth": max((item["depth"] for item in callers_output), default=0),
            "callers": callers_output,
            "code": "\n".join(output_parts),
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filepath")
    parser.add_argument("target_line", type=int)
    parser.add_argument("--max-depth", type=int, default=3)
    args = parser.parse_args()

    slicer = PythonProgramSlicer(args.filepath)

    result = {
        "variant_a": slicer.extract_variant_a(args.target_line),
        "variant_b": slicer.extract_variant_b(args.target_line),
        "variant_c": slicer.extract_variant_c(
            args.target_line,
            max_depth=args.max_depth,
        ),
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
