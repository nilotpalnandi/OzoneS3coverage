import ast


def is_fixture(node):
    """Check if a function node is a pytest fixture."""
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "fixture":
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr == "fixture":
            return True
    return False


def optimize_python_code_from_file(input_path: str, output_path: str):
    with open(input_path, "r", encoding="utf-8") as f:
        code_str = f.read()

    parsed = ast.parse(code_str)

    unique_imports = set()
    unique_fixtures = {}
    unique_functions = {}
    new_body = []

    for node in parsed.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imp_code = ast.unparse(node)
            if imp_code not in unique_imports:
                unique_imports.add(imp_code)
                new_body.append(node)
        elif isinstance(node, ast.FunctionDef):
            if is_fixture(node):
                if node.name not in unique_fixtures:
                    unique_fixtures[node.name] = node
                    new_body.append(node)
            else:
                if node.name not in unique_functions:
                    unique_functions[node.name] = node
                    new_body.append(node)
        else:
            new_body.append(node)

    optimized_module = ast.Module(body=new_body, type_ignores=[])
    optimized_code = ast.unparse(optimized_module)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(optimized_code)

    print(f"Optimized code written to {output_path}")


if __name__ == "__main__":
    api_file = "test_s3_all_apis.py"
    output_file = "test_s3_all_apis_optimised.py"  # Path to save optimized code

    print("Optimizing Python code from file...")
    optimize_python_code_from_file(api_file, output_file)
