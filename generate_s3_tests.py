import os
import ast

from openai import AzureOpenAI

# Read the AWS S3 public APIs list from a file
with open("aws_s3_public_apis.txt", "r") as f:
    apis_list = [line.strip() for line in f if line.strip()]

# Azure OpenAI endpoint, API key, and deployment name
azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
api_key = os.getenv("AZURE_OPENAI_API_KEY")
api_version = os.getenv("AZURE_OPENAI_API_VERSION")
deployment_name = os.getenv("AZURE_OPENAI_CHAT_DEPLOYMENT_NAME")


# Initialize AzureOpenAI client with endpoint, api_key, and api_versio
def create_azure_client():
    """
    Create and return an AzureOpenAI client instance.
    """
    if not azure_endpoint or not api_key or not deployment_name:
        raise ValueError("Azure OpenAI configuration is incomplete.")

    return AzureOpenAI(
        azure_endpoint=azure_endpoint,
        api_key=api_key,
        api_version=api_version,
    )


CLIENT = create_azure_client()


def create_common_code() -> str:
    """
    Generate common code for all tests, including imports, client setup, and fixtures.
    """
    prompt = """
    You are an expert Python pytest developer. Generate common code for pytest tests
    """
    context = """
     - include setup fixtures
     - importing necessary libraries boto3, logging, and Ozone utility
     - Include logging for test execution. For that import logging . Add "logger = logging.getLogger(__name__)" at the top of the file after imports.
     - Use the Ozone utility to get S3 access and secret keys
        secretDict = Ozone.get_s3_access_and_secret_keys() . Add from beaver.component.ozone import Ozone in import section
        aws_access_key = secretDict['awsAccessKey']
        aws_secret_key = secretDict['awsSecret']
    - Create an S3 client using boto3 having ca_bundle_path , endpoint, access key, and secret key
    - ca_bundle_path = '/usr/local/share/ca-certificates/ca.crt'
    - endpoint = Ozone.get_s3_endpoint()
    - Do not add Explanation, only add the python code for the common code.
    - Do not add ```python in the beginning of the code block.
    
    """
    messages = [
        {"role": "system", "content": "You are a helpful assistant that writes Python pytest code."},
        {"role": "user", "content": prompt + "\n\nContext:\n" + context}
    ]

    res = CLIENT.chat.completions.create(
        model=deployment_name,
        messages=messages,
        temperature=0,
        max_tokens=4096,
    )
    return res.choices[0].message.content


def generate_test_for_apis(api_chunk: list) -> str:
    prompt = f"""
    You are an expert Python pytest developer. Generate a pytest test suite using boto3 (without mocking) for {api_chunk}
    The tests should be runnable, clear.
    """

    context = f"""
    The tests should:
    - run for all the APIs present in {api_chunk}
    - generate tests for the specific apis only present in {api_chunk}
    - Do NOT omit any API or provide partial implementations. Add all Additional tests for other APIs as well.
    - Do not suggest to implement rest of the APIs instead generate the tests for all rest of the APIs.
    - Assume boto3 S3 client is already created and available as `s3_client`
    - Include assertions verifying expected behavior
    - Add doctests for each test function to explain what the test is doing.
    - Do not add duplicate tests for the same API.
    - Do not add Explanation, only add the python code for the test suite.
    - Do not add ```python and the beginning of the code block.
    """
    messages = [
        {"role": "system", "content": "You are a helpful assistant that writes Python pytest code."},
        {"role": "user", "content": prompt + "\n\nContext:\n" + context}
    ]

    res = CLIENT.chat.completions.create(
        model=deployment_name,
        messages=messages,
        temperature=0,
        max_tokens=4096,
    )
    return res.choices[0].message.content


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


def create_api_list_chunks(apis: list, chunk_size: int = 10) -> list:
    """
    Split the list of APIs into chunks of specified size.
    """
    return [apis[i:i + chunk_size] for i in range(0, len(apis), chunk_size)]


if __name__ == "__main__":
    print("Creating common code")
    common_code = create_common_code()

    results = []
    chunks = create_api_list_chunks(apis_list, chunk_size=10)

    for chunk in chunks:
        print(f"Generating test for API: {chunk}")
        results.append(generate_test_for_apis(chunk))
        print(f"Generated test for API chunk: {chunk}\n")
        print(results)

    # Combine common code and all generated tests
    all_tests = [common_code + "\n\n"]
    for api, test_code in zip(apis_list, results):
        all_tests.append(f"# Test for {api}\n{test_code}\n\n")

    api_file = "test_s3_all_apis.py"
    with open(api_file, "w", encoding="utf-8") as f:
        f.writelines(all_tests)

    print(f"Generated pytest test suite saved to {api_file}")
    output_file = "test_s3_all_apis_optimised.py"  # Path to save optimized code

    print("Optimizing Python code from file...")
    optimize_python_code_from_file(api_file, output_file)
