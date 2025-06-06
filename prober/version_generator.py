import json


def extract_versions():
    with open("testing_matrix.json") as file:
        data = json.load(file)
    version_mapping = {}
    for entry in data["python-version"]:
        python_version = str(entry["version"])
        version_mapping[python_version] = entry["snowflake-connector-python"]
    return version_mapping


def update_dockerfile(version_mapping):
    dockerfile_path = "Dockerfile"
    new_matrix_version = json.dumps(version_mapping)

    with open(dockerfile_path) as file:
        lines = file.readlines()

    with open(dockerfile_path, "w") as file:
        for line in lines:
            if line.startswith("ARG MATRIX_VERSION"):
                file.write(f'ARG MATRIX_VERSION=\'{new_matrix_version}\'\n')
            else:
                file.write(line)

if __name__ == "__main__":
    extracted_mapping = extract_versions()
    update_dockerfile(extracted_mapping)
