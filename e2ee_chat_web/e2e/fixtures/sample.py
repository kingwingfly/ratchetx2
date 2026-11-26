# Deterministic Python fixture exercising preview_code_scripts.
def greet(target: str) -> str:
    marker = "SEARCH_MARKER_PYTHON"
    return f"Hello {target} ({marker})"


if __name__ == "__main__":
    print(greet("ratchetx2"))
