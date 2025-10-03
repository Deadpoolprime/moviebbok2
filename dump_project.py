import os

# Set your project root (current folder)
project_root = "."

# Output file
output_file = "project_dump.txt"

# File extensions to include when dumping all files
include_exts = [".py", ".html", ".css", ".js", ".json", ".txt", ".md"]

# 🔧 If you want only specific files, list them here by name
# Example: only_files = ["views.py", "urls.py", "login.html"]
only_files = []   # put filenames here

with open(output_file, "w", encoding="utf-8") as outfile:
    for root, dirs, files in os.walk(project_root):
        if "venv" in dirs:
            dirs.remove("venv")
        if "__pycache__" in dirs:
            dirs.remove("__pycache__")

        for file in files:
            # ✅ If only_files is set, include only those filenames
            if only_files and file not in only_files:
                continue

            # Otherwise filter by extension
            if not only_files and not any(file.endswith(ext) for ext in include_exts):
                continue

            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8") as infile:
                    outfile.write(f"\n{'='*80}\n")
                    outfile.write(f"File: {filepath}\n")
                    outfile.write(f"{'='*80}\n\n")
                    outfile.write(infile.read())
                    outfile.write("\n\n")
            except Exception as e:
                outfile.write(f"\n[Could not read {filepath}: {e}]\n")

print(f"✅ File contents saved to {output_file}")
print("ℹ️  Cleared only_files list after writing.")
