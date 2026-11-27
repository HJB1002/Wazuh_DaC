import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import sys
import os
from collections import defaultdict, Counter

def run_git_command(args):
    """Hàm phụ trợ để chạy lệnh git và trả về output"""
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return result.stdout

def get_changed_rule_files():
    try:
        output = run_git_command(["git", "diff", "--name-status", "origin/main...HEAD"])
        changed_files = []
        for line in output.strip().splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) != 2:
                continue
            status, file_path = parts
            if file_path.startswith("rules/") and file_path.endswith(".xml"):
                changed_files.append((status, Path(file_path)))
        return changed_files
    except subprocess.CalledProcessError as e:
        print("Failed to get changed files:", e)
        sys.exit(1)

def extract_rule_ids_from_xml(content):
    ids = []
    try:
        wrapped = f"<root>{content}</root>"
        root = ET.fromstring(wrapped)
        for rule in root.findall(".//rule"):
            rule_id = rule.get("id")
            if rule_id and rule_id.isdigit():
                ids.append(int(rule_id))
    except ET.ParseError as e:
        print(f"XML Parse Error: {e}")
    return ids

def get_rule_ids_per_file_in_main():
    print("Đang tải danh sách rule IDs từ nhánh main...")
    run_git_command(["git", "fetch", "origin", "main"])
    files_output = run_git_command(["git", "ls-tree", "-r", "origin/main", "--name-only"])
    xml_files = [f for f in files_output.splitlines() if f.startswith("rules/") and f.endswith(".xml")]

    rule_id_to_files = defaultdict(set)
    for file in xml_files:
        try:
            content = run_git_command(["git", "show", f"origin/main:{file}"])
            rule_ids = extract_rule_ids_from_xml(content)
            for rule_id in rule_ids:
                rule_id_to_files[rule_id].add(file)
        except subprocess.CalledProcessError:
            continue
    return rule_id_to_files

def get_rule_ids_from_main_version(file_path: Path):
    try:
        content = run_git_command(["git", "show", f"origin/main:{file_path.as_posix()}"])
        return extract_rule_ids_from_xml(content)
    except subprocess.CalledProcessError:
        return []

def detect_duplicates(rule_ids):
    counter = Counter(rule_ids)
    return [rule_id for rule_id, count in counter.items() if count > 1]

def print_conflicts(conflicting_ids, rule_id_to_files):
    print("Phát hiện xung đột Rule ID:")
    for rule_id in sorted(conflicting_ids):
        files = rule_id_to_files.get(rule_id, [])
        print(f"  - Rule ID {rule_id} đang bị trùng với các file sau trên main:")
        for f in files:
            print(f"    - {f}")

def main():
    # SỬA LỖI 1: Dùng git để tự động tìm thư mục gốc, không phụ thuộc vào vị trí file
    try:
        repo_root = run_git_command(["git", "rev-parse", "--show-toplevel"]).strip()
    except subprocess.CalledProcessError:
        print("Không thể xác định thư mục gốc của repository.")
        sys.exit(1)
    os.chdir(repo_root)
    print(f"Đang làm việc tại thư mục: {os.getcwd()}")

    changed_files = get_changed_rule_files()
    if not changed_files:
        print("Không có file rule nào bị thay đổi trong PR này.")
        return

    rule_id_to_files_main = get_rule_ids_per_file_in_main()

    print(f"Bắt đầu kiểm tra xung đột cho các file: {[f.name for _, f in changed_files]}")

    # SỬA LỖI 2: Đếm số file đã kiểm tra thành công, nếu không bằng tổng số file thì thất bại
    processed_count = 0

    for status, path in changed_files:
        print(f"\nĐang kiểm tra file: {path.name} (Trạng thái: {status})")

        # SỬA LỖI 2: Nếu không đọc được file thì coi là lỗi, dừng ngay
        try:
            dev_content = path.read_text()
            dev_ids = extract_rule_ids_from_xml(dev_content)
        except Exception as e:
            print(f"LỖI: Không thể đọc file {path.name}: {e}")
            sys.exit(1)  # Thay vì continue, phải exit(1) để chặn PR

        # 1. Kiểm tra trùng lặp ID bên trong chính file đó
        duplicates = detect_duplicates(dev_ids)
        if duplicates:
            print(f"Phát hiện Rule ID bị trùng lặp bên trong file {path.name}: {sorted(duplicates)}")
            sys.exit(1)

        # 2. Kiểm tra xung đột với nhánh main
        if status == "A":
            conflicting_ids = set(dev_ids) & set(rule_id_to_files_main.keys())
            if conflicting_ids:
                print_conflicts(conflicting_ids, rule_id_to_files_main)
                sys.exit(1)
            else:
                print(f"File mới {path.name} không có xung đột ID.")

        elif status == "M":
            main_ids = get_rule_ids_from_main_version(path)
            if set(dev_ids) == set(main_ids):
                print(f"File {path.name} được sửa nhưng danh sách Rule ID không thay đổi.")
                processed_count += 1
                continue

            new_or_changed_ids = set(dev_ids) - set(main_ids)
            conflicting_ids = new_or_changed_ids & set(rule_id_to_files_main.keys())

            if conflicting_ids:
                print_conflicts(conflicting_ids, rule_id_to_files_main)
                sys.exit(1)
            else:
                print(f"File sửa đổi {path.name} không có xung đột ID.")

        processed_count += 1

    # SỬA LỖI 2: Kiểm tra an toàn cuối cùng
    if processed_count != len(changed_files):
        print(f"LỖI: Chỉ kiểm tra được {processed_count}/{len(changed_files)} file.")
        sys.exit(1)

    print("\nTất cả các thay đổi đều vượt qua bài kiểm tra xung đột Rule ID.")

if __name__ == "__main__":
    main()