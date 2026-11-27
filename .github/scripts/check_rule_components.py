#!/usr/bin/env python3
"""Kiểm tra thành phần bắt buộc của các rule Wazuh được thêm/sửa trong Pull Request.

Mỗi rule thay đổi phải có: id, level, description và ít nhất một thẻ điều kiện.
Chỉ rule mới hoặc rule có nội dung khác so với nhánh base mới bị kiểm tra.
"""

import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

BASE_REF = os.environ.get("BASE_REF", "main")
BASE = f"origin/{BASE_REF}"
RULES_DIR = "rules/"
IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"

# Theo tài liệu Wazuh: id 1-999999, level 0-16
ID_MIN, ID_MAX = 1, 999999
LEVEL_MIN, LEVEL_MAX = 0, 16

# Các thẻ dùng để "bắt" sự kiện (không gồm same_*, options, group, info... vì
# chúng không tự tạo điều kiện khớp)
CONDITION_TAGS = {
    "match", "regex", "decoded_as", "category", "field", "data", "extra_data",
    "srcip", "dstip", "srcport", "dstport", "srcgeoip", "dstgeoip",
    "user", "system_name", "program_name", "protocol", "hostname",
    "time", "weekday", "id", "url", "location", "action", "status",
    "if_sid", "if_group", "if_level",
    "if_matched_sid", "if_matched_group", "if_matched_level",
    "list", "check_diff",
}


def git(*args):
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, encoding="utf-8", check=True
    ).stdout


def get_changed_rule_files():
    """File .xml trong rules/ được thêm hoặc sửa (bỏ qua file bị xoá)."""
    out = git(
        "diff", "--name-only", "--no-renames", "--diff-filter=AM", "-z",
        f"{BASE}...HEAD",
    )
    return [p for p in out.split("\0") if p.startswith(RULES_DIR) and p.endswith(".xml")]


def parse_rules(content):
    """Trả về danh sách phần tử <rule>. Ném ET.ParseError nếu XML sai cú pháp."""
    content = re.sub(r"^\s*<\?xml[^>]*\?>", "", content.lstrip("\ufeff"))
    # File rule của Wazuh thường có nhiều phần tử gốc (<group>...) nên cần bọc <root>
    root = ET.fromstring(f"<root>{content}</root>")
    return root.findall(".//rule")


def canonical(elem):
    """Chuỗi chuẩn hoá của một phần tử: bỏ qua khoảng trắng thừa, thứ tự attribute, comment."""
    attrs = "".join(f' {k}="{v}"' for k, v in sorted(elem.attrib.items()))
    inner = "".join(canonical(c) for c in elem)
    return f"<{elem.tag}{attrs}>{(elem.text or '').strip()}{inner}</{elem.tag}>"


def rules_in_base(path):
    """Tập chuỗi chuẩn hoá của các rule trong file ở nhánh base (rỗng nếu file mới)."""
    try:
        content = git("show", f"{BASE}:{path}")
        return {canonical(r) for r in parse_rules(content)}
    except (subprocess.CalledProcessError, ET.ParseError):
        return set()


def rule_label(rule):
    rid = (rule.get("id") or "").strip()
    if rid:
        return f"Rule ID {rid}"
    desc = rule.find("description")
    snippet = " ".join("".join(desc.itertext()).split())[:50] if desc is not None else ""
    return "Rule ID <không xác định>" + (f' (description: "{snippet}")' if snippet else "")


def validate_rule(rule):
    """Trả về (danh sách thành phần thiếu, danh sách giá trị không hợp lệ)."""
    missing, invalid = [], []

    rid = (rule.get("id") or "").strip()
    if not rid:
        missing.append("id")
    elif not re.fullmatch(r"[0-9]+", rid) or not ID_MIN <= int(rid) <= ID_MAX:
        invalid.append(f"id='{rid}' (cần số {ID_MIN}-{ID_MAX})")

    level = (rule.get("level") or "").strip()
    if not level:
        missing.append("level")
    elif not re.fullmatch(r"[0-9]+", level) or not LEVEL_MIN <= int(level) <= LEVEL_MAX:
        invalid.append(f"level='{level}' (cần số {LEVEL_MIN}-{LEVEL_MAX})")

    desc = rule.find("description")
    if desc is None or not "".join(desc.itertext()).strip():
        missing.append("description")

    if not any(child.tag in CONDITION_TAGS for child in rule):
        missing.append("thẻ điều kiện")

    return missing, invalid


def report(path, label, parts):
    line = f"[LỖI] {path} | {label} | " + " | ".join(parts)
    # Trên GitHub Actions, ::error tạo annotation gắn vào file trong PR
    print(f"::error file={path}::{line}" if IN_ACTIONS else f"  {line}")


def main():
    os.chdir(git("rev-parse", "--show-toplevel").strip())

    files = get_changed_rule_files()
    if not files:
        print("Không có file rule nào được thêm/sửa.")
        return 0

    failed = False
    checked = 0

    for path in files:
        print(f"\nĐang kiểm tra: {path}")
        try:
            with open(path, encoding="utf-8-sig") as f:
                rules = parse_rules(f.read())
        except ET.ParseError as e:
            # XML hỏng thì không thể kiểm tra -> phải fail, không được bỏ qua
            report(path, "File XML", [f"sai cú pháp XML: {e}"])
            failed = True
            continue
        except (OSError, UnicodeDecodeError) as e:
            report(path, "File", [f"không đọc được: {e}"])
            failed = True
            continue

        base = rules_in_base(path)
        changed = [r for r in rules if canonical(r) not in base]
        if not changed:
            print("  Không có rule nào thay đổi.")
            continue

        for rule in changed:
            checked += 1
            missing, invalid = validate_rule(rule)
            parts = []
            if missing:
                parts.append("thiếu: " + ", ".join(missing))
            if invalid:
                parts.append("không hợp lệ: " + "; ".join(invalid))
            if parts:
                failed = True
                report(path, rule_label(rule), parts)
            else:
                print(f"  [OK] {rule_label(rule)}")

    print(f"\nĐã kiểm tra {checked} rule thay đổi.")
    if failed:
        print("KẾT QUẢ: THẤT BẠI. Vui lòng bổ sung/sửa các thành phần ở trên.")
        return 1
    print("KẾT QUẢ: Tất cả rule thay đổi đều đầy đủ thành phần bắt buộc.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
