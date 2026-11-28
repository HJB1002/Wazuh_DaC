#!/usr/bin/env python3
"""Kiểm tra cú pháp và cấu trúc XML của các file ruleset Wazuh thay đổi trong Pull Request.

LỖI (làm fail workflow):
  1. Thẻ không đóng, đóng thừa, đóng sai tên hoặc sai thứ tự
  2. File rỗng / không còn rule nào (từng file và toàn bộ thư mục rules/)
  3. Sai cấu trúc: <rule> ngoài <group>, <rule> lồng <rule>, <group> thiếu name
  4. Ký tự '<' hoặc '&' chưa escape, attribute thiếu dấu nháy
  5. File không phải UTF-8 hoặc chứa ký tự điều khiển
CẢNH BÁO (không làm fail): thẻ lạ, thường do gõ sai tên thẻ.

Khác với check_rule_components, ở đây kiểm tra TOÀN BỘ file bị thay đổi
(một thẻ hỏng ở rule cũ vẫn làm Wazuh không nạp được cả file).
"""

import bisect
import difflib
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

BASE_REF = os.environ.get("BASE_REF", "main")
BASE = f"origin/{BASE_REF}"
RULES_DIR = "rules/"
IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"
MAX_SHOWN = 50  # số vấn đề tối đa in ra cho mỗi file

# Thẻ con hợp lệ trong <rule> (theo tài liệu Wazuh). Chỉ dùng để CẢNH BÁO thẻ lạ.
RULE_CHILD_TAGS = {
    "match", "regex", "decoded_as", "category", "field", "data", "extra_data",
    "srcip", "dstip", "srcport", "dstport", "srcgeoip", "dstgeoip",
    "user", "system_name", "program_name", "protocol", "hostname",
    "time", "weekday", "id", "url", "location", "action", "status",
    "if_sid", "if_group", "if_level", "if_fts",
    "if_matched_sid", "if_matched_group", "if_matched_level",
    "description", "list", "info", "options", "check_diff", "group", "mitre",
    "compiled_rule",
}
RULE_CHILD_PREFIXES = ("same_", "not_same_", "different_")

# --- Biểu thức chính quy ---------------------------------------------------
NAME = r"[A-Za-z_][\w.\-:]*"
ATTR_VALUE = r"\"[^\"<]*\"|'[^'<]*'"  # giá trị attribute không được chứa '<'
# Thẻ: <name attrs>, </name>, <name attrs/>
TAG_RE = re.compile(
    r"<(?P<close>/?)(?P<name>" + NAME + r")"
    r"(?P<attrs>(?:[^<>\"']|" + ATTR_VALUE + r")*?)(?P<self>/?)>"
)
HALF_TAG_RE = re.compile(r"</?" + NAME)  # '<tên' nhưng thiếu '>' hoặc nháy sai
ATTRS_OK_RE = re.compile(r"(?:\s+" + NAME + r"\s*=\s*(?:" + ATTR_VALUE + r"))*\s*")
ATTR_PAIR_RE = re.compile("(" + NAME + r")\s*=\s*(?:\"([^\"<]*)\"|'([^'<]*)')")
BAD_ENTITY_RE = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#[0-9]+|#x[0-9A-Fa-f]+);)")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
NON_TAG_RE = re.compile(r"<!--.*?-->|<!\[CDATA\[.*?\]\]>|<\?.*?\?>", re.S)
RULE_OPEN_RE = re.compile(r"<rule(?=[\s/>])")

COUNT = {"error": 0, "warning": 0}


def git(*args):
    return subprocess.run(
        ["git", *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=True,
    ).stdout


def blank(s):
    """Thay mọi ký tự (trừ xuống dòng) bằng khoảng trắng: giữ nguyên độ dài và số dòng."""
    return re.sub(r"[^\n]", " ", s)


def blank_non_tags(text):
    """Xoá comment, CDATA, khai báo <?...?> để không bị tính nhầm là thẻ."""
    return NON_TAG_RE.sub(lambda m: blank(m.group(0)), text)


def count_rules(text):
    return len(RULE_OPEN_RE.findall(blank_non_tags(text)))


def known_child(parent, name):
    if parent is None:
        return name in {"group", "var", "rule"}
    if parent == "group":
        return name in {"rule", "var", "group"}
    if parent == "rule":
        return (name in RULE_CHILD_TAGS or name == "rule"
                or name.startswith(RULE_CHILD_PREFIXES))
    return True  # con của <mitre>, <options>... không kiểm tra


def unknown_tag_msg(parent, name):
    where = f"trong <{parent}>" if parent else "ở cấp ngoài cùng (chỉ nên có <group>, <var>)"
    pool = RULE_CHILD_TAGS if parent == "rule" else {"rule", "group", "var"}
    close = difflib.get_close_matches(name, pool, n=1, cutoff=0.75)
    hint = f" - có phải ý bạn là <{close[0]}>?" if close else ""
    return f"thẻ lạ <{name}> {where}{hint}"


class FileChecker:
    def __init__(self, text):
        self.text = text.lstrip("\ufeff")
        self.clean = ""
        self.issues = []  # (mức, dòng, thông báo)
        self._starts = [0] + [m.end() for m in re.finditer("\n", self.text)]

    def line_of(self, pos):
        return bisect.bisect_right(self._starts, pos)

    def add(self, kind, pos, msg):
        self.issues.append((kind, None if pos is None else self.line_of(pos), msg))

    def sanitize(self):
        clean = blank_non_tags(self.text)
        # Phần còn sót lại là comment/CDATA/khai báo mở ra mà không đóng
        for opener, what in (("<!--", "comment"), ("<![CDATA[", "CDATA"),
                             ("<?", "khai báo <?...?>")):
            idx = clean.find(opener)
            if idx != -1:
                self.add("error", idx, f"{what} bắt đầu nhưng không có phần kết thúc")
                clean = clean[:idx] + blank(clean[idx:])
        return clean

    def check_entities(self, start, end):
        for e in BAD_ENTITY_RE.finditer(self.clean, start, end):
            self.add("error", e.start(), "ký tự '&' chưa escape (cần viết &amp;)")

    # --- Quét thẻ bằng stack ----------------------------------------------
    def scan(self):
        clean, stack, pos = self.clean, [], 0  # stack: (tên thẻ, vị trí)
        while True:
            i = clean.find("<", pos)
            self.check_entities(pos, len(clean) if i == -1 else i)
            if i == -1:
                break
            m = TAG_RE.match(clean, i)
            if not m:
                half = HALF_TAG_RE.match(clean, i)
                if half:
                    self.add("error", i, f"thẻ '{half.group(0)}' sai cú pháp "
                             "(thiếu dấu '>' hoặc dấu nháy trong attribute không đóng)")
                    if not half.group(0).startswith("</"):
                        stack.append((half.group(0)[1:], i))  # coi như thẻ mở, tránh lỗi dây chuyền
                else:
                    self.add("error", i, "ký tự '<' chưa escape (cần viết &lt;)")
                pos = i + 1
                continue
            pos = m.end()
            if m["close"]:
                self.on_close(stack, m, i)
            else:
                self.on_open(stack, m, i)
        for name, p in stack:
            self.add("error", p, f"<{name}> thiếu thẻ đóng </{name}> (đến hết file vẫn chưa đóng)")

    def on_close(self, stack, m, i):
        name = m["name"]
        if m["attrs"].strip() or m["self"]:
            self.add("error", i, f"thẻ đóng </{name}> không hợp lệ "
                     "(thẻ đóng không có attribute và không có '/' ở cuối)")
        if name in [n for n, _ in stack]:
            while stack[-1][0] != name:  # các thẻ nằm trên đỉnh là thẻ thiếu đóng
                n, p = stack.pop()
                self.add("error", p, f"<{n}> thiếu thẻ đóng </{n}> "
                         f"(gặp </{name}> ở dòng {self.line_of(i)} trước khi thẻ này được đóng)")
            stack.pop()
        else:
            hint = ""
            if stack:
                n, p = stack[-1]
                hint = (f" (đóng thừa hoặc gõ sai tên thẻ; thẻ đang mở gần nhất "
                        f"là <{n}> ở dòng {self.line_of(p)})")
            self.add("error", i, f"</{name}> không có thẻ mở tương ứng{hint}")

    def on_open(self, stack, m, i):
        name, attrs = m["name"], m["attrs"]
        if not ATTRS_OK_RE.fullmatch(attrs):
            self.add("error", i, f"attribute của <{name}> sai cú pháp "
                     "(giá trị phải đặt trong dấu nháy, dạng tên=\"giá trị\")")
        self.check_entities(m.start("attrs"), m.end("attrs"))

        names = [n for n, _ in stack]
        parent = names[-1] if names else None
        if name == "rule":
            if "rule" in names:
                self.add("error", i, "<rule> lồng trong <rule> khác (rule trước thiếu </rule>?)")
            if "group" not in names:
                self.add("error", i, "<rule> nằm ngoài <group>")
        elif name == "group" and parent != "rule":  # <group> trong <rule> là thẻ nhóm, không phải container
            pairs = {k: a or b for k, a, b in ATTR_PAIR_RE.findall(attrs)}
            if not pairs.get("name", "").strip():
                self.add("error", i, "<group> thiếu attribute name (ví dụ <group name=\"local,\">)")

        if not known_child(parent, name):
            self.add("warning", i, unknown_tag_msg(parent, name))
        if not m["self"]:
            stack.append((name, i))

    def standard_parse(self):
        """Lớp chốt: parser chuẩn bắt các lỗi mà bước quét thẻ bỏ sót (vd attribute trùng)."""
        try:
            ET.fromstring("<root>" + self.clean + "</root>")
        except ET.ParseError as e:
            self.issues.append(("error", e.position[0], f"XML không hợp lệ theo parser chuẩn: {e}"))

    def run(self, base_rules=0):
        m = CONTROL_RE.search(self.text)
        if m:
            self.add("error", m.start(), f"ký tự điều khiển không hợp lệ U+{ord(m.group()):04X}")
        self.clean = self.sanitize()

        reason = None
        if not self.text.strip():
            reason = "file rỗng (không có nội dung)"
        elif not self.clean.strip():
            reason = "file chỉ có comment hoặc khai báo XML, không có phần tử nào"
        else:
            self.scan()
            if not any(k == "error" for k, _, _ in self.issues):
                self.standard_parse()
            if not RULE_OPEN_RE.search(self.clean):
                reason = "file có nội dung nhưng không có <rule> nào"
        if reason:
            if base_rules:
                reason += f"; ở nhánh {BASE_REF} file này có {base_rules} rule, nay đã bị xoá hết"
            self.add("error", None, reason)

        self.issues.sort(key=lambda x: x[1] or 0)
        return self.issues


# --- Git / báo cáo -----------------------------------------------------------
def changed_files(diff_filter):
    out = git("diff", "--name-only", "--no-renames", f"--diff-filter={diff_filter}",
              "-z", f"{BASE}...HEAD")
    return [p for p in out.split("\0") if p.startswith(RULES_DIR) and p.endswith(".xml")]


def count_rules_in_base(path):
    try:
        return count_rules(git("show", f"{BASE}:{path}"))
    except subprocess.CalledProcessError:
        return 0  # file mới


def emit(kind, path, line, msg, show=True):
    COUNT[kind] += 1
    if not show:
        return
    label = "LỖI" if kind == "error" else "CẢNH BÁO"
    text = f"[{label}] " + " | ".join(filter(None, [path, f"dòng {line}" if line else None, msg]))
    if IN_ACTIONS:  # annotation gắn vào đúng file/dòng trong PR
        props = ",".join(filter(None, [f"file={path}" if path else None,
                                       f"line={line}" if line else None]))
        print(f"::{kind}{' ' + props if props else ''}::{text.replace('%', '%25')}")
    else:
        print(f"  {text}")


def check_file(path):
    print(f"\nĐang kiểm tra: {path}")
    with open(path, "rb") as f:
        data = f.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        emit("error", path, data.count(b"\n", 0, e.start) + 1,
             "file không phải UTF-8 hợp lệ (vui lòng lưu lại với mã hoá UTF-8)")
        text = data.decode("utf-8", errors="replace")

    issues = FileChecker(text).run(count_rules_in_base(path))
    for n, (kind, line, msg) in enumerate(issues):
        emit(kind, path, line, msg, show=n < MAX_SHOWN)
    if len(issues) > MAX_SHOWN:
        print(f"  ... và {len(issues) - MAX_SHOWN} vấn đề khác (không hiển thị)")
    if not issues:
        print("  [OK] Không phát hiện lỗi cú pháp/cấu trúc.")


def check_whole_ruleset():
    """Sau PR, thư mục rules/ vẫn phải còn ít nhất một rule."""
    files = [p for p in git("ls-files", "-z", "--", f"{RULES_DIR}*.xml").split("\0") if p]
    total = 0
    for p in files:
        with open(p, "rb") as f:
            total += count_rules(f.read().decode("utf-8", errors="replace"))
    print(f"\nToàn bộ ruleset sau PR: {total} rule trong {len(files)} file .xml")
    if not files:
        emit("error", None, None, f"thư mục {RULES_DIR} không còn file .xml nào: ruleset rỗng")
    elif total == 0:
        emit("error", None, None, f"ruleset rỗng: {len(files)} file .xml nhưng không còn <rule> nào")


def main():
    os.chdir(git("rev-parse", "--show-toplevel").strip())

    deleted = changed_files("D")
    if deleted:
        print("File bị xoá (không kiểm tra cú pháp): " + ", ".join(deleted))
    for path in changed_files("AM"):
        check_file(path)
    check_whole_ruleset()  # luôn chạy, kể cả khi PR chỉ xoá file

    print(f"\nTổng kết: {COUNT['error']} lỗi, {COUNT['warning']} cảnh báo.")
    if COUNT["error"]:
        print("KẾT QUẢ: THẤT BẠI. Vui lòng sửa các lỗi ở trên.")
        return 1
    print("KẾT QUẢ: Cú pháp và cấu trúc XML hợp lệ.")
    return 0


if __name__ == "__main__":
    sys.exit(main())