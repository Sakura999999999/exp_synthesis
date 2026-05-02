import re
import sys

ADDR_RE = re.compile(r'0x[0-9a-fA-F]+')
# 匹配单个 slab 的起始行，例如：
#   "- Slab @ 0xffff8881083f6000 [0xffffea000420fd80]:"
#   "Slab @ 0xffff8881083f6000"
#   "Slab: 0xffff8881083f6000"
# 但 **不要** 匹配整个 cache 的头 "Slab Cache @ 0x..." 或属性 "Slab size: 0x1000"。
SLAB_HEADER_RE = re.compile(r'\b[Ss]lab\s*[:@]\s*0x[0-9a-fA-F]+')

# 外层 scope：每个 slab 归属的是哪种管理结构
#   kmem_cache_cpu  @ 0xXXX [CPU 0]:          -> per-CPU
#   kmem_cache_node @ 0xXXX [NUMA node 0, ...]:-> per-Node
CPU_OWNER_RE = re.compile(r'kmem_cache_cpu\s*@\s*0x[0-9a-fA-F]+\s*\[([^\]]+)\]')
NODE_OWNER_RE = re.compile(r'kmem_cache_node\s*@\s*0x[0-9a-fA-F]+\s*\[([^\]]+)\]')

# 内层 section：当前 scope 内该 slab 落在哪条链上
#   per-CPU  下有 "Active Slab" 和 "Partial Slabs"（即 CPU partial list）
#   per-Node 下只有 "Partial Slabs"
SECTION_KEYWORDS = [
    "Active Slab:",
    "Partial Slabs",
]

DEFAULT_INPUT = "./log.txt"


def is_section_header(line):
    return any(k in line for k in SECTION_KEYWORDS)


def is_slab_header(line):
    return bool(SLAB_HEADER_RE.search(line))


def analyze_slab_file(file_path):
    stats = {
        "active_slab_free": 0,
        "cpu_partial_free": 0,
        "node_partial_free": 0,
        "total_free": 0,
    }
    current_section = None

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if "Active Slab:" in line:
                    current_section = "active"
                elif "Partial Slabs [nr_slabs/cpu_partial_slabs" in line:
                    current_section = "cpu_partial"
                elif "kmem_cache_node" in line:
                    current_section = "node_partial"

                if "In-Use:" in line:
                    match = re.search(r"In-Use: (\d+)/(\d+)", line)
                    if match:
                        in_use = int(match.group(1))
                        total_in_slab = int(match.group(2))
                        free_in_slab = total_in_slab - in_use
                        if current_section == "active":
                            stats["active_slab_free"] += free_in_slab
                        elif current_section == "cpu_partial":
                            stats["cpu_partial_free"] += free_in_slab
                        elif current_section == "node_partial":
                            stats["node_partial_free"] += free_in_slab
                        stats["total_free"] += free_in_slab
        return stats
    except FileNotFoundError:
        print(f"错误：找不到文件 '{file_path}'")
        return None


def _owner_label(line):
    """若该行是 per-CPU / per-Node 归属头，返回标签字符串；否则 None。"""
    m = CPU_OWNER_RE.search(line)
    if m:
        return f"per-CPU [{m.group(1).strip()}]"
    m = NODE_OWNER_RE.search(line)
    if m:
        return f"per-Node [{m.group(1).strip()}]"
    return None


def _section_label(line):
    """若该行是内层 section 行（Active Slab / Partial Slabs），返回标签；否则 None。"""
    s = line.strip()
    if s.startswith("Active Slab"):
        return "Active Slab"
    if s.startswith("Partial Slabs") or s.startswith("- Partial Slabs"):
        return "Partial Slabs"
    if "Active Slab" in s and s.endswith(":"):
        return "Active Slab"
    if "Partial Slabs" in s and (":" in s):
        return "Partial Slabs"
    return None


def parse_blocks(file_path):
    """把 slab info 文件切成若干 (owner, section, slab_block_lines)。

    - owner:   外层归属，如 'per-CPU [CPU 0]' 或 'per-Node [NUMA node 0, ...]'
    - section: 内层 section，如 'Active Slab' 或 'Partial Slabs'
    - slab_block_lines: 一个 slab 对应的原始文本行列表，从 `Slab:` / `Slab @` 开始，
      到下一个 slab header / 内层 section / 外层 owner 之前结束。
    """
    blocks = []
    current_owner = ""
    current_section = ""
    current_block = None

    def flush():
        nonlocal current_block
        if current_block is not None:
            blocks.append((current_owner, current_section, current_block))
            current_block = None

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.rstrip('\n')

                owner = _owner_label(line)
                if owner is not None:
                    flush()
                    current_owner = owner
                    current_section = ""
                    continue

                section = _section_label(line)
                if section is not None:
                    flush()
                    current_section = section
                    continue

                if is_slab_header(line):
                    flush()
                    current_block = [line]
                    continue

                if current_block is not None:
                    current_block.append(line)
    except FileNotFoundError:
        print(f"错误：找不到文件 '{file_path}'")
        return None

    flush()
    return blocks


def find_slab_for_addr(blocks, target_addr, page_mask=~0xFFF):
    """返回所有包含 target_addr 的 slab 块（理论上 order-0 slab 只会命中一个）。

    判定方式：只要该 slab 块里出现的任何地址的 page base（addr & ~0xFFF）
    与 target_addr 的 page base 相同，就算命中。
    """
    target_page = target_addr & page_mask
    matches = []
    for owner, section, block_lines in blocks:
        hit = False
        for line in block_lines:
            for m in ADDR_RE.findall(line):
                try:
                    a = int(m, 16)
                except ValueError:
                    continue
                if (a & page_mask) == target_page:
                    hit = True
                    break
            if hit:
                break
        if hit:
            matches.append((owner, section, block_lines))
    return matches


def print_stats(result, file_path):
    print(f"--- 统计报告: {file_path} ---")
    print(f"Active Slab Free:      {result['active_slab_free']}")
    print(f"Per-CPU Partial Free:  {result['cpu_partial_free']}")
    print(f"Per-Node Partial Free: {result['node_partial_free']}")
    print("-" * 30)
    print(f"总计 Free Objects:      {result['total_free']}")


def usage():
    print("用法:")
    print(f"  python3 {sys.argv[0]}              # 汇总统计（读取 {DEFAULT_INPUT}）")
    print(f"  python3 {sys.argv[0]} <address>    # 查找包含该地址的 slab 并打印原始信息")
    print("示例:")
    print(f"  python3 {sys.argv[0]} 0xffff888012345200")


if __name__ == "__main__":
    file_path = DEFAULT_INPUT
    target_addr = None

    args = sys.argv[1:]
    if args:
        if args[0] in ("-h", "--help"):
            usage()
            sys.exit(0)
        try:
            target_addr = int(args[0], 16)
        except ValueError:
            print(f"错误：'{args[0]}' 不是合法的 16 进制地址")
            usage()
            sys.exit(1)

    if target_addr is None:
        result = analyze_slab_file(file_path)
        if result:
            print_stats(result, file_path)
        sys.exit(0)

    blocks = parse_blocks(file_path)
    if blocks is None:
        sys.exit(1)

    matches = find_slab_for_addr(blocks, target_addr)
    if not matches:
        print(f"[-] 未在 {file_path} 中找到包含地址 0x{target_addr:x} 的 slab")
        sys.exit(1)

    for i, (owner, section, lines) in enumerate(matches):
        # 归属信息：per-CPU [CPU 0] / Active Slab
        tag_parts = []
        if owner:
            tag_parts.append(owner)
        if section:
            tag_parts.append(section)
        tag = " / ".join(tag_parts) if tag_parts else "unknown"

        # 简单判定 per-CPU / per-Node 并在最显眼位置点出来
        if owner.startswith("per-CPU"):
            kind = "per-CPU"
        elif owner.startswith("per-Node"):
            kind = "per-Node"
        else:
            kind = "unknown"

        print(f"=== match #{i + 1}  <{kind}>  [{tag}] ===")
        for l in lines:
            print(l)
        print()
