import re
import sys

def analyze_slab_file(file_path):
    stats = {
        "active_slab_free": 0,
        "cpu_partial_free": 0,
        "node_partial_free": 0,
        "total_free": 0
    }
    
    current_section = None 

    try:
        with open("./log.txt", 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # 识别区域切换
                if "Active Slab:" in line:
                    current_section = "active"
                elif "Partial Slabs [nr_slabs/cpu_partial_slabs" in line:
                    current_section = "cpu_partial"
                elif "kmem_cache_node" in line:
                    current_section = "node_partial"

                # 解析 In-Use 行
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

if __name__ == "__main__":
    # 你可以从命令行参数读取文件名，或者手动指定
    target_file = "slab_info.txt"  # <--- 在这里修改你的文件名
    
    result = analyze_slab_file(target_file)
    if result:
        print(f"--- 统计报告: {target_file} ---")
        print(f"Active Slab Free:      {result['active_slab_free']}")
        print(f"Per-CPU Partial Free:  {result['cpu_partial_free']}")
        print(f"Per-Node Partial Free: {result['node_partial_free']}")
        print("-" * 30)
        print(f"总计 Free Objects:      {result['total_free']}")