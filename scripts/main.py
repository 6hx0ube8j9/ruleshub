# -*- coding: utf-8 -*-
import os
import json
import asyncio
import aiohttp
import subprocess
import sys
import urllib.request
import urllib.error

import rules_loader
import rules_formatter
import rules_processor

# 基础路径与编译工具链路径定义
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) 
RULESET_JSON_PATH = os.path.join(SCRIPT_DIR, 'ruleset.json')
MIHOMO_BIN = os.path.join(SCRIPT_DIR, 'mihomo-bin')
SINGBOX_BIN = os.path.join(SCRIPT_DIR, 'sing-box')

# 异步获取单个URL的规则内容
async def fetch_single_url_async(session, url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        async with session.get(url, headers=headers, timeout=15) as response:
            if response.status == 200:
                text = await response.text(encoding='utf-8', errors='ignore')
                return url, text.splitlines()
            else:
                print(f"[WARN] Fetch failed for {url} (Status: {response.status})")
                return url, None
    except Exception as e:
        print(f"[WARN] Fetch failed for {url} (Error: {e})")
        return url, None

# 批量异步获取所有规则数据
async def async_fetch_all(urls_list):
    if not urls_list:
        return {}
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_single_url_async(session, url) for url in urls_list]
        results = await asyncio.gather(*tasks)
        return dict(results)

# 将下载并清洗后的数据同步写入本地磁盘
def sync_to_disk(sync_config, fetched_data):
    if not sync_config:
        return

    source_keys = rules_processor.source_keys

    for url, targets in sync_config.items():
        if isinstance(targets, str):
            target_list = [targets]
        elif isinstance(targets, list):
            target_list = targets
        else:
            continue
        
        remote_lines = fetched_data.get(url)
        # 仅在下载内容为 None 时判定为失败，避免清空本地数据
        if remote_lines is None:
            print(f"[ERROR] Sync failed, skip update: {url}")
            continue
            
        for target in target_list:
            target = target.strip().lower()
            if not target:
                continue
            filename = target if target.endswith('.txt') else f"{target}.txt"
            file_path = os.path.join(rules_loader.SOURCE_DIR, filename)
            pure_name = os.path.splitext(filename)[0]
            
            # 删除磁盘中可能存在的残留大写同名旧文件
            for raw_f in os.listdir(rules_loader.SOURCE_DIR):
                if raw_f.lower() == filename and raw_f != filename:
                    try:
                        os.remove(os.path.join(rules_loader.SOURCE_DIR, raw_f))
                    except Exception:
                        pass
            
            local_raw = load_local_raw_lines(file_path)
            cleaned_rules = rules_processor.execute_rules_pipeline(local_raw, remote_lines)
            save_local_rules(file_path, pure_name, cleaned_rules, source_keys)
            print(f"[INFO] Merged and saved: {filename} from {url}")

# 读取本地原始文件行数据
def load_local_raw_lines(source_path):
    if not os.path.exists(source_path):
        return []
    with open(source_path, 'r', encoding='utf-8') as f:
        return f.read().splitlines()

# 保存清理排序后的本地规则文件
def save_local_rules(source_path, source_file_name, rules, rule_keys):
    if not any(len(rules.get(k, [])) > 0 for k in rule_keys if k in rules):
        return
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {source_file_name} Combined Base Rules ===\n\n")
        for r_type in rule_keys:
            if rules.get(r_type):
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")

# 清理并规范化本地 source 目录下的文件名
def format_local_sources():
    if not os.path.exists(rules_loader.SOURCE_DIR):
        return

    print("[INFO] Formatting local source files...")
    source_keys = rules_processor.source_keys
    formatted_count = 0

    for filename in os.listdir(rules_loader.SOURCE_DIR):
        if not filename.lower().endswith('.txt'):
            continue
            
        old_file_path = os.path.join(rules_loader.SOURCE_DIR, filename)
        
        # 转换物理文件名至全小写以适配 Linux 大小写敏感特性
        lower_filename = filename.lower()
        new_file_path = os.path.join(rules_loader.SOURCE_DIR, lower_filename)
        pure_name = os.path.splitext(lower_filename)[0]
        
        local_raw = load_local_raw_lines(old_file_path)
        if not local_raw:
            continue
            
        cleaned_rules = rules_processor.execute_rules_pipeline(local_raw, [])
        save_local_rules(new_file_path, pure_name, cleaned_rules, source_keys)
        
        # 删除大写旧文件，避免生成残留
        if old_file_path != new_file_path:
            try:
                os.remove(old_file_path)
            except Exception:
                pass
                
        formatted_count += 1

    print(f"[INFO] Formatting complete. Total files formatted: {formatted_count}")

# 载入并清洗特定策略组所需的全部本地和网络规则
def build_group_rules(group_config):
    group_name = group_config['name']
    inputs = group_config.get('inputs')
    
    all_local_raw = []
    all_remote_raw = []
    
    # 无 inputs 时默认读取本地同名小写文件
    if inputs is None:
        filename = f"{group_name.lower()}.txt"
        file_path = os.path.join(rules_loader.SOURCE_DIR, filename)
        if not os.path.exists(file_path):
            print(f"[WARN] Skip group '{group_name}': Local file '{filename}' not found")
            return None
        all_local_raw.extend(load_local_raw_lines(file_path))
    
    # 依次处理显式定义的输入源
    else:
        if not isinstance(inputs, list):
            inputs = [inputs]
            
        for inp in inputs:
            inp_str = str(inp).strip()
            if not inp_str:
                continue
            
            # 处理远程 HTTP/HTTPS 源（保持 URL 原始大小写）
            if inp_str.startswith('http://') or inp_str.startswith('https://'):
                print(f"[INFO] Fetching network rule: {inp_str}")
                try:
                    req = urllib.request.Request(inp_str, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=15) as response:
                        lines = response.read().decode('utf-8', errors='ignore').splitlines()
                        all_remote_raw.extend(lines)
                except urllib.error.HTTPError as e:
                    print(f"[WARN] Fetch failed: {inp_str} (HTTP {e.code})")
                except urllib.error.URLError as e:
                    print(f"[WARN] Connection failed: {inp_str} ({e.reason})")
                except Exception as e:
                    print(f"[WARN] Fetch error: {inp_str} ({e})")
            
            # 处理本地规则引用（文件名小写化以匹配本地磁盘）
            else:
                clean_name = inp_str.lower()
                filename = clean_name if clean_name.endswith('.txt') else f"{clean_name}.txt"
                file_path = os.path.join(rules_loader.SOURCE_DIR, filename)
                if os.path.exists(file_path):
                    all_local_raw.extend(load_local_raw_lines(file_path))
                else:
                    print(f"[WARN] Local file not found, skip: {filename}")
                    
    final_rules = rules_processor.execute_rules_pipeline(all_local_raw, all_remote_raw)
    return final_rules

# 将整合完毕的规则包分发存储至全局平台数据矩阵
def dispatch_to_matrix(group_name, group_config, rules, global_matrix):
    routing_map = rules_loader.resolve_routing(group_config, group_name)
    outputs = group_config.get('outputs', {})
    
    for plat in rules_loader.ROUTING_MATRIX.keys():
        if plat not in routing_map:
            continue
            
        target_name = routing_map[plat]
        
        if not isinstance(target_name, str) or not target_name:
            continue
                
        if plat == 'quantumultx':
            fallback_label = group_name.capitalize() if group_name.lower() not in ['direct', 'reject'] else group_name.lower()
            qx_policy_label = fallback_label
            if isinstance(outputs, dict) and 'qx_policy' in outputs:
                custom_label = outputs['qx_policy']
                if isinstance(custom_label, str) and custom_label.strip() and str(custom_label).lower() not in ['true', 'false']:
                    qx_policy_label = custom_label.strip()
            
            if target_name not in global_matrix[plat]:
                global_matrix[plat][target_name] = {
                    'policy_label': qx_policy_label,
                    **{k: set() for k in rules.keys()}
                }
            for k in rules:
                if k in global_matrix[plat][target_name]:
                    global_matrix[plat][target_name][k].update(rules[k])                    
        else:
            if target_name not in global_matrix[plat]:
                global_matrix[plat][target_name] = {k: set() for k in rules.keys()}
            for k, v in rules.items():
                global_matrix[plat][target_name][k].update(v)

# 调用二进制转换工具编译 Mihomo MRS 二进制规则集
def compile_mihomo_mrs(base_name, group_config, rules):
    if not os.path.exists(MIHOMO_BIN):
        return
    
    routing_map = rules_loader.resolve_routing(group_config, base_name)
    mrs_tunnels = ['mihomo_ipcidr', 'mihomo_domain']
    
    for tunnel_type in mrs_tunnels:
        if tunnel_type not in routing_map: 
            continue

        target_name = routing_map[tunnel_type]
        if not isinstance(target_name, str) or not target_name:
            continue
            
        sub_dir = 'ipcidr' if tunnel_type == 'mihomo_ipcidr' else 'domain'
        
        formatter = getattr(rules_formatter, f"generate_{tunnel_type}", None)
        content = formatter(rules) if formatter else ""
        if not content: 
            continue

        yaml_path = os.path.join(rules_loader.MIHOMO_DIR, sub_dir, f"{target_name}.yaml")
        mrs_out_path = os.path.join(rules_loader.MIHOMO_DIR, sub_dir, f"{target_name}.mrs")
        
        try:
            with open(yaml_path, 'w', encoding='utf-8') as f:
                f.write(content)
            subprocess.run([MIHOMO_BIN, 'convert-ruleset', sub_dir, 'yaml', yaml_path, mrs_out_path], check=True, capture_output=True)
            print(f"[SUCCESS] Compiled MRS: {target_name}.mrs ({sub_dir})")
        except subprocess.CalledProcessError:
            print(f"[ERROR] Failed to compile MRS: {target_name} ({sub_dir})")

# 调用二进制转换工具编译 Sing-box SRS 二进制规则集
def compile_singbox_srs(global_matrix, singbox_dir):
    if not os.path.exists(SINGBOX_BIN) or not global_matrix.get('singbox'): 
        return

    for g_name, raw_rules in global_matrix['singbox'].items():
        sb_path = os.path.join(singbox_dir, f"{g_name}.json")
        sb_srs_path = os.path.join(singbox_dir, f"{g_name}.srs")

        if not os.path.exists(sb_path): 
            continue

        try:
            subprocess.run([SINGBOX_BIN, 'rule-set', 'compile', sb_path, '-o', sb_srs_path], check=True, capture_output=True)
            print(f"[SUCCESS] Compiled SRS: {g_name}.srs")
        except subprocess.CalledProcessError:
            print(f"[ERROR] Failed to compile SRS: {g_name}.json")

# 主程序生命周期控制
def main():
    # 阶段 1：载入规则配置
    print("[INFO] Stage 1: Loading rules configuration...")
    try:
        config_data = rules_loader.load_and_prepare_config(RULESET_JSON_PATH)
    except (FileNotFoundError, ValueError) as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    sync_source = config_data.get('sync_source', {})
    groups = config_data.get('groups', [])
    
    # 格式化本地源文件，防止大小写冲突
    format_local_sources()

    # 阶段 2：网络规则拉取与同步
    print("\n[INFO] Stage 2: Syncing local rules...")
    urls_to_fetch = list(sync_source.keys())
    if urls_to_fetch:
        print(f"[INFO] Fetching {len(urls_to_fetch)} network sources asynchronously...")
        fetched_data = asyncio.run(async_fetch_all(urls_to_fetch))
        print("[INFO] Saving synced data to local disk...")
        sync_to_disk(sync_source, fetched_data)
    else:
        print("[INFO] No sync sources defined, skipping sync.")

    # 阶段 3：策略组分发与合并
    print("\n[INFO] Stage 3: Dispatching group rules...")
    global_matrix = {plat: {} for plat in rules_loader.ROUTING_MATRIX.keys()}
    group_rules_cache = {}  
    
    for group_config in groups:
        group_name = group_config.get('name')
        if not group_name:
            continue
            
        print(f"[INFO] Dispatching group: {group_name}")
        rules_in_memory = build_group_rules(group_config)
        if rules_in_memory is None:
            continue
            
        group_rules_cache[group_name] = (group_config, rules_in_memory)
        dispatch_to_matrix(group_name, group_config, rules_in_memory, global_matrix)

    # 阶段 4：平台文件导出与工具链编译
    print("\n[INFO] Stage 4: Exporting and compiling files...")
    
    output_directories = {
        plat: cfg['dir'] 
        for plat, cfg in rules_loader.ROUTING_MATRIX.items() 
        if 'dir' in cfg and plat not in ('mihomo_ipcidr', 'mihomo_domain')
    }
    
    # 导出文本形式配置文件
    rules_formatter.export_all(
        global_matrix = global_matrix,
        dir_map = output_directories
    )
    
    # 执行 Mihomo 二进制转换
    for group_name, (group_config, rules) in group_rules_cache.items():
        compile_mihomo_mrs(group_name, group_config, rules)
        
    # 执行 Sing-box 二进制编译
    if 'singbox' in output_directories:
        compile_singbox_srs(global_matrix, output_directories['singbox'])

if __name__ == '__main__':
    main()
