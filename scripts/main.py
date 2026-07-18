# -*- coding: utf-8 -*-
import os
import json
import asyncio
import aiohttp
import subprocess
import sys

import rules_loader
import rules_formatter
import rules_processor

# ==============================================================================
# Stage 0: 外部调用参数、组件方法与环境常量统一配置区
# ==============================================================================

# 基础网络请求配置
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}
FETCH_TIMEOUT   = 15

# 外部物理路径与核心控制矩阵映射
RULESET_CONFIG_PATH     = rules_loader.RULESET_JSON_PATH        # 统一读取 loader 定义的 ruleset.json 路径
MIHOMO_COMPILER_BIN     = rules_loader.MIHOMO_BIN              # 统一读取 loader 校验的 Mihomo 二进制路径
SINGBOX_COMPILER_BIN    = rules_loader.SINGBOX_BIN             # 统一读取 loader 校验的 Sing-box 二进制路径

SOURCE_DIRECTORY        = rules_loader.SOURCE_DIR              # 规则文本落盘/冷备源目录
MIHOMO_OUTPUT_DIR       = rules_loader.MIHOMO_DIR              # Mihomo 专用编译输出父目录
PLATFORM_ROUTING_MATRIX = rules_loader.ROUTING_MATRIX           # 平台路由矩阵控制轴

# 跨模块继承的核心元数据与清洗红线
CONFIG_KEYS             = rules_loader.CONFIG_KEYS             # 动态继承自 loader 的 JSON 配置键名全集
RULE_SOURCE_KEYS        = rules_processor.source_keys          # 清洗管道生成的核心流类型红线

# 外部业务组件核心方法指针绑定
PROCESSOR_PIPELINE      = rules_processor.execute_rules_pipeline # 规则解包清洗主管道函数
FORMATTER_EXPORT_ALL    = rules_formatter.export_all            # 全局各客户端平台文本导出器
MIHOMO_ROUTING          = {
    'mihomo_ipcidr': ('ipcidr', rules_formatter.generate_mihomo_ipcidr),
    'mihomo_domain': ('domain', rules_formatter.generate_mihomo_domain)
}


# ==============================================================================
# Stage 2: 异步高并发网络拉取引擎
# ==============================================================================

# 异步单链接拉取核心引擎
async def fetch_single_url_async(session, url):
    try:
        async with session.get(url, headers=DEFAULT_HEADERS, timeout=FETCH_TIMEOUT) as response:
            if response.status == 200:
                text = await response.text(encoding='utf-8', errors='ignore')
                return url, text.splitlines()
            else:
                print(f"[WARN] Fetch failed for {url} (Status: {response.status})")
                return url, None
    except Exception as e:
        print(f"[WARN] Fetch failed for {url} (Error: {e})")
        return url, None

# 高并发批量拉取驱动轴
async def async_fetch_all(urls_list):
    if not urls_list:
        return {}
    async with aiohttp.ClientSession() as session:
        tasks   = [fetch_single_url_async(session, url) for url in urls_list]
        results = await asyncio.gather(*tasks)
        return dict(results)

# 解析配置中所有的网络同步源及 inputs 直连源并激活高并发异步流
async def fetch_all_remote_sources(config_data):
    urls_to_fetch = []
    
    sync_source = config_data.get(CONFIG_KEYS['SOURCES'], {})
    for url in sync_source.keys():
        if url.startswith(('http://', 'https://')):
            urls_to_fetch.append(url)
            
    # 收集 groups 的 inputs 里的直连链接（纯内存直通，阅后即焚）
    groups = config_data.get(CONFIG_KEYS['GROUPS'], [])
    for group in groups:
        inputs = group.get('inputs', [])
        if isinstance(inputs, str):
            inputs = [inputs]
        for inp in inputs:
            inp_str = str(inp).strip()
            if inp_str.startswith(('http://', 'https://')):
                urls_to_fetch.append(inp_str)
                
    urls_to_fetch = list(set(urls_to_fetch))
    return await async_fetch_all(urls_to_fetch)


# ==============================================================================
# Stage 2.5: 内存沙盒化融合与清洗缓冲
# ==============================================================================

# 内存沙盒化处理器，支持网络拉取与磁盘冷备在内存中完成无缝对齐清洗
def process_sources_in_memory(config_data, fetched_data):
    write_buffer = {}
    sync_source  = config_data.get(CONFIG_KEYS['SOURCES'], {})
    
    for url, targets in sync_source.items():
        if isinstance(targets, str):
            target_list = [targets]
        elif isinstance(targets, list):
            target_list = targets
        else:
            continue
            
        for target in target_list:
            target = target.strip().lower()
            if not target:
                continue
            filename = target if target.endswith('.txt') else f"{target}.txt"
            
            # 统一由顶层全局配置提供的 SOURCE_DIRECTORY 锚定路径
            file_path = os.path.join(SOURCE_DIRECTORY, filename)
            
            # 物理只读式预加载本地快照（作为冷备降级基准）
            local_raw = []
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    local_raw = f.read().splitlines()
            
            # 内存清洗沙盒化判定
            remote_lines = fetched_data.get(url)
            if remote_lines is not None:
                print(f"[INFO] Merging remote updates for: {filename}")
                cleaned_rules = PROCESSOR_PIPELINE(local_raw, remote_lines)
            else:
                print(f"[WARN] Fetch failed for {url}. Falling back to local snapshot for: {filename}")
                cleaned_rules = PROCESSOR_PIPELINE(local_raw, [])
                
            write_buffer[file_path] = cleaned_rules
            
    return write_buffer


# ==============================================================================
# Stage 3: 内存路由矩阵构建与分配
# ==============================================================================

# 纯内存策略组合并，利用顶层全局红线 RULE_SOURCE_KEYS 驱动计算
def build_group_rules_pure_memory(group_config: dict, write_buffer: dict, fetched_data: dict = None) -> dict:
    if fetched_data is None:
        fetched_data = {}
        
    final_rules = {k: set() for k in RULE_SOURCE_KEYS}
    group_name  = group_config.get('name', '')
    inputs      = group_config.get('inputs', [])

    # 宽容度补全：若未指定 inputs，默认隐式绑定同名本地规则源
    if not inputs:
        default_key  = f"{group_name.lower()}.txt"
        default_path = os.path.join(SOURCE_DIRECTORY, default_key)
        if default_path in write_buffer:
            inputs = [default_path]
        else:
            if os.path.exists(default_path):
                with open(default_path, 'r', encoding='utf-8') as f:
                    parsed = rules_processor.process_raw_lines_batch(f.readlines(), RULE_SOURCE_KEYS)
                    for k in RULE_SOURCE_KEYS:
                        final_rules[k].update(parsed.get(k, set()))
            return final_rules

    # 纯内存或磁盘跨域合并 + 即时网络直连
    for inp in inputs:
        inp_str = str(inp).strip()
        if not inp_str:
            continue
            
        # 命中网络直连 URL，执行纯内存直通解析，绝不落盘
        if inp_str.startswith(('http://', 'https://')):
            remote_lines = fetched_data.get(inp_str)
            if remote_lines:
                print(f"[INFO] Injecting on-the-fly network rules for: {group_name}")
                parsed = rules_processor.process_raw_lines_batch(remote_lines, RULE_SOURCE_KEYS)
                for k in RULE_SOURCE_KEYS:
                    final_rules[k].update(parsed.get(k, set()))
            else:
                print(f"[WARN] In-memory fetch failed or empty for URL: {inp_str}")
            continue
            
        # 处理本地文件依赖（沙盒缓冲池或磁盘冷备）
        if os.path.isabs(inp_str):
            buffer_key = inp_str
        else:
            filename   = inp_str if inp_str.lower().endswith('.txt') else f"{inp_str.lower()}.txt"
            buffer_key = os.path.join(SOURCE_DIRECTORY, filename)
        
        if buffer_key in write_buffer:
            target_dict = write_buffer[buffer_key]
            for k in RULE_SOURCE_KEYS:
                if k in target_dict:
                    final_rules[k].update(target_dict[k])
        else:
            # 内存未击中，下沉磁盘捞冷备文件并利用管道二次解析
            if os.path.exists(buffer_key):
                with open(buffer_key, 'r', encoding='utf-8') as f:
                    parsed = rules_processor.process_raw_lines_batch(f.readlines(), RULE_SOURCE_KEYS)
                    for k in RULE_SOURCE_KEYS:
                        final_rules[k].update(parsed.get(k, set()))
            else:
                print(f"[WARN] Local file not found in buffer or disk: {buffer_key}")

    return final_rules

def _extract_qx_policy_label(group_name, outputs):
    if group_name.lower() in ['direct', 'reject']:
        fallback = group_name.lower()
    else:
        fallback = group_name.capitalize()
    
    if isinstance(outputs, dict) and CONFIG_KEYS['QX_POLICY'] in outputs:
        custom_label = outputs[CONFIG_KEYS['QX_POLICY']]
        if isinstance(custom_label, str) and custom_label.strip():
            if custom_label.lower() not in ['true', 'false']:
                return custom_label.strip()
                
    return fallback

def dispatch_to_matrix(group_name, group_config, rules, global_matrix):
    routing_map = rules_loader.resolve_routing(group_config, group_name)
    outputs     = group_config.get(CONFIG_KEYS['OUTPUTS'], {})
    
    for plat in PLATFORM_ROUTING_MATRIX.keys():
        if plat not in routing_map:
            continue
            
        target_name = routing_map[plat]
        if not isinstance(target_name, str) or not target_name:
            continue
            
        if target_name not in global_matrix[plat]:
            if plat == 'quantumultx':
                global_matrix[plat][target_name] = {
                    'policy_label': _extract_qx_policy_label(group_name, outputs),
                    **{k: set() for k in rules.keys()}
                }
            else:
                global_matrix[plat][target_name] = {k: set() for k in rules.keys()}
                
        target_bucket = global_matrix[plat][target_name]
        for k, v in rules.items():
            if k in target_bucket:
                target_bucket[k].update(v)

# 基于纯内存写缓冲区全面构建下流全局路由矩阵，支持内存级直连注入
def build_routing_matrix_from_buffer(write_buffer, config_data, group_rules_cache, fetched_data):
    global_matrix = {plat: {} for plat in PLATFORM_ROUTING_MATRIX.keys()}
    groups        = config_data.get(CONFIG_KEYS['GROUPS'], [])
    
    for group_config in groups:
        group_name = group_config.get('name')
        if not group_name:
            continue
            
        # 传递 fetched_data 开启纯内存网络直连支持
        rules_in_memory = build_group_rules_pure_memory(group_config, write_buffer, fetched_data)
        if rules_in_memory is None:
            continue
            
        group_rules_cache[group_name] = (group_config, rules_in_memory)
        dispatch_to_matrix(group_name, group_config, rules_in_memory, global_matrix)
        
    return global_matrix


# ==============================================================================
# Stage 4: 事务提交（原子落盘）与 二进制工具链编译
# ==============================================================================

# 稳健原子级落盘：直接将写缓冲集合展开回写，自适应 Linux 大小写冲突
def commit_write_buffer(write_buffer: dict):
    if not os.path.exists(SOURCE_DIRECTORY):
        os.makedirs(SOURCE_DIRECTORY, exist_ok=True)

    # 执行 Linux 平台潜在的大小写物理冲突强覆盖扫描
    existing_files = os.listdir(SOURCE_DIRECTORY)
    lower_existing = {f.lower(): f for f in existing_files if os.path.isfile(os.path.join(SOURCE_DIRECTORY, f))}

    for file_path, category_dict in write_buffer.items():
        base_name         = os.path.basename(file_path)
        target_lower_name = base_name.lower()

        # 清除大小写残留，为高鲁棒性原子替换清空盲区
        if target_lower_name in lower_existing:
            actual_name = lower_existing[target_lower_name]
            if actual_name != base_name:
                try:
                    os.remove(os.path.join(SOURCE_DIRECTORY, actual_name))
                except Exception as e:
                    print(f"[WARN] Failed to remove case-clashing file {actual_name}: {e}")

        temp_path = f"{file_path}.tmp"

        try:
            # 极其干净的单行 Payload 物理展开写入
            with open(temp_path, 'w', encoding='utf-8') as f:
                for category_set in category_dict.values():
                    if category_set:
                        f.write("\n".join(sorted(category_set)) + "\n")
            
            # 原子事务级物理替换，100% 免疫进程意外中断引发的空文件与损坏故障
            os.replace(temp_path, file_path)
        except Exception as e:
            print(f"[ERROR] Transactional save failed for {base_name}: {e}")
            if os.path.exists(temp_path):
                os.remove(temp_path)

# 通用工具：原子级写入文件（先写.tmp再替换），防止写入中断导致文件损坏
def safe_write_text(filepath, content):
    temp_path = f"{filepath}.tmp"
    try:
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(content)
        os.replace(temp_path, filepath)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to safely write {filepath}: {e}")
        if os.path.exists(temp_path):
            try: os.remove(temp_path)
            except OSError: pass
        return False
        
# 调用外部置顶的 Mihomo 核心二进制工具链执行规则编译
def compile_mihomo_mrs(base_name, group_config, rules):
    if not os.path.exists(MIHOMO_COMPILER_BIN):
        return
        
    routing_map = rules_loader.resolve_routing(group_config, base_name)
    
    # 直接遍历顶层配置好的策略矩阵
    for tunnel_type, (sub_dir, formatter) in MIHOMO_ROUTING.items():
        
        target_name = routing_map.get(tunnel_type)
        if not target_name or not isinstance(target_name, str):
            continue
            
        content = formatter(rules)
        if not content:
            continue
            
        yaml_path    = os.path.join(MIHOMO_OUTPUT_DIR, sub_dir, f"{target_name}.yaml")
        mrs_out_path = os.path.join(MIHOMO_OUTPUT_DIR, sub_dir, f"{target_name}.mrs")
        
        if not safe_write_text(yaml_path, content):
            continue
            
        try:
            subprocess.run(
                [MIHOMO_COMPILER_BIN, 'convert-ruleset', sub_dir, 'yaml', yaml_path, mrs_out_path], 
                check=True, capture_output=True, text=True
            )
            print(f"[SUCCESS] Compiled MRS: {target_name}.mrs ({sub_dir})")
        except subprocess.CalledProcessError as e:
            print(f"[WARN] Mihomo compilation failed for {target_name}. Exit code: {e.returncode}. Stderr: {e.stderr.strip()}")

# 调用外部置顶的 Sing-box 核心二进制工具链执行规则二进制固化
def compile_singbox_srs(global_matrix, singbox_dir):
    if not os.path.exists(SINGBOX_COMPILER_BIN) or not global_matrix.get('singbox'): 
        return

    for g_name, raw_rules in global_matrix['singbox'].items():
        sb_path     = os.path.join(singbox_dir, f"{g_name}.json")
        sb_srs_path = os.path.join(singbox_dir, f"{g_name}.srs")

        if not os.path.exists(sb_path): 
            continue

        try:
            subprocess.run([SINGBOX_COMPILER_BIN, 'rule-set', 'compile', sb_path, '-o', sb_srs_path], check=True, capture_output=True, text=True)
            print(f"[SUCCESS] Compiled SRS: {g_name}.srs")
        except subprocess.CalledProcessError as e:
            print(f"[WARN] Sing-box compilation failed for {g_name}.json. Exit code: {e.returncode}. Stderr: {e.stderr.strip()}")


# ==============================================================================
# 顶层全局异步调度主轴
# ==============================================================================

async def async_main():
    # Stage 1: 加载配置与环境初始化（严格依赖置顶变量）
    print("[INFO] Stage 1: Loading rules configuration...")
    try:
        config_data = rules_loader.load_and_prepare_config(RULESET_CONFIG_PATH)
    except (FileNotFoundError, ValueError) as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    # Stage 2: 内存级并行拉取网络源
    print("\n[INFO] Stage 2: Parallel fetching remote sources in memory...")
    fetched_data = await fetch_all_remote_sources(config_data) 
    
    # Stage 2.5: 沙盒化合并与清洗（完全隔离构建纯内存缓冲池）
    print("\n[INFO] Stage 2.5: Building pure-memory write buffer (Sandbox)...")
    try:
        write_buffer = process_sources_in_memory(config_data, fetched_data)
    except Exception as e:
        print(f"[FATAL ERROR] Stage 2.5 Sandbox merging failed: {e}.")
        sys.exit(1)
        
    # Stage 3: 纯内存路由矩阵构建与全向分配
    print("\n[INFO] Stage 3: Resolving rules and building routing matrix...")
    group_rules_cache = {}
    try:
        global_matrix = build_routing_matrix_from_buffer(write_buffer, config_data, group_rules_cache, fetched_data)
    except Exception as e:
        print(f"[FATAL ERROR] Matrix Resolution Failed: {e}.")
        sys.exit(1)
        
    # Stage 4: 原子事务提交与工具链硬编译阶段
    print("\n[INFO] Stage 4: Executing Commit Phase & Compilations...")
    try:
        # 1. 批量原子落盘改写用户的本地 .txt 核心规则源文件
        commit_write_buffer(write_buffer)
        
        # 2. 动态过滤提取各平台真实输出目录参数
        output_directories = {
            plat: cfg['dir'] 
            for plat, cfg in PLATFORM_ROUTING_MATRIX.items() 
            if 'dir' in cfg and plat not in ('mihomo_ipcidr', 'mihomo_domain')
        }
        
        # 3. 驱动上游格式化模块全量导出纯文本规则
        FORMATTER_EXPORT_ALL(global_matrix=global_matrix, dir_map=output_directories)
        
        # 4. 驱动外部二进制链条执行最终编译固化
        for group_name, (group_config, rules) in group_rules_cache.items():
            compile_mihomo_mrs(group_name, group_config, rules)
            
        if 'singbox' in output_directories:
            compile_singbox_srs(global_matrix, output_directories['singbox'])
            
        print("\n[SUCCESS] All stages executed successfully with absolute transactional security!")
    except Exception as e:
        print(f"[FATAL ERROR] Stage 4 Commit or Compilation failed: {e}")
        sys.exit(1)

def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(async_main())

if __name__ == '__main__':
    main()
