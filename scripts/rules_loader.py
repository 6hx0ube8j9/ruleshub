# -*- coding: utf-8 -*-
import os
import json
import re


# ---------------- 阶段 1: 全局配置与矩阵定义 ----------------

SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__)) 
PROJECT_ROOT     = os.path.dirname(SCRIPT_DIR)                  

RULESET_BASE_DIR = os.path.join(PROJECT_ROOT, 'ruleset')
SOURCE_DIR       = os.path.join(SCRIPT_DIR, 'source')
MIHOMO_DIR       = os.path.join(RULESET_BASE_DIR, 'mihomo')

RULESET_JSON_PATH = os.path.join(SCRIPT_DIR, 'ruleset.json')
MIHOMO_CORE       = os.path.join(SCRIPT_DIR, 'mihomo-core')
SINGBOX_CORE      = os.path.join(SCRIPT_DIR, 'singbox-core')

CONFIG_KEYS = {
    'SOURCES':   'sync_source',   
    'GROUPS':    'groups', 
    'INPUTS':    'inputs',
    'OUTPUTS':   'outputs',
    'QX_POLICY': 'qx_policy'
}

ROUTING_MATRIX = {
    'loon':              {'dir': os.path.join(RULESET_BASE_DIR, 'loon')},
    'mihomo_classical': {'dir': os.path.join(MIHOMO_DIR, 'classical')},    
    'quantumultx':      {'dir': os.path.join(RULESET_BASE_DIR, 'quantumultx')},    
    'singbox':          {'dir': os.path.join(RULESET_BASE_DIR, 'singbox')},
    'shadowrocket':     {'dir': os.path.join(RULESET_BASE_DIR, 'shadowrocket')},    
    'pac':              {'whitelist': ['direct', 'china'], 'dir': os.path.join(RULESET_BASE_DIR, 'pac')},
    'mihomo_ipcidr':    {'regex': r'(^|[_0-9-])ip([_0-9-]|$)', 'blacklist': ['classic', 'nodomain'], 'dir': os.path.join(MIHOMO_DIR, 'ipcidr')},
    'mihomo_domain':    {'regex': r'^(?!.*(^|[_0-9-])ip([_0-9-]|$)).*$', 'blacklist': ['classic', 'nodomain'], 'dir': os.path.join(MIHOMO_DIR, 'domain')}
}


# ---------------- 阶段 2: 环境初始化与依赖校验 ----------------

def setup_environment():
    """初始化项目运行所需的所有目录环境。"""
    print("[信息] 开始初始化运行目录结构...")
    required_dirs = {RULESET_BASE_DIR, SOURCE_DIR, MIHOMO_DIR}
    required_dirs.update(
        cfg['dir'] for cfg in ROUTING_MATRIX.values() if 'dir' in cfg
    )
    for d in sorted(required_dirs):
        print(f"[信息] 正在确保目录存在: {d}")
        os.makedirs(d, exist_ok=True)

def check_binary_dependencies(config_data):
    """校验并确认是否存在运行规则生成所需的外部二进制工具。"""
    print("[信息] 开始校验外部工具链二进制依赖...")
    need_mihomo  = False
    need_singbox = False

    groups = config_data.get(CONFIG_KEYS['GROUPS'], [])
    for group in groups:
        group_name = group.get('name')
        if not group_name:
            continue
            
        routing_map = resolve_routing(group, group_name)
        
        if 'singbox' in routing_map:
            need_singbox = True
            
        if any(tool_key.startswith('mihomo') for tool_key in routing_map.keys()):
            need_mihomo = True

    missing_bins = []
    if need_mihomo and not os.path.exists(MIHOMO_CORE):
        missing_bins.append(f"Mihomo: {MIHOMO_CORE}")
    if need_singbox and not os.path.exists(SINGBOX_CORE):
        missing_bins.append(f"Sing-box: {SINGBOX_CORE}")
        
    if missing_bins:
        print("[错误] 检测到核心二进制工具链依赖残缺")
        raise FileNotFoundError(
            "[FATAL] 当前配置的输出缺少所需的外部二进制工具链:\n - " + "\n - ".join(missing_bins)
        )
        
    print("[成功] 外部二进制依赖校验全部通过")


# ---------------- 阶段 3: 核心规则过滤引擎 ----------------

class RuleFilter:
    """定义路由平台的规则过滤匹配逻辑。"""

    @staticmethod
    def _filter_whitelist(config, name_lower):
        """执行白名单规则过滤匹配。"""
        if 'whitelist' not in config: return True
        return any(w in name_lower for w in config['whitelist'])

    @staticmethod
    def _filter_blacklist(config, name_lower):
        """执行黑名单规则过滤匹配。"""
        if 'whitelist' in config: return True
        if 'blacklist' not in config: return True
        return not any(b in name_lower for b in config['blacklist'])

    @staticmethod
    def _filter_regex(config, name_lower):
        """执行正则表达式命中匹配。"""
        if 'regex' not in config: return True
        try:
            return bool(re.search(config['regex'], name_lower, re.IGNORECASE))
        except re.error:
            print(f"[错误] 正则表达式解析失败: {config['regex']}")
            return False

    _PIPELINE = [_filter_whitelist, _filter_blacklist, _filter_regex]

    @classmethod
    def evaluate(cls, config, group_name_lower):
        """综合评估当前规则组名称是否通过完整过滤管线。"""
        return all(filter_func(config, group_name_lower) for filter_func in cls._PIPELINE)


# ---------------- 阶段 4: 配置规范化工具函数 ----------------

def _get_normalized_user_value(raw_val):
    """将用户输入的配置值转化为标准类型（布尔值或路径字符串）。"""
    if isinstance(raw_val, str):
        val_lower = raw_val.strip().lower()
        if val_lower in ['true', 'ture']: return True
        if val_lower == 'false':          return False
        if val_lower == '':               return ''
        return raw_val.strip()            
    return raw_val

def _normalize_rule_item(item):
    """确保单项规则文件名后缀合法并补全 .txt 扩展名。"""
    if not isinstance(item, str):
        return item
    
    item_str = item.strip()
    if item_str.startswith(('http://', 'https://')):
        return item_str
        
    item_lower = item_str.lower()
    if not item_lower.endswith('.txt'):
        return f"{item_lower}.txt"
    return item_lower

def _normalize_config_value(val):
    """规范化配置中的规则路径列表并执行去重。"""
    if isinstance(val, str):
        return _normalize_rule_item(val)
        
    if isinstance(val, list):
        cleaned_list      = [_normalize_rule_item(i) for i in val if str(i).strip()]
        deduplicated_list = list(dict.fromkeys(cleaned_list))
        return deduplicated_list
        
    return val


# ---------------- 阶段 5: 配置解析与路由加载器 ----------------

def load_and_prepare_config(json_path):
    """加载配置文件，执行自动纠错、路径补全并同步保存。"""
    print(f"[信息] 正在载入配置文件: {json_path}")
    with open(json_path, 'r', encoding='utf-8') as f:
        config_data = json.load(f)
        
    setup_environment()
    modified = False
    
    sync_source = config_data.get(CONFIG_KEYS['SOURCES'], {})
    for url, targets in sync_source.items():
        norm_targets = _normalize_config_value(targets)
        if norm_targets != targets:
            sync_source[url] = norm_targets
            modified         = True

    for group in config_data.get(CONFIG_KEYS['GROUPS'], []):
        if CONFIG_KEYS['INPUTS'] not in group or not group[CONFIG_KEYS['INPUTS']]:
            group_name = group.get('name', '')
            if group_name:
                group[CONFIG_KEYS['INPUTS']] = [f"{group_name.lower()}.txt"]
                modified                     = True
        else:
            inputs       = group[CONFIG_KEYS['INPUTS']]
            norm_inputs  = _normalize_config_value(inputs)
            if norm_inputs != inputs:
                group[CONFIG_KEYS['INPUTS']] = norm_inputs
                modified                     = True

        group_name = group.get('name')
        outputs    = group.get(CONFIG_KEYS['OUTPUTS'])
        
        if not group_name or not isinstance(outputs, dict):
            continue
            
        group_name_lower = group_name.lower()
        
        for tool_key, config in ROUTING_MATRIX.items():
            if tool_key not in outputs:
                continue  
                
            raw_val  = outputs[tool_key]
            user_val = _get_normalized_user_value(raw_val)
            
            target_val = None
            
            if user_val is True:
                target_val = group_name_lower
            elif user_val == '':
                is_passed  = RuleFilter.evaluate(config, group_name_lower)
                target_val = group_name_lower if is_passed else False
                
            if target_val is not None and raw_val != target_val:
                outputs[tool_key] = target_val
                modified          = True

    if modified:
        print(f"[信息] 监测到配置结构差异，正在回写同步数据: {json_path}")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        print("[成功] 配置文件自动修复并成功保存至 JSON")
        
    check_binary_dependencies(config_data)
        
    return config_data

def resolve_routing(group_config, group_name):
    """根据当前规则组的输出配置生成路由映射矩阵。"""
    print(f"[信息] 正在解析规则组的分流路由映射: {group_name}")
    group_name_lower = group_name.lower()
    raw_outputs      = group_config.get(CONFIG_KEYS['OUTPUTS']) or {}
    routing_map      = {}
    
    for tool_key, config in ROUTING_MATRIX.items():
        if tool_key not in raw_outputs:
            if RuleFilter.evaluate(config, group_name_lower):
                routing_map[tool_key] = group_name_lower
            continue
            
        user_val = raw_outputs[tool_key]
        if isinstance(user_val, str) and user_val.strip() != '':
            routing_map[tool_key] = user_val.strip().lower()
        elif user_val is True:
            routing_map[tool_key] = group_name_lower
            
    return routing_map


# ---------------- 阶段 6: 脚本主执行入口 ----------------

if __name__ == '__main__':
    setup_environment()
    print("[成功] 运行环境初始化目录构建完成")
