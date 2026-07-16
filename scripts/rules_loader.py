# -*- coding: utf-8 -*-
import os
import json
import re

# 基础路径定义
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) 
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                  

RULESET_BASE_DIR = os.path.join(PROJECT_ROOT, 'ruleset')
SOURCE_DIR = os.path.join(SCRIPT_DIR, 'source')
MIHOMO_DIR = os.path.join(RULESET_BASE_DIR, 'mihomo')

# 平台分流路由控制矩阵
ROUTING_MATRIX = {
    'loon':             {'dir': os.path.join(RULESET_BASE_DIR, 'loon')},
    'mihomo_classical': {'dir': os.path.join(MIHOMO_DIR, 'classical')},    
    'quantumultx':      {'dir': os.path.join(RULESET_BASE_DIR, 'quantumultx')},    
    'singbox':          {'dir': os.path.join(RULESET_BASE_DIR, 'singbox')},
    'shadowrocket':     {'dir': os.path.join(RULESET_BASE_DIR, 'shadowrocket')},    
    'pac':              {'whitelist': ['direct', 'china'], 'dir': os.path.join(RULESET_BASE_DIR, 'pac')},
    'mihomo_ipcidr':    {'regex': r'(^|[_0-9-])ip([_0-9-]|$)', 'blacklist': ['classic', 'nodomain'], 'dir': os.path.join(MIHOMO_DIR, 'ipcidr')},
    'mihomo_domain':    {'regex': r'^(?!.*(^|[_0-9-])ip([_0-9-]|$)).*$', 'blacklist': ['classic', 'nodomain'], 'dir': os.path.join(MIHOMO_DIR, 'domain')}
}

# 初始化创建所有必需的输出目录
def setup_environment():
    required_dirs = {RULESET_BASE_DIR, SOURCE_DIR, MIHOMO_DIR}
    required_dirs.update(
        cfg['dir'] for cfg in ROUTING_MATRIX.values() if 'dir' in cfg
    )
    for d in sorted(required_dirs):
        os.makedirs(d, exist_ok=True)

# 路由过滤器规则匹配引擎
class RuleFilter:

    # 匹配白名单规则
    @staticmethod
    def _filter_whitelist(config, name_lower):
        if 'whitelist' not in config: return True
        return any(w in name_lower for w in config['whitelist'])

    # 匹配黑名单规则
    @staticmethod
    def _filter_blacklist(config, name_lower):
        if 'whitelist' in config: return True
        if 'blacklist' not in config: return True
        return not any(b in name_lower for b in config['blacklist'])

    # 正则表达式规则匹配
    @staticmethod
    def _filter_regex(config, name_lower):
        if 'regex' not in config: return True
        try:
            return bool(re.search(config['regex'], name_lower, re.IGNORECASE))
        except re.error:
            return False

    # 过滤规则执行管道
    _PIPELINE = [_filter_whitelist, _filter_blacklist, _filter_regex]

    # 执行过滤管道评估
    @classmethod
    def evaluate(cls, config, group_name_lower):
        return all(filter_func(config, group_name_lower) for filter_func in cls._PIPELINE)

# 清洗并规整配置中的用户输入值
def _get_normalized_user_value(raw_val):
    if isinstance(raw_val, str):
        val_lower = raw_val.strip().lower()
        if val_lower in ['true', 'ture']: return True
        if val_lower == 'false':          return False
        if val_lower == '':               return ''
        return raw_val.strip()            
    return raw_val

def _normalize_rule_item(item):
    """
    单字符串补全与规范化核心逻辑
    职责单一：精准过滤网络链接，仅对本地文件名进行小写化与 .txt 后缀补全
    """
    if not isinstance(item, str):
        return item
    
    item_str = item.strip()
    # 精准过滤：如果是网络链接，则不修改（保持原始大小写，不补全后缀）
    if item_str.startswith(('http://', 'https://')):
        return item_str
        
    # 本地文件：转换小写并自动补全 .txt 后缀
    item_lower = item_str.lower()
    if not item_lower.endswith('.txt'):
        return f"{item_lower}.txt"
    return item_lower

def _normalize_config_value(val):
    """
    轻量容器适配器
    消除面条代码：统一处理单个字符串或列表，供 sync_source 和 inputs 共同调用
    """
    if isinstance(val, str):
        return _normalize_rule_item(val)
    if isinstance(val, list):
        return [_normalize_rule_item(i) for i in val]
    return val
    
# 加载 JSON 配置文件并执行自动纠错与补全
def load_and_prepare_config(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        config_data = json.load(f)
        
    setup_environment()  
    modified = False
    
    # ------------------ [新增] sync_source 配置自愈 ------------------
    sync_source = config_data.get('sync_source', {})
    for url, targets in sync_source.items():
        norm_targets = _normalize_config_value(targets)
        if norm_targets != targets:
            sync_source[url] = norm_targets
            modified = True

    # ------------------ [新增] groups.inputs 配置自愈 ------------------
    for group in config_data.get('groups', []):
        if 'inputs' in group and group['inputs'] is not None:
            inputs = group['inputs']
            norm_inputs = _normalize_config_value(inputs)
            if norm_inputs != inputs:
                group['inputs'] = norm_inputs
                modified = True

        # ------------------ 原有 outputs 校验与对齐逻辑 ------------------
        group_name = group.get('name')
        outputs = group.get('outputs')
        
        if not group_name or not isinstance(outputs, dict):
            continue
            
        group_name_lower = group_name.lower()
        
        for tool_key, config in ROUTING_MATRIX.items():
            if tool_key not in outputs:
                continue  
                
            raw_val = outputs[tool_key]
            user_val = _get_normalized_user_value(raw_val)
            
            target_val = None
            
            if user_val is True:
                target_val = group_name_lower
            elif user_val == '':
                is_passed = RuleFilter.evaluate(config, group_name_lower)
                target_val = group_name_lower if is_passed else False
                
            if target_val is not None and raw_val != target_val:
                outputs[tool_key] = target_val
                modified = True

    # 物理落盘自愈：如果有任何标准补全或路由对齐发生，直接覆盖 JSON 文件
    if modified:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        print("[INFO] Configuration self-healed and saved to JSON")
        
    return config_data

# 根据清洗后的配置生成内存路由映射表
def resolve_routing(group_config, group_name):
    group_name_lower = group_name.lower()
    raw_outputs = group_config.get('outputs') or {}
    routing_map = {}
    
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

if __name__ == '__main__':
    setup_environment()
    print("[SUCCESS] Environment setup completed")
