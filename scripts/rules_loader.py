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

# 加载 JSON 配置文件并执行自动纠错与补全
def load_and_prepare_config(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        config_data = json.load(f)
        
    setup_environment()  
    modified = False
    
    for group in config_data.get('groups', []):
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
