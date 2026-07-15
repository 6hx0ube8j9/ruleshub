# -*- coding: utf-8 -*-
import os
import json
import re

# =========================================================================
# 1. 基础路径定义 (纯静态，无副作用)
# =========================================================================
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__)) 
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                  

RULESET_BASE_DIR = os.path.join(PROJECT_ROOT, 'ruleset')
SOURCE_DIR       = os.path.join(SCRIPT_DIR, 'source')
MIHOMO_DIR       = os.path.join(RULESET_BASE_DIR, 'mihomo')

# =========================================================================
# 2. 🗂️ 统一骨架矩阵 (DRY 原则：单一真理源)
# 👑 规范：矩阵内的特征字符串（如 'direct', 'china'）必须保持全小写，供下游无感知高效匹配
# =========================================================================
ROUTING_MATRIX = {
    # 全局分发平台
    'loon':             {'dir': os.path.join(RULESET_BASE_DIR, 'loon')},
    'mihomo_classical': {'dir': os.path.join(MIHOMO_DIR, 'classical')},    
    'quantumultx':      {'dir': os.path.join(RULESET_BASE_DIR, 'quantumultx')},    
    'singbox':          {'dir': os.path.join(RULESET_BASE_DIR, 'singbox')},
    'shadowrocket':     {'dir': os.path.join(RULESET_BASE_DIR, 'shadowrocket')},    
    'pac':              {'whitelist': ['direct', 'china'], 'dir': os.path.join(RULESET_BASE_DIR, 'pac')},
    # Mihomo MRS 隧道
    'mihomo_ipcidr':    {'regex': r'(^|[_0-9-])ip([_0-9-]|$)', 'blacklist': ['classic', 'nodomain'], 'dir': os.path.join(MIHOMO_DIR, 'ipcidr')},
    'mihomo_domain':    {'regex': r'^(?!.*(^|[_0-9-])ip([_0-9-]|$)).*$', 'blacklist': ['classic', 'nodomain'], 'dir': os.path.join(MIHOMO_DIR, 'domain')}
}

# =========================================================================
# 3. 📂 生命周期管理
# =========================================================================
def setup_environment():
    """
    初始化输出目录，确保所有输出路径物理存在。
    """
    required_dirs = {RULESET_BASE_DIR, SOURCE_DIR, MIHOMO_DIR}
    required_dirs.update(
        cfg['dir'] for cfg in ROUTING_MATRIX.values() if 'dir' in cfg
    )
    for d in sorted(required_dirs):
        os.makedirs(d, exist_ok=True)

# =========================================================================
# 4. ⚙️ 解耦过滤引擎
# =========================================================================
class RuleFilter:
    """
    路由过滤器集合 (静态命名空间类)
    🎯 极致去重：传入的 group_name_lower 必须是已被上游处理过的纯小写字符串。
    """
    @staticmethod
    def _filter_whitelist(config, name_lower):
        if 'whitelist' not in config: return True
        # 👑 隐患消除 1：移除 w.lower() 冗余运行时计算，直接利用硬编码已小写的骨架矩阵
        return any(w in name_lower for w in config['whitelist'])

    @staticmethod
    def _filter_blacklist(config, name_lower):
        if 'whitelist' in config: return True  # 有白名单时，黑名单失效
        if 'blacklist' not in config: return True
        # 👑 隐患消除 2：同样移除 b.lower() 的高频重复清洗动作
        return not any(b in name_lower for b in config['blacklist'])

    @staticmethod
    def _filter_regex(config, name_lower):
        if 'regex' not in config: return True
        try:
            return bool(re.search(config['regex'], name_lower, re.IGNORECASE))
        except re.error:
            return False

    _PIPELINE = [_filter_whitelist, _filter_blacklist, _filter_regex]

    @classmethod
    def evaluate(cls, config, group_name_lower):
        return all(filter_func(config, group_name_lower) for filter_func in cls._PIPELINE)

# =========================================================================
# 5. 🔄 自愈规整与内存路由解析核心
# =========================================================================
def _get_normalized_user_value(raw_val):
    """
    清洗用户输入的临时占位符。
    🚨 职责分离：仅对控制状态（布尔、空值）进行形态收拢，不对自定义字符串内容执行 premature（提前）小写污染。
    """
    if isinstance(raw_val, str):
        val_lower = raw_val.strip().lower()
        if val_lower in ['true', 'ture']: return True
        if val_lower == 'false':          return False
        if val_lower == '':               return ''
        return raw_val.strip()            # 👑 修复点 3：保持原始文本大小写返回，不要在这里提前破坏用户可能定义的特定名称
    return raw_val


def load_and_prepare_config(json_path):
    """
    接口 1：加载配置并执行【就地自愈规整】。
    - "true" -> 强写为 默认组名（纯小写，方便落盘文件对齐）
    - ""     -> 过滤器通过写 默认组名，未通过则强制写为 false 告知关闭
    - 缺失    -> 不处理，走默认内存托管
    """
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
                continue  # 💡 字段直接没有：不作任何干扰，保留其干净状态
                
            raw_val = outputs[tool_key]
            user_val = _get_normalized_user_value(raw_val)
            
            target_val = None
            
            if user_val is True:
                target_val = group_name_lower
            elif user_val == '':
                is_passed = RuleFilter.evaluate(config, group_name_lower)
                target_val = group_name_lower if is_passed else False
                
            # 仅在实际发生变更时执行就地修改
            if target_val is not None and raw_val != target_val:
                outputs[tool_key] = target_val
                modified = True

    # 💾 只有发生过自愈，才回写磁盘文件
    if modified:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        print("📝 [配置自愈] 已将 \"true\" 或 \"\" 占位符转换为确定小写值并写回 JSON！")
        
    return config_data


def resolve_routing(group_config, group_name):
    """
    接口 2：内存路由解析决策引擎。
    🎯 终极防线：在此处对输出的目标文件名/策略组名进行最后的物理文件系统级小写收拢，下游 formatter 拿去后直接进行 IO 即可，不需要再次进行小写转换。
    """
    group_name_lower = group_name.lower()
    raw_outputs = group_config.get('outputs') or {}
    routing_map = {}
    
    for tool_key, config in ROUTING_MATRIX.items():
        # 1. 字段缺失 -> 走自动托管（统一托管至纯小写组名）
        if tool_key not in raw_outputs:
            if RuleFilter.evaluate(config, group_name_lower):
                routing_map[tool_key] = group_name_lower
            continue
            
        # 2. 字段存在 -> 提取用户自定义的静态配置值并执行物理小写强制收拢
        user_val = raw_outputs[tool_key]
        if isinstance(user_val, str) and user_val.strip() != '':
            # 👑 终极防线 4：在此处一次性将其拍平为小写，打通 Linux/Docker 跨平台物理文件读写安全通道
            routing_map[tool_key] = user_val.strip().lower()
        elif user_val is True:
            # 防御性退路：若内存配置由于某种原因未及时持久化，依旧安全退化至纯小写组名
            routing_map[tool_key] = group_name_lower
            
    return routing_map


if __name__ == '__main__':
    setup_environment()
    print("Environment setup completed successfully with Zero-Risk Case Design.")
