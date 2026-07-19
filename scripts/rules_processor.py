# -*- coding: utf-8 -*-
import re
import logging
import ipaddress
from typing import Tuple, Optional, Dict, Set, List

# 配置基础日志输出
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ---------------- 阶段 1: 核心数据矩阵与配置 ----------------

# 公共后缀黑名单矩阵：用于判定无类型前缀的纯文本域名行是否默认归类为后缀匹配 (suffix)
PUBLIC_SUFFIX_BLACKLIST = {
    'com', 'net', 'org', 'gov', 'edu', 'mil', 'int', 'arpa', 'biz', 'info', 'name', 'pro',
    'app', 'dev', 'shop', 'club', 'top', 'xyz', 'vip', 'fun', 'site', 'online', 'tech', 'store',
    'work', 'live', 'link', 'icu', 'ltd', 'art', 'blog', 'news', 'wiki', 'chat', 'space', 'me',
    'io', 'co', 'ai', 'so', 'to', 'do', 'in', 'cc', 'tv', 'la', 'fm', 'am', 'im', 'gg',
    'run', 'pub', 'network', 'studio', 'design', 'life', 'today', 'world', 'zone', 'host',
    'cn', 'hk', 'tw', 'mo', 'jp', 'kr', 'sg', 'my', 'th', 'vn', 'ph', 'id', 'pk', 'kh', 'mm', 
    'us', 'uk', 'ca', 'au', 'de', 'fr', 'ru', 'it', 'es', 'nl', 'se', 'no', 'fi', 'dk', 'ch', 
    'at', 'be', 'ie', 'nz', 'br', 'za', 'mx', 'ar', 'cl', 'tr', 'il', 'ae', 'sa', 'ua', 'pl',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'mil.cn', 'ac.cn', 'ah.cn', 'bj.cn', 'cq.cn',
    'fj.cn', 'gd.cn', 'gs.cn', 'gx.cn', 'gz.cn', 'ha.cn', 'hb.cn', 'he.cn', 'hi.cn', 'hl.cn',
    'hn.cn', 'jl.cn', 'js.cn', 'jx.cn', 'ln.cn', 'nm.cn', 'nx.cn', 'qh.cn', 'sc.cn', 'sd.cn',
    'sh.cn', 'sn.cn', 'sx.cn', 'tj.cn', 'xj.cn', 'xz.cn', 'yn.cn', 'zj.cn',
    'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk', 'idv.hk', 'hk.org', 'hk.com',
    'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw', 'club.tw', 'ebiz.tw', 'game.tw',
    'com.mo', 'net.mo', 'org.mo', 'gov.mo', 'edu.mo',
    'co.uk', 'me.uk', 'org.uk', 'ltd.uk', 'plc.uk', 'gov.uk', 'sch.uk', 'net.uk',
    'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp', 'ed.jp', 'ad.jp', 'lg.jp',
    'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'go.kr', 'mil.kr', 'ac.kr',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg', 'per.sg',
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my', 'co.id', 'web.id', 'or.id', 'go.id', 'ac.id',
    'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn',
    'com.au', 'net.au', 'org.au', 'asn.au', 'id.au', 'gov.au', 'edu.au',
    'co.nz', 'net.nz', 'org.nz', 'ac.nz', 'govt.nz', 'geek.nz', 'school.nz',
    'com.br', 'net.br', 'org.br', 'gov.br', 'co.za', 'web.za', 'org.za', 'gov.za'
}

# 规则归一化映射字典
_GROUPS = {
    'remove':    {'REMOVE'},
    'process':   {'PROCESS-NAME', 'PROCESS_NAME', 'PROCESS'},
    'port':      {'DST-PORT', 'DEST-PORT', 'PORT'},
    'full':      {'DOMAIN', 'HOST', 'FULL'},
    'suffix':    {'DOMAIN-SUFFIX', 'HOST-SUFFIX', 'DOMAIN_SUFFIX', 'SUFFIX'},
    'keyword':   {'DOMAIN-KEYWORD', 'HOST-KEYWORD', 'DOMAIN_KEYWORD', 'KEYWORD'},
    'ip':        {'IP-CIDR', 'IP'},
    'ip6':       {'IP-CIDR6', 'IP6-CIDR', 'IP6'}, 
    'useragent': {'USER-AGENT', 'USERAGENT'},
    'wildcard':  {'DOMAIN-WILDCARD', 'HOST-WILDCARD', 'WILDCARD'},
    'regex':     {'DOMAIN-REGEX', 'DOMAIN_REGEX', 'REGEX'}
}

SOURCE_KEYS = list(_GROUPS.keys())
RULE_MAP = {rule_name: target_cat for target_cat, rule_sets in _GROUPS.items() for rule_name in rule_sets}

# 严苛的 RFC 域名结构判定正则
STRICT_DOMAIN_REGEX = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')


# ---------------- 阶段 2: 内部私有高精度卡尺工具集 ----------------

def _is_exact_ip(text: str) -> Tuple[Optional[str], str]:
    """高精度精细化 IP 真伪及类型断言卡尺。"""
    if not text:
        return None, ""
    cleaned = text.strip().strip('[]')
    ip_body = cleaned.split('/')[0]
    mask_suffix = f"/{cleaned.split('/')[1]}" if '/' in cleaned else ""
    
    try:
        ip_obj = ipaddress.ip_address(ip_body)
        if ip_obj.version == 4:
            return 'ip', f"{ip_body}{mask_suffix}"
        elif ip_obj.version == 6:
            return 'ip6', f"{ip_body.lower()}{mask_suffix}"
    except ValueError:
        pass
    return None, text


def _is_exact_domain(text: str) -> Optional[str]:
    """高精度域名合法性卡尺（基于 RFC 规范与 Punycode 深度转化）。"""
    if not text or any(c in text for c in ['/', '?', '@', '=', '%', '&', ';', ' ']):
        return None
    domain = text.strip().rstrip('.').lstrip('+*.')
    if not domain:
        return None
        
    if ':' in domain:
        parts = domain.split(':')
        if len(parts) == 2 and parts[1].isdigit():
            domain = parts[0]
            
    if not domain.isascii():
        try:
            domain = domain.encode('idna').decode('ascii')
        except Exception:
            return None
            
    domain = domain.lower()
    if STRICT_DOMAIN_REGEX.match(domain):
        return domain
    return None


def _clean_policy_suffix(line: str) -> str:
    """策略后缀剥离守卫。"""
    first_comma_idx = line.find(',')
    if first_comma_idx != -1:
        head = line[:first_comma_idx].strip().upper()
        if head in RULE_MAP:
            return line
        parts = [p.strip() for p in line.split(',')]
        if parts:
            return parts[0]
    return line


# ---------------- ⚡ 稳健优化工具：高性能轻量字典树 ----------------

class DomainTrie:
    """专为百万级域名降维去重裁剪打造的轻量化逆向字典树"""
    def __init__(self):
        self.root = {}

    def insert_suffix(self, domain: str):
        """插入一条 SUFFIX 规则（倒序插入节点，标记结尾）"""
        parts = domain.split('.')
        current = self.root
        for part in reversed(parts):
            if '__end__' in current: # 已经被更短的父级后缀覆盖，提前剪枝
                return
            current = current.setdefault(part, {})
        current['__end__'] = True

    def is_covered(self, domain: str, is_full: bool = False) -> bool:
        """断言域名是否已被树中的某条记录包含覆盖 (时间复杂度只需等同于域名段数：O(Log N))"""
        parts = domain.split('.')
        current = self.root
        for part in reversed(parts):
            if '__end__' in current:
                return True
            if part not in current:
                return False
            current = current[part]
        # 如果是 FULL 匹配，要求完全走完或被包含；如果是 SUFFIX 且走到了树的尽头，则匹配
        return '__end__' in current if is_full else True


# ---------------- 阶段 3: 主流水线总入口 ----------------

def execute_rules_pipeline(local_raw_lines: List[str], remote_raw_lines: List[str]) -> Dict[str, Set[str]]:
    """主执行流水线。"""
    logging.info(f"开始处理规则，本地: {len(local_raw_lines)} 行，远程: {len(remote_raw_lines)} 行")
    
    local_rules = process_raw_lines_batch(local_raw_lines, SOURCE_KEYS)
    remote_rules = process_raw_lines_batch(remote_raw_lines, SOURCE_KEYS)
    
    merged_rules = merge_and_sovereignty_filter(local_rules, remote_rules, SOURCE_KEYS)
    optimize_domains(merged_rules)
    
    print("[成功] 规则处理流水线全部执行完毕。")
    return merged_rules


# ---------------- 阶段 4: 核心解析与格式收拢断言 ----------------

def filter_raw_line(line: str) -> Optional[str]:
    """剔除注释符号、多余前缀，并精准切除附加的策略后缀。"""
    line = line.split('#')[0].split('//')[0].split(';')[0].strip()
    if not line or line.lower() == 'payload:':
        return None
    if line.startswith('- '):
        line = line[2:].strip()
    return _clean_policy_suffix(line) if line else None


def normalize_rule_line(raw_payload: str, internal_type: Optional[str]) -> Optional[str]:
    """根据类型执行特定格式规范化（实现 O(1) 纯文本级别极速直通）"""
    payload = raw_payload.strip().strip("'").strip('"').strip()
    if not payload:
        return None

    if internal_type == 'port':
        payload = payload.replace('(', '').replace(')', '').replace(':', '-')
        parts = [p.strip() for p in payload.split('-') if p.strip()]
        return '-'.join(parts) if parts else None

    # IP、REMOVE IP、Domain 均已在入口层完成 RFC / 掩码的绝对对齐，此处直接放行
    return payload


def parse_line(line: str) -> Tuple[Optional[str], str]:
    """智能路由单行文本至对应解析器（针对纯文本高频场景的快道拦截优化）"""
    clean_line = filter_raw_line(line)
    if not clean_line:
        return None, ""

    if clean_line.startswith('|'):
        return parse_adguard_rule(clean_line)
        
    if ',' not in clean_line:
        return parse_pure_text_rule(clean_line)
        
    # 只有带逗号的行，才去尝试解析标准前缀
    head, _, _ = clean_line.partition(',')
    head = head.strip().upper()

    if head in RULE_MAP:
        return parse_standard_rule(clean_line)
        
    # 兜底：处理带逗号但不是标准前缀的特殊文本
    return parse_pure_text_rule(clean_line)


def parse_standard_rule(line: str) -> Tuple[Optional[str], str]:
    """解析标准前缀声明的规则（融合了 IP 与 REMOVE 机制的最高主权就地补全）"""
    parts = [x.strip() for x in line.split(',')]
    if not parts or len(parts) < 2:
        return None, ""

    tag = parts[0].upper()
    if tag not in RULE_MAP:
        return None, ""
    internal_type = RULE_MAP[tag]
    
    # 规避多段逗号污染（如正则表达式、USERAGENT等），精准排除策略
    if internal_type not in ['regex', 'wildcard', 'useragent']:
        raw_payload = parts[1]
    else:
        # 针对需要多段逗号的特殊规则，融合高容错兜底与标准白名单（补充 MATCH 策略）
        if len(parts) > 2 and (parts[-1].upper() in ['DIRECT', 'PROXY', 'REJECT', 'REJECT-DROP', 'MATCH'] or len(parts[-1]) < 10):
            raw_payload = ','.join(parts[1:-1]).strip()
        else:
            raw_payload = ','.join(parts[1:]).strip()

    # 1. 跨界污染阻断：阻止域名、进程等规则中误混入 IP
    if internal_type in ['suffix', 'full', 'keyword', 'process']:
        ip_type, _ = _is_exact_ip(raw_payload)
        if ip_type is not None:
            return None, ""

    # 2. 正规 IP 规则校验与掩码就地补全
    if internal_type in ['ip', 'ip6']:
        ip_type, checked_ip = _is_exact_ip(raw_payload)
        if ip_type is None:
            return None, "" 
        if internal_type == 'ip6' and ip_type == 'ip':
            return None, "" 
        if internal_type == 'ip' and ip_type == 'ip6':
            internal_type = 'ip6'
            
        # 就地补全掩码
        raw_payload = checked_ip if '/' in checked_ip else f"{checked_ip}/{'128' if internal_type == 'ip6' else '32'}"

    # 🌟 核心修正 2：当用户输入 REMOVE 指令时，如果载荷是 IP 则就地对齐掩码，如果是域名则完全不碰
    elif internal_type == 'remove':
        ip_type, checked_ip = _is_exact_ip(raw_payload)
        if ip_type is not None:
            raw_payload = checked_ip if '/' in checked_ip else f"{checked_ip}/{'128' if ip_type == 'ip6' else '32'}"

    # 3. 最终清洗与直通
    final_payload = normalize_rule_line(raw_payload, internal_type)
    return (internal_type, final_payload) if final_payload else (None, "")


def parse_pure_text_rule(line: str) -> Tuple[Optional[str], str]:
    """无前缀纯文本分层路由算法。"""
    if '*' in line and not (line.startswith('*.') or line.startswith('+.')):
        return None, ""    
    is_explicit_suffix = line.startswith('+.') or line.startswith('*.') or line.startswith('.')
    clean_val = line.lstrip('+*.')

    ip_type, checked_ip = _is_exact_ip(clean_val)
    if ip_type is not None:
        if is_explicit_suffix:
            return None, "" 
        final_payload = normalize_rule_line(checked_ip, ip_type)
        return (ip_type, final_payload) if final_payload else (None, "")

    exact_domain = _is_exact_domain(clean_val)
    if not exact_domain:
        return None, "" 

    if is_explicit_suffix:
        return 'suffix', exact_domain

    if exact_domain in PUBLIC_SUFFIX_BLACKLIST:
        return None, "" 

    parts = exact_domain.split('.')
    N = len(parts)

    if N == 2:
        return 'suffix', exact_domain
    elif N == 3:
        if f"{parts[1]}.{parts[2]}" in PUBLIC_SUFFIX_BLACKLIST or parts[2] in PUBLIC_SUFFIX_BLACKLIST:
            return 'suffix', exact_domain
        return 'full', exact_domain
    else:
        return 'full', exact_domain


def parse_adguard_rule(line: str) -> Tuple[Optional[str], str]:
    """解析 AdGuard / uBlock 格式规则。"""
    core_content = line.split('^')[0].strip()
    for prefix, internal_type in [('||', 'suffix'), ('|', 'full')]:
        if core_content.startswith(prefix):
            raw_payload = core_content[len(prefix):].strip()
            break
    else:
        return None, "" 

    exact_domain = _is_exact_domain(raw_payload)
    if not exact_domain:
        return None, ""

    final_payload = normalize_rule_line(exact_domain, internal_type)
    return (internal_type, final_payload) if final_payload else (None, "")


# ---------------- 阶段 5: 优化合并与极致树状剪枝 ----------------

def process_raw_lines_batch(lines: List[str], rule_keys: List[str]) -> Dict[str, Set[str]]:
    """批量分发解析。"""
    parsed_rules = {k: set() for k in rule_keys}
    for line in lines:
        r_type, payload = parse_line(line)  
        if payload and r_type in parsed_rules:
            parsed_rules[r_type].add(payload)
    return parsed_rules


def merge_and_sovereignty_filter(local_rules: Dict[str, Set[str]], remote_rules: Dict[str, Set[str]], rule_keys: List[str]) -> Dict[str, Set[str]]:
    """
    ⚡ 稳健优化：消除大内存拷贝拷贝，采用原地集合运算（In-place Operation）
    """
    merged = {}
    local_remove = local_rules.get('remove', set())
    
    # 建立本地资产大集合
    local_all_assets = set()
    for r_type in rule_keys:
        if r_type != 'remove':
            local_all_assets.update(local_rules.get(r_type, set()))

    for r_type in rule_keys:
        if r_type == 'remove':
            # remove 自身进行简单的本地和远程求并集
            merged['remove'] = local_rules.get('remove', set()) | remote_rules.get('remove', set())
            continue

        local_set = local_rules.get(r_type, set())
        remote_set = remote_rules.get(r_type, set())
        
        # ⚡ 工业级内存控制：原地减去冲突资产，阻止生成巨大的中间 Set 副本
        remote_set.difference_update(local_all_assets)
        remote_set.difference_update(local_remove)
        
        # 原地与本地规则取并，再过滤 remove 项
        local_set.update(remote_set)
        local_set.difference_update(local_remove)
        
        merged[r_type] = local_set
        
    return merged


def optimize_domains(rules: Dict[str, Set[str]]) -> None:
    """
    ⚡ 稳健优化：将高频 internal 循环重构为工业级 Trie 树，将复杂度从近似 O(N^2) 直降为 O(N)
    """
    if 'suffix' not in rules or 'full' not in rules: 
        return
        
    trie = DomainTrie()
    
    # 按长度由短到长对所有 SUFFIX 域名排序并构建字典树
    sorted_suffixes = sorted(list(rules['suffix']), key=len)
    optimized_suffixes = set()
    
    for suf in sorted_suffixes:
        # 如果当前后缀已经被树中更短的父级后缀包含（例如已存在 google.com，当前是 mail.google.com），则直接剔除
        if trie.is_covered(suf):
            continue
        trie.insert_suffix(suf)
        optimized_suffixes.add(suf)

    # 精准剪枝 FULL 域名
    optimized_fulls = set()
    for f_dom in rules['full']:
        # 如果 FULL 域名落在了 SUFFIX 的通配树结构内，直接剪枝干掉
        if trie.is_covered(f_dom, is_full=True):
            continue
        optimized_fulls.add(f_dom)

    rules['suffix'] = optimized_suffixes
    rules['full'] = optimized_fulls
    logging.info(f"字典树剪枝完成。保留 SUFFIX: {len(optimized_suffixes)} 个，FULL: {len(optimized_fulls)} 个")
