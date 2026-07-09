var IP_ADDRESS = '127.0.0.1:7891';
var PROXY_METHOD = 'SOCKS5 ' + IP_ADDRESS + '; SOCKS ' + IP_ADDRESS + '; DIRECT';

var DIRECT_DOMAINS = {
};

var PRIVATE_IP_REGEXP = /^(127|10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\./;
var IS_IPV4_REGEXP = /^\d+\.\d+\.\d+\.\d+$/;
var IS_IPV6_REGEXP = /^\[.*\]$/;

function FindProxyForURL(url, host) {
    if (isPlainHostName(host)) {
        return "DIRECT";
    }

    if (IS_IPV4_REGEXP.test(host)) {
        if (PRIVATE_IP_REGEXP.test(host)) return "DIRECT"; 
    } else if (IS_IPV6_REGEXP.test(host)) {
        if (host === "[::1]" || host.indexOf("[fe80") === 0) return "DIRECT"; 
    }

    var suffix = host.toLowerCase();
    while (suffix) {
        if (DIRECT_DOMAINS.hasOwnProperty(suffix)) {
            return "DIRECT";
        }
        var pos = suffix.indexOf('.');
        if (pos === -1) break;
        suffix = suffix.substring(pos + 1);
    }

    return PROXY_METHOD;
}
