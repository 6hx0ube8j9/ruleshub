var IP_ADDRESS = '127.0.0.1:7891';
var PROXY_METHOD = 'SOCKS5 ' + IP_ADDRESS + '; SOCKS ' + IP_ADDRESS + '; DIRECT';

var DIRECT_DOMAINS = {
    "appledaily.com": 1,
    "appledaily.com.hk": 1,
    "appledaily.com.tw": 1,
    "appledaily.hk": 1,
    "applefruity.com": 1,
    "applehealth.com.hk": 1,
    "atnext.com": 1,
    "bestmallawards.com": 1,
    "deluxe.com.hk": 1,
    "eracom.com.tw": 1,
    "next.hk": 1,
    "nextdigital.com.hk": 1,
    "nextdigital.com.tw": 1,
    "nextfilm.com.hk": 1,
    "nextmag.com.tw": 1,
    "nextmedia.com": 1,
    "nextmedia.com.tw": 1,
    "nextmgz.com": 1,
    "nextplus.com.hk": 1,
    "nexttv.com.tw": 1,
    "nextwork.com.hk": 1,
    "nextwork.com.tw": 1,
    "nextwork.hk": 1,
    "nextwork.tw": 1,
    "nxtdig.com.hk": 1,
    "nxtdig.com.tw": 1,
    "omoplanet.com": 1,
    "privilege.hk": 1,
    "privilege.tw": 1,
    "sharpdaily.tw": 1,
    "tomonews.net": 1,
    "twnextdigital.com": 1
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
