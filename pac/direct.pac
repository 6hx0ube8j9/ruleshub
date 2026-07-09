var IP_ADDRESS = '127.0.0.1:7891';
var PROXY_METHOD = 'SOCKS5 ' + IP_ADDRESS + '; DIRECT';

var DIRECT_DOMAINS = {
};

function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
        return "DIRECT";
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
