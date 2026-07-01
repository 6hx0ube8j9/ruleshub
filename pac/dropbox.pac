function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, '.db.tt') || host === 'db.tt') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropbox-dns.com') || host === 'dropbox-dns.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropbox.com') || host === 'dropbox.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropbox.tech') || host === 'dropbox.tech') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropbox.zendesk.com') || host === 'dropbox.zendesk.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxapi.com') || host === 'dropboxapi.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxbusiness.com') || host === 'dropboxbusiness.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxcaptcha.com') || host === 'dropboxcaptcha.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxforum.com') || host === 'dropboxforum.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxforums.com') || host === 'dropboxforums.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxinsiders.com') || host === 'dropboxinsiders.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxmail.com') || host === 'dropboxmail.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxpartners.com') || host === 'dropboxpartners.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxstatic.com') || host === 'dropboxstatic.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.dropboxusercontent.com') || host === 'dropboxusercontent.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.getdropbox.com') || host === 'getdropbox.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.paper-attachments.s3.amazonaws.com') || host === 'paper-attachments.s3.amazonaws.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    return 'DIRECT';
}
