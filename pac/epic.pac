function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, '.battlebreakers.com') || host === 'battlebreakers.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.eac-cdn.com') || host === 'eac-cdn.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.easy.ac') || host === 'easy.ac') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.easyanticheat.net') || host === 'easyanticheat.net') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.epicgames.com') || host === 'epicgames.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.epicgames.dev') || host === 'epicgames.dev') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.fortnite.com') || host === 'fortnite.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.helpshift.com') || host === 'helpshift.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.paragon.com') || host === 'paragon.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.playparagon.com') || host === 'playparagon.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.roborecall.com') || host === 'roborecall.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.shadowcomplex.com') || host === 'shadowcomplex.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.spyjinx.com') || host === 'spyjinx.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.unrealengine.com') || host === 'unrealengine.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.unrealtournament.com') || host === 'unrealtournament.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    return 'DIRECT';
}
