function FindProxyForURL(url, host) {
    if (host === 'ai.google.dev') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (host === 'alkalimakersuite-pa.clients6.google.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (host === 'makersuite.google.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.apis.google.com') || host === 'apis.google.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.bard.google.com') || host === 'bard.google.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.deepmind.com') || host === 'deepmind.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.deepmind.google') || host === 'deepmind.google') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.gemini.google.com') || host === 'gemini.google.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.generativeai.google') || host === 'generativeai.google') return 'PROXY 127.0.0.1:7890; DIRECT';
    if (dnsDomainIs(host, '.proactivebackend-pa.googleapis.com') || host === 'proactivebackend-pa.googleapis.com') return 'PROXY 127.0.0.1:7890; DIRECT';
    return 'DIRECT';
}
