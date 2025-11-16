const CORE_URL = 'https://raw.githubusercontent.com/PLACEHOLDER/main/dist/converter.js';

export default {
    async fetch(request) {
        const url = new URL(request.url);
        const path = url.pathname;

        const coreResp = await fetch(CORE_URL + '?v=' + Date.now());
        if (!coreResp.ok) return new Response('Core load failed', { status: 500 });
        const code = await coreResp.text();
        const core = new Function(code + '; return { linkToClash, clashToLink };')();

        if (path === '/to-clash' && request.method === 'POST') {
            const { links } = await request.json();
            return new Response(core.linkToClash(links), {
                headers: { 'Content-Type': 'text/yaml', 'Access-Control-Allow-Origin': '*' }
            });
        }

        if (path === '/to-link' && request.method === 'POST') {
            const yaml = await request.text();
            return new Response(core.clashToLink(yaml), {
                headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' }
            });
        }

        return new Response('404 Not Found', { status: 404 });
    }
};