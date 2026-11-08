<script lang="ts">
	const site = 'https://sinhaparth5.github.io/wgmon/';
	const seo = {
		title: 'wgmon — see what crosses your WireGuard tunnel, live',
		description:
			'wgmon is a free, open-source terminal monitor for WireGuard. Watch decrypted packets, DNS lookups, TLS SNI and blocked traffic per peer, live, on your Linux server.',
		url: site,
		image: site + 'og.png',
		ld: {
			'@context': 'https://schema.org',
			'@type': 'SoftwareApplication',
			name: 'wgmon',
			description: 'Terminal monitor that shows the decrypted packets crossing a WireGuard interface, live.',
			applicationCategory: 'DeveloperApplication',
			operatingSystem: 'Linux',
			softwareVersion: '2026.11.0',
			license: 'https://opensource.org/licenses/MIT',
			url: site,
			downloadUrl: 'https://github.com/sinhaparth5/wgmon/releases',
			codeRepository: 'https://github.com/sinhaparth5/wgmon',
			image: site + 'og.png',
			author: { '@type': 'Person', name: 'Parth Sinha' },
			offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' }
		}
	};

	import { onMount } from 'svelte';
	import { fly, fade, draw, crossfade } from 'svelte/transition';
	import { flip } from 'svelte/animate';
	import { Tween } from 'svelte/motion';
	import { cubicOut } from 'svelte/easing';

	const repo = 'https://github.com/sinhaparth5/wgmon';
	const install = 'curl -fsSL https://raw.githubusercontent.com/sinhaparth5/wgmon/master/install.sh | sh';

	const keys = [
		['j k', 'Move up and down the packet list'],
		['n', 'Jump to the newest packet at the bottom'],
		['space', 'Pause the stream, or go live again'],
		['/', 'Filter by any text: a domain, an IP, a port'],
		['tab', 'Cycle through peers; esc clears filters'],
		['f', 'Flows: one row per connection, bytes each way, rtt, state'],
		['b', 'Blocked: domains your resolver answered with 0.0.0.0'],
		['enter', 'In flows or blocked, show that row’s packets'],
		['?', 'Explain the selected packet in plain English'],
		['x', 'Toggle the hex dump under the breakdown'],
		['w', 'Save the packets on screen to a .pcap']
	];

	const spec = [
		['Binary', 'static · musl'],
		['Arch', 'amd64 · arm64'],
		['Runtime deps', 'none'],
		['Packet ring', '10,000 × 4 KB'],
		['Redraw cap', '30 fps'],
		['Capture', 'AF_PACKET'],
		['Needs', 'cap_net_raw, cap_net_admin']
	];

	const protos = ['IPv4', 'IPv6', 'TCP', 'UDP', 'ICMP', 'DNS', 'TLS SNI', 'HTTP Host', 'WireGuard'];

	const installSteps = [
		'Finds the latest tagged release on GitHub',
		'Verifies the download against SHA256SUMS',
		'Swaps the binary atomically, safe while wgmon runs',
		'Grants cap_net_raw and cap_net_admin, so no sudo'
	];

	// Sample traffic for the live demo; shapes match what wgmon prints.
	type Sample = { peer: string; proto: string; info: string; layers: string[]; say: string };
	const samples: Sample[] = [
		{
			peer: 'phone', proto: 'DNS', info: 'A github.com → 140.82.112.4',
			layers: ['IPv4  10.8.0.2 → 1.1.1.3 · 71 B', 'UDP   53124 → 53', 'DNS   A github.com = 140.82.112.4 · 18 ms'],
			say: 'Your phone asked its resolver for github.com and got 140.82.112.4 back in 18 ms. From now on wgmon shows that IP as github.com.'
		},
		{
			peer: 'laptop', proto: 'TLS', info: 'SNI api.github.com',
			layers: ['IPv4  10.8.0.3 → 140.82.113.6 · 583 B', 'TCP   51122 → 443 · PSH ACK', 'TLS   ClientHello · SNI api.github.com · h2'],
			say: 'Your laptop is opening an HTTPS connection to api.github.com. The name is sent before encryption starts, so wgmon can read it. The page itself stays encrypted.'
		},
		{
			peer: 'phone', proto: 'BLK', info: 'ads.doubleclick.net → 0.0.0.0',
			layers: ['IPv4  1.1.1.3 → 10.8.0.2 · 87 B', 'UDP   53 → 41877', 'DNS   A ads.doubleclick.net = 0.0.0.0'],
			say: 'The filtering resolver refused this ad domain by answering 0.0.0.0, so the phone never connects to it. It is counted in the blocked view (b).'
		},
		{
			peer: 'laptop', proto: 'TCP', info: '→ 104.16.85.20:443 SYN',
			layers: ['IPv4  10.8.0.3 → 104.16.85.20 · 60 B', 'TCP   51130 → 443 · SYN · win 64240'],
			say: 'Your laptop is starting a new connection to port 443. The flows view times the handshake from this SYN to the server’s SYN-ACK.'
		},
		{
			peer: 'phone', proto: 'TLS', info: 'SNI fonts.gstatic.com',
			layers: ['IPv4  10.8.0.2 → 142.250.187.3 · 517 B', 'TCP   49210 → 443 · PSH ACK', 'TLS   ClientHello · SNI fonts.gstatic.com'],
			say: 'A web page on your phone is loading fonts from Google. Same as any HTTPS request: the hostname is visible, the content is not.'
		},
		{
			peer: 'laptop', proto: 'DNS', info: 'AAAA cdn.jsdelivr.net',
			layers: ['IPv4  10.8.0.3 → 1.1.1.1 · 79 B', 'UDP   50211 → 53', 'DNS   AAAA cdn.jsdelivr.net (query)'],
			say: 'Your laptop is asking for the IPv6 address of cdn.jsdelivr.net. The answer will follow a few milliseconds later as its own packet.'
		},
		{
			peer: 'phone', proto: 'UDP', info: '→ 142.250.180.14:443 QUIC',
			layers: ['IPv4  10.8.0.2 → 142.250.180.14 · 1252 B', 'UDP   61022 → 443 · QUIC Initial'],
			say: 'An HTTP/3 (QUIC) packet. Its server name is inside encrypted fields, so wgmon shows the name it learned from the earlier DNS answer instead.'
		},
		{
			peer: 'laptop', proto: 'BLK', info: 'telemetry.example.net → 0.0.0.0',
			layers: ['IPv4  1.1.1.3 → 10.8.0.3 · 93 B', 'UDP   53 → 38015', 'DNS   A telemetry.example.net = 0.0.0.0'],
			say: 'A telemetry domain your resolver blocks. The app that asked for it gets nowhere, and the domain shows up in the blocked list.'
		}
	];

	const stages = [
		['Peers', 'phone, laptop', 'Encrypt everything with their WireGuard keys.'],
		['eth0', 'udp/51820', 'Outer packets: handshakes, keepalives, ciphertext.'],
		['Kernel', 'WireGuard', 'Checks and decrypts each packet.'],
		['wg0', 'plain IP', 'Real addresses and ports, after decryption.'],
		['Socket', 'AF_PACKET · SOCK_DGRAM', 'A raw socket on wg0 with a 4 MB buffer. No libpcap.'],
		['Parse', 'summarize()', 'Bounds-checked decoders for IP, TCP/UDP, DNS, TLS, HTTP.'],
		['Remember', 'ring 10k · names', 'Last 10,000 packets plus names learned from DNS, SNI and Host.'],
		['Draw', 'ncurses ≤ 30 fps', 'One thread polls the socket and the keyboard.']
	];

	const decisions = [
		['Capture on wg0, not eth0', 'You see decrypted packets with real IPs and ports.', 'The outer handshake is hidden, so -i eth0 exists for that.'],
		['Raw socket, no libpcap', 'Zero dependencies. You see exactly what the kernel hands over.', 'No in-kernel filter; fine below ~50k packets/s.'],
		['One thread, poll()', 'No locks and no races. Easy to debug.', 'A slow redraw delays reads; the 4 MB kernel buffer absorbs it.'],
		['Ring of 10k packets', 'Memory stays bounded. Scroll back and inspect.', 'History is lost on exit, so press w to keep a .pcap.'],
		['Names from DNS, SNI, Host', 'youtube.com:443 instead of 142.250.x.x.', 'Blind to DoH and ECH; run a resolver on the VPS to fix it.']
	];

	const views = [
		{
			id: 'packets', key: 'default', title: 'Packets',
			note: 'Every packet, newest at the bottom. Names replace IPs once wgmon has seen a DNS answer or SNI for them.',
			body: `TIME      PEER    PROTO  REMOTE                LEN  INFO
14:02:11  phone   DNS    1.1.1.3:53             71  A github.com
14:02:11  laptop  TLS    api.github.com:443    583  ClientHello h2
14:02:12  phone   DNS    1.1.1.3:53             87  ads.doubleclick.net 0.0.0.0  blocked
14:02:12  laptop  TCP    cdn.jsdelivr.net:443   60  SYN
14:02:13  phone   UDP    youtube.com:443      1252  QUIC`
		},
		{
			id: 'flows', key: 'f', title: 'Flows',
			note: 'One row per connection: bytes each way, how long it has been open, handshake round-trip and state.',
			body: `PEER    REMOTE                  OUT      IN     DUR    RTT    STATE
laptop  api.github.com:443   14.2 KB  231 KB  12.4s  21 ms  open
phone   fonts.gstatic.com:443 3.1 KB   88 KB   2.1s  34 ms  closed
laptop  cdn.jsdelivr.net:443  1.8 KB   46 KB   0.9s  19 ms  open
phone   1.1.1.3:53             420 B  1.1 KB    —      —    udp`
		},
		{
			id: 'blocked', key: 'b', title: 'Blocked',
			note: 'Domains your filtering resolver (1.1.1.3) answered with 0.0.0.0, with who asked and how often.',
			body: `DOMAIN                     PEER    HITS  LAST
ads.doubleclick.net        phone     14  12s ago
telemetry.example.net      laptop     6  1m ago
tracker.example.com        phone      3  4m ago
metrics.example.org        laptop     1  9m ago`
		},
		{
			id: 'explain', key: '?', title: 'Explain',
			note: 'Plain English for the selected packet, next to the layered breakdown.',
			body: `IPv4  10.8.0.3 → 140.82.113.6   583 B
TCP   51122 → 443   PSH ACK
TLS   ClientHello   SNI api.github.com   ALPN h2

Your laptop is opening an HTTPS connection to api.github.com.
The name is sent before encryption starts, so it is visible here.
Everything after this packet is encrypted.`
		},
		{
			id: 'hex', key: 'x', title: 'Hex',
			note: 'The raw bytes under the breakdown, for when you want to check a parser’s work.',
			body: `0000  45 00 00 47 1c 46 40 00  40 11 5a 2e 0a 08 00 02  E..G.F@.@.Z.....
0010  01 01 01 03 cf 44 00 35  00 33 8e 1f 6b 2a 01 00  .....D.5.3..k*..
0020  00 01 00 00 00 00 00 00  06 67 69 74 68 75 62 03  .........github.
0030  63 6f 6d 00 00 01 00 01                           com.....`
		},
		{
			id: 'eth0', key: '-i eth0', title: 'Outside',
			note: 'Watch the encrypted side instead: WireGuard handshakes, cookies, keepalives and data.',
			body: `TIME      PEER    TYPE                    LEN
14:02:11  phone   handshake initiation    148 B
14:02:11  vps     handshake response       92 B
14:02:12  phone   data                   1312 B
14:02:37  laptop  keepalive                32 B`
		}
	];

	const sections = ['overview', 'how', 'decisions', 'views', 'notes'];
	const navLinks = [
		['overview', 'Overview'],
		['how', 'How it works'],
		['decisions', 'Decisions'],
		['views', 'Views'],
		['notes', 'Limits']
	];

	type Row = { id: number; t: string; s: number };
	let rows: Row[] = $state([]);
	let count = $state(0);
	let perPeer = $state({ phone: 0, laptop: 0 } as Record<string, number>);
	let handshake = $state([12, 71]);
	let live = $state(true);
	let ready = $state(false);
	let copied = $state(false);
	let reduced = $state(false);
	let selId: number | null = $state(null);
	let tab = $state('packets');
	let active = $state('overview');
	let step = $state(0);
	let seen: Record<string, boolean> = $state({});

	const d = (ms: number) => (reduced ? 0 : ms);
	const show = (id: string) => !ready || seen[id];
	const cur = $derived(rows.find((r) => r.id === selId) ?? rows.at(-1));
	const view = $derived(views.find((v) => v.id === tab)!);

	const [send, receive] = crossfade({ duration: (n) => d(Math.sqrt(n * 200)), easing: cubicOut });

	const stats = [
		{ label: 'Packet ring', unit: 'pkts', to: 10000, t: new Tween(10000, { duration: 1400, easing: cubicOut }) },
		{ label: 'Memory', unit: 'MB', to: 40, t: new Tween(40, { duration: 1400, easing: cubicOut }) },
		{ label: 'Redraw cap', unit: 'fps', to: 30, t: new Tween(30, { duration: 1400, easing: cubicOut }) }
	];

	function push() {
		const s = count % samples.length;
		const t = new Date().toTimeString().slice(0, 8);
		perPeer[samples[s].peer]++;
		rows = [...rows, { id: count++, t, s }].slice(-6);
	}

	function pick(id: number) {
		selId = id;
		live = false;
	}

	function toggle() {
		live = !live;
		if (live) selId = null;
	}

	function spy() {
		let c = sections[0];
		for (const id of sections) {
			const el = document.getElementById(id);
			if (el && el.getBoundingClientRect().top < innerHeight * 0.4) c = id;
		}
		active = c;
	}

	// Marks a section as seen once it scrolls into view, which starts its intro transitions.
	function reveal(node: HTMLElement) {
		const o = new IntersectionObserver(
			([e]) => {
				if (e.isIntersecting) {
					seen[node.id] = true;
					o.disconnect();
				}
			},
			{ rootMargin: '0px 0px -12% 0px' }
		);
		o.observe(node);
		return { destroy: () => o.disconnect() };
	}

	onMount(() => {
		reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
		ready = true;
		for (let i = 0; i < 4; i++) push();
		for (const s of stats) {
			s.t.set(0, { duration: 0 });
			s.t.set(s.to, { duration: d(1400) });
		}
		spy();
		const feed = setInterval(() => live && push(), 1400);
		const clock = setInterval(() => {
			handshake = handshake.map((h) => (h >= 120 ? 0 : h + 1)); // WireGuard rehandshakes every 2 min
			if (!reduced) step = (step + 1) % stages.length;
		}, 1000);
		return () => {
			clearInterval(feed);
			clearInterval(clock);
		};
	});

	async function copy() {
		await navigator.clipboard.writeText(install);
		copied = true;
		setTimeout(() => (copied = false), 1600);
	}
</script>

<svelte:window onscroll={spy} />

<svelte:head>
	<title>{seo.title}</title>
	<meta name="description" content={seo.description} />
	<meta name="author" content="Parth Sinha" />
	<link rel="canonical" href={seo.url} />
	<meta property="og:type" content="website" />
	<meta property="og:site_name" content="wgmon" />
	<meta property="og:url" content={seo.url} />
	<meta property="og:title" content={seo.title} />
	<meta property="og:description" content={seo.description} />
	<meta property="og:image" content={seo.image} />
	<meta property="og:image:width" content="1200" />
	<meta property="og:image:height" content="630" />
	<meta property="og:image:alt" content="wgmon: a live terminal list of decrypted packets crossing a WireGuard tunnel" />
	<meta name="twitter:card" content="summary_large_image" />
	<meta name="twitter:title" content={seo.title} />
	<meta name="twitter:description" content={seo.description} />
	<meta name="twitter:image" content={seo.image} />
	{@html `<script type="application/ld+json">${JSON.stringify(seo.ld)}</script>`}
</svelte:head>

<a class="skip" href="#overview">Skip to content</a>

<div class="frame">
	<header class="top">
		<a class="brand" href="./">wgmon<span class="ver">2026.11</span></a>
		<nav aria-label="Sections">
			{#each navLinks as [id, label] (id)}
				<a href="#{id}" aria-current={active === id ? 'location' : undefined}>
					{label}
					{#if active === id}
						<span class="bar" in:receive={{ key: 'bar' }} out:send={{ key: 'bar' }}></span>
					{/if}
				</a>
			{/each}
			<a class="ext" href={repo}>Source ↗</a>
			<a class="cta" href="#install">Install</a>
		</nav>
	</header>

	<!-- LEFT -->
	<aside class="left">
		<h2 class="label-lg">Tunnel<br />overview</h2>

		<section>
			<h3 class="label">What it sees</h3>
			<p class="muted">
				Peers, DNS lookups, TLS hostnames, blocked domains, connections, and a layered breakdown or
				hex dump of any packet that crosses <code>wg0</code>.
			</p>
		</section>

		<section>
			<h3 class="label">Peers <span class="pulse" class:off={!live}></span></h3>
			<ul class="peers">
				{#each [['phone', '10.8.0.2', '1.1.1.3', 18], ['laptop', '10.8.0.3', '1.1.1.1', 12]] as [name, ip, dns, ms], i (name)}
					<li>
						<b>.{i + 2}</b>
						<div>
							<div class="peer-top"><span>{name}</span><span class="pk">{perPeer[name]} pkts</span></div>
							<em>{ip} · handshake {handshake[i]}s ago</em>
							<em>DNS {dns} · {ms} ms</em>
							<span class="meter"><i style="width: {(Number(ms) / 40) * 100}%"></i></span>
						</div>
					</li>
				{/each}
			</ul>
			<p class="muted small">
				Read from the kernel over netlink, so peers are named without config. <code>--peer</code> overrides.
			</p>
		</section>

		<section>
			<h3 class="label">Spec sheet</h3>
			<dl class="spec">
				{#each spec as [k, v] (k)}
					<dt>{k}</dt>
					<dd>{v}</dd>
				{/each}
			</dl>
		</section>

		<section>
			<h3 class="label">Decodes</h3>
			<ul class="chips">
				{#each protos as p (p)}<li>{p}</li>{/each}
			</ul>
		</section>

		<p class="foot italic">Linux · amd64 &amp; arm64</p>
	</aside>

	<!-- CENTER -->
	<main id="overview" class="center">
		<p class="byline italic">A terminal monitor for WireGuard<br />Written in C++ · one static binary</p>

		<div class="tags">
			<span><i style="background: var(--teal)"></i>WIREGUARD</span>
			<span><i style="background: var(--navy)"></i>TERMINAL</span>
		</div>

		{#if ready}
			<h1 in:fly={{ y: 24, duration: d(700), easing: cubicOut }}>What is actually crossing your tunnel?</h1>
		{:else}
			<h1>What is actually crossing your tunnel?</h1>
		{/if}

		<p class="lead">
			<span class="cap">W</span>gmon reads the decrypted packets on your WireGuard interface and shows
			them live, in the terminal. Which peer looked up which domain, which hostname it opened a TLS
			connection to, what your filtering resolver blocked, and how each connection is doing. Press
			<kbd>?</kbd> on any packet and it tells you, in plain English, what it is.
		</p>

		<div class="metrics">
			<div>
				<h3 class="label">Release</h3>
				<p class="big">2026.11</p>
			</div>
			{#each stats as s (s.label)}
				<div>
					<h3 class="label">{s.label}</h3>
					<p class="big">{Math.round(s.t.current).toLocaleString('en')}<small>{s.unit}</small></p>
				</div>
			{/each}
		</div>

		<section id="live" class="live" aria-label="Live demo">
			<div class="term">
				<div class="term-head">
					<span>wgmon · wg0</span>
					<span class:paused={!live}>{live ? '● live' : '❚❚ paused'}</span>
				</div>
				<ol>
					{#each rows as r (r.id)}
						{@const s = samples[r.s]}
						<li
							animate:flip={{ duration: d(350) }}
							in:fly={{ y: 14, duration: d(350) }}
							out:fade={{ duration: d(150) }}
						>
							<button
								class="row"
								class:blk={s.proto === 'BLK'}
								class:sel={selId === r.id}
								aria-pressed={selId === r.id}
								onclick={() => pick(r.id)}
							>
								<span>{r.t}</span><span>{s.peer}</span><b>{s.proto}</b><span>{s.info}</span>
							</button>
						</li>
					{/each}
				</ol>
				<div class="term-foot">
					<span>click a row to inspect · the feed pauses</span>
					<span>{count} seen</span>
				</div>
			</div>

			<div class="rail">
				<div class="n" title="Packets seen">{count}</div>
				<button onclick={toggle} aria-label={live ? 'Pause' : 'Resume'}>{live ? '❚❚' : '▶'}</button>
				<a href={repo} aria-label="Source on GitHub">gh</a>
			</div>
		</section>

		<section class="inspect" aria-live="polite">
			<h3 class="label">Selected packet <kbd>?</kbd></h3>
			{#if cur}
				{@const s = samples[cur.s]}
				{#key cur.id}
					<div class="inspect-grid">
						<ol class="layers">
							{#each s.layers as l, i (l)}
								<li in:fly={{ x: -12, duration: d(300), delay: d(i * 70) }}>{l}</li>
							{/each}
						</ol>
						<p class="say" in:fade={{ duration: d(400), delay: d(150) }}>{s.say}</p>
					</div>
				{/key}
			{/if}
		</section>

		<figure class="diagram" aria-label="Where wgmon listens">
			{#if ready}
				<svg viewBox="0 0 520 136" fill="none" stroke="currentColor" stroke-width="1">
					<rect x="6" y="35" width="90" height="40" in:draw={{ duration: d(900) }} />
					<rect x="215" y="25" width="90" height="60" in:draw={{ duration: d(900), delay: d(200) }} />
					<rect x="424" y="35" width="90" height="40" in:draw={{ duration: d(900), delay: d(400) }} />
					<path id="wire" d="M96 55 H215 M305 55 H424" stroke-dasharray="4 4" in:draw={{ duration: d(800), delay: d(700) }} />
					<path d="M260 85 V104" in:draw={{ duration: d(400), delay: d(1100) }} />
					{#if !reduced}
						<circle r="3.5" fill="var(--teal)" stroke="none" in:fade={{ delay: 1500 }}>
							<animateMotion dur="2.8s" repeatCount="indefinite" path="M96 55 H424" />
						</circle>
					{/if}
					<g class="txt" in:fade={{ delay: d(900), duration: d(400) }}>
						<text x="51" y="59">PEER</text>
						<text x="260" y="59">WG0</text>
						<text x="469" y="59">INTERNET</text>
						<text x="260" y="128" class="tap">wgmon taps here, after decryption</text>
					</g>
				</svg>
			{/if}
		</figure>
	</main>

	<!-- RIGHT -->
	<aside class="right">
		<section id="keys">
			<h3 class="title">Keys</h3>
			<ol class="keys">
				{#each keys as [k, v], i (k)}
					<li>
						<span class="num">{i + 1}.</span>
						<div><kbd>{k}</kbd><p>{v}</p></div>
					</li>
				{/each}
			</ol>
		</section>

		<section id="install">
			<h3 class="title italic">Install now</h3>
			<p class="muted small">On the WireGuard server. Run it again to update.</p>
			<pre><code>{install}</code></pre>
			<button class="send" onclick={copy} aria-live="polite">{copied ? 'COPIED ✓' : 'COPY'}</button>
			<ol class="steps">
				{#each installSteps as st, i (st)}
					<li><span>{String(i + 1).padStart(2, '0')}</span>{st}</li>
				{/each}
			</ol>
			<p class="muted small">
				Then run <code>wgmon</code>. Pin a version with <code>WGMON_VERSION=2026.11.0</code>.
			</p>
		</section>

		<p class="rights">MIT · ALL PACKETS STAY ON YOUR SERVER</p>
	</aside>

	<!-- HOW IT WORKS -->
	<section id="how" class="band" use:reveal>
		<div class="band-label">
			<span class="idx">01</span>
			<h2 class="label-lg">How it<br />works</h2>
			<p class="muted small">
				One process, one thread, no database. The numbers for a home VPN (2 peers, bursts of ~10k
				packets/s) never needed more.
			</p>
		</div>
		<div class="band-body">
			<ol class="pipe">
				{#if show('how')}
					{#each stages as [name, sub, text], i (name)}
						<li
							class:on={!reduced && step === i}
							class:tap={i === 3 || i === 4}
							in:fly={{ y: 18, duration: d(450), delay: d(i * 60), easing: cubicOut }}
						>
							<span class="pipe-n">{String(i + 1).padStart(2, '0')}</span>
							<strong>{name}</strong>
							<code>{sub}</code>
							<p>{text}</p>
						</li>
					{/each}
				{/if}
			</ol>
			<p class="italic caption">
				The highlight walks the path one packet takes. wgmon attaches at 04, after the kernel has
				decrypted it, so it never needs your keys.
			</p>
		</div>
	</section>

	<!-- DECISIONS -->
	<section id="decisions" class="band" use:reveal>
		<div class="band-label">
			<span class="idx">02</span>
			<h2 class="label-lg">Design<br />decisions</h2>
			<p class="muted small">Each choice and the cost it buys. From the design notes in the repo.</p>
		</div>
		<div class="band-body">
			<div class="dec-head" aria-hidden="true"><span>Decision</span><span>Solves</span><span>Costs</span></div>
			<ul class="dec">
				{#if show('decisions')}
					{#each decisions as [a, b, c], i (a)}
						<li in:fly={{ x: -16, duration: d(400), delay: d(i * 80), easing: cubicOut }}>
							<strong>{a}</strong><span>{b}</span><span>{c}</span>
						</li>
					{/each}
				{/if}
			</ul>
		</div>
	</section>

	<!-- VIEWS -->
	<section id="views" class="band" use:reveal>
		<div class="band-label">
			<span class="idx">03</span>
			<h2 class="label-lg">Six<br />views</h2>
			<p class="muted small">One key each. Sample output below.</p>
		</div>
		<div class="band-body">
			<div class="tabs" role="tablist" aria-label="wgmon views">
				{#each views as v (v.id)}
					<button role="tab" aria-selected={tab === v.id} onclick={() => (tab = v.id)}>
						{v.title}<kbd>{v.key}</kbd>
						{#if tab === v.id}
							<span class="bar" in:receive={{ key: 'tab' }} out:send={{ key: 'tab' }}></span>
						{/if}
					</button>
				{/each}
			</div>
			<div class="view" role="tabpanel">
				{#key tab}
					<div in:fly={{ y: 10, duration: d(300), easing: cubicOut }}>
						<p class="view-note">{view.note}</p>
						<pre class="screen">{view.body}</pre>
					</div>
				{/key}
			</div>
		</div>
	</section>

	<!-- NOTES -->
	<section id="notes" class="band" use:reveal>
		<div class="band-label">
			<span class="idx">04</span>
			<h2 class="label-lg">Safety &amp;<br />limits</h2>
		</div>
		<div class="band-body cols">
			{#if show('notes')}
				<article in:fly={{ y: 16, duration: d(400), easing: cubicOut }}>
					<h3 class="title-l">Safe on hostile input</h3>
					<p>
						Every parser is bounds-checked and fuzzed by truncation under ASan and UBSan in
						<code>make test</code>. A malformed packet is shown as malformed, never trusted.
					</p>
				</article>
				<article in:fly={{ y: 16, duration: d(400), delay: d(100), easing: cubicOut }}>
					<h3 class="title-l">Stays on your server</h3>
					<p>
						Nothing is sent anywhere and nothing is written to disk unless you press <kbd>w</kbd>. If
						the kernel ever drops packets, a counter says so in the header.
					</p>
				</article>
				<article in:fly={{ y: 16, duration: d(400), delay: d(200), easing: cubicOut }}>
					<h3 class="title-l">Honest limits</h3>
					<ul class="limits">
						<li>DoH and ECH hide names. Run a resolver on the VPS and they come back.</li>
						<li>QUIC server names are not decoded.</li>
						<li>No history across runs. Save a <code>.pcap</code> instead.</li>
						<li>Not an IDS and not a logger: it is for looking.</li>
					</ul>
				</article>
			{/if}
		</div>
	</section>

	<footer class="band end">
		<div class="band-label"><a class="brand-s" href="./">wgmon</a></div>
		<div class="band-body end-body">
			<span>MIT License · © 2026 Parth Sinha</span>
			<span class="links">
				<a href={repo}>GitHub</a>
				<a href="{repo}/releases">Releases</a>
				<a href="{repo}/blob/master/docs/design/wgmon.md">Design notes</a>
				<a href="{repo}/blob/master/LICENSE">License</a>
			</span>
		</div>
	</footer>
</div>

<style>
	:global(:root) {
		--bg: #f2f1ef;
		--ink: #111;
		--muted: #6b6b6b;
		--hair: #d1d1d6;
		--teal: #72b8b6;
		--teal-soft: #d7e9e8;
		--navy: #1f4363;
		--serif: 'EB Garamond', Garamond, Georgia, serif;
		--sans: Inter, 'Helvetica Neue', sans-serif;
		--mono: 'JetBrains Mono', ui-monospace, monospace;
		--ease: cubic-bezier(0.215, 0.61, 0.355, 1);
	}
	:global(*) {
		box-sizing: border-box;
	}
	:global(html) {
		scroll-behavior: smooth;
		scroll-padding-top: 1rem;
	}
	:global(body) {
		margin: 0;
		background: var(--bg);
		color: var(--ink);
		font-family: var(--sans);
		-webkit-font-smoothing: antialiased;
	}
	:global(::selection) {
		background: var(--teal);
	}
	@media (prefers-reduced-motion: reduce) {
		:global(html) {
			scroll-behavior: auto;
		}
	}

	.skip {
		position: absolute;
		left: -999px;
		top: 0.5rem;
		background: var(--ink);
		color: var(--bg);
		padding: 0.5rem 1rem;
		z-index: 10;
	}
	.skip:focus {
		left: 0.5rem;
	}

	.frame {
		margin: clamp(0px, 3vw, 40px);
		border: 2px solid var(--ink);
		display: grid;
		grid-template-columns: minmax(0, 1fr) minmax(0, 2.6fr) minmax(0, 1.2fr);
	}
	a {
		color: inherit;
	}
	code,
	kbd {
		font-family: var(--mono);
		font-size: 0.85em;
	}
	.italic {
		font-family: var(--serif);
		font-style: italic;
	}
	.muted {
		color: var(--muted);
		font-weight: 300;
		line-height: 1.75;
		font-size: 0.875rem;
		margin: 0;
	}
	.small {
		font-size: 0.8rem;
		line-height: 1.6;
	}
	.label {
		font-family: var(--mono);
		font-size: 0.68rem;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--muted);
		font-weight: 400;
		margin: 0 0 0.8rem;
		padding-bottom: 0.5rem;
		border-bottom: 1px solid var(--hair);
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.label-lg {
		font-family: var(--mono);
		font-size: 0.95rem;
		font-weight: 600;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		margin: 0;
		line-height: 1.4;
	}

	/* top bar */
	.top {
		grid-column: 1 / -1;
		display: grid;
		grid-template-columns: subgrid;
		border-bottom: 1px solid var(--ink);
		position: sticky;
		top: 0;
		z-index: 5;
		background: var(--bg);
	}
	.brand {
		font-family: var(--serif);
		font-weight: 700;
		font-size: 1.5rem;
		text-decoration: none;
		padding: 1.2rem 2rem;
		border-right: 1px solid var(--ink);
		display: flex;
		align-items: baseline;
		gap: 0.6rem;
	}
	.ver {
		font: 400 0.65rem var(--mono);
		letter-spacing: 0.1em;
		color: var(--muted);
	}
	nav {
		grid-column: 2 / -1;
		display: flex;
		gap: 2rem;
		padding: 0 0 0 3rem;
		align-items: stretch;
		font-size: 0.875rem;
	}
	nav a {
		position: relative;
		display: flex;
		align-items: center;
		text-decoration: none;
		color: var(--muted);
		white-space: nowrap;
		transition: color 0.2s;
	}
	nav a:hover,
	nav a[aria-current] {
		color: var(--ink);
	}
	.bar {
		position: absolute;
		left: 0;
		right: 0;
		bottom: -1px;
		height: 2px;
		background: var(--ink);
	}
	nav .ext {
		margin-left: auto;
	}
	nav .cta {
		color: var(--bg);
		background: var(--ink);
		padding: 0 2rem;
		font-family: var(--mono);
		font-size: 0.75rem;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		transition: background 0.2s var(--ease), color 0.2s;
	}
	nav .cta:hover {
		background: var(--teal);
		color: var(--ink);
	}

	/* left */
	.left {
		border-right: 1px solid var(--ink);
		padding: 3rem 2rem 2rem;
		display: flex;
		flex-direction: column;
		gap: 2.5rem;
		min-width: 0;
	}
	.left section {
		margin: 0;
	}
	.pulse {
		width: 7px;
		height: 7px;
		border-radius: 50%;
		background: var(--teal);
		animation: pulse 1.6s ease-in-out infinite;
	}
	.pulse.off {
		background: var(--hair);
		animation: none;
	}
	@keyframes pulse {
		50% {
			opacity: 0.3;
		}
	}
	.peers {
		list-style: none;
		padding: 0;
		margin: 0 0 1rem;
		display: grid;
		gap: 1.2rem;
	}
	.peers li {
		display: flex;
		gap: 1rem;
		font-size: 0.9rem;
	}
	.peers li > div {
		flex: 1;
	}
	.peers b {
		font-family: var(--mono);
		font-size: 0.75rem;
		padding-top: 0.15rem;
	}
	.peer-top {
		display: flex;
		justify-content: space-between;
		font-weight: 500;
	}
	.pk {
		font: 400 0.7rem var(--mono);
		color: var(--muted);
		font-variant-numeric: tabular-nums;
	}
	.peers em {
		display: block;
		font-style: normal;
		color: var(--muted);
		font-size: 0.72rem;
		font-family: var(--mono);
		margin-top: 0.25rem;
		font-variant-numeric: tabular-nums;
	}
	.meter {
		display: block;
		height: 3px;
		background: var(--hair);
		margin-top: 0.5rem;
	}
	.meter i {
		display: block;
		height: 100%;
		background: var(--teal);
	}
	.spec {
		display: grid;
		grid-template-columns: auto 1fr;
		margin: 0;
		font-size: 0.78rem;
	}
	.spec dt,
	.spec dd {
		margin: 0;
		padding: 0.45rem 0;
		border-bottom: 1px dotted var(--hair);
	}
	.spec dt {
		color: var(--muted);
		padding-right: 1rem;
	}
	.spec dd {
		font-family: var(--mono);
		font-size: 0.72rem;
		text-align: right;
	}
	.chips {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
	}
	.chips li {
		font: 0.7rem var(--mono);
		border: 1px solid var(--ink);
		padding: 0.2rem 0.5rem;
		transition: background 0.2s;
	}
	.chips li:hover {
		background: var(--teal);
	}
	.foot {
		margin-top: auto;
		padding-top: 1rem;
		border-top: 1px solid var(--ink);
		font-size: 0.85rem;
	}

	/* center */
	.center {
		padding: 3rem clamp(1.5rem, 4vw, 4rem);
		min-width: 0;
	}
	.byline {
		margin: 0 0 2.5rem;
		font-size: 1rem;
		line-height: 1.5;
	}
	.tags {
		display: inline-flex;
		gap: 1.5rem;
		padding: 0.7rem 0;
		border-block: 1px solid var(--ink);
		font-family: var(--serif);
		font-size: 1rem;
	}
	.tags span {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
	}
	.tags i {
		width: 1rem;
		height: 1rem;
		border-right: 5px solid var(--ink);
	}
	h1 {
		font-family: var(--serif);
		font-weight: 700;
		font-size: clamp(2.4rem, 5vw, 4.2rem);
		line-height: 1.05;
		letter-spacing: -0.01em;
		margin: 2.5rem 0 2rem;
		max-width: 14ch;
		text-wrap: balance;
	}
	.lead {
		font-family: var(--serif);
		font-size: 1.15rem;
		line-height: 1.7;
		max-width: 60ch;
		margin: 0;
	}
	.cap {
		float: left;
		font-size: 4.2rem;
		line-height: 0.8;
		font-weight: 700;
		padding: 0.35rem 0.5rem 0 0;
	}
	.lead kbd {
		border: 1px solid var(--ink);
		padding: 0 0.3em;
	}
	.metrics {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		gap: 2rem;
		margin: 3rem 0;
	}
	.big {
		font-family: var(--mono);
		font-weight: 300;
		font-size: clamp(1.5rem, 2.6vw, 2.2rem);
		margin: 0.4rem 0 0;
		font-variant-numeric: tabular-nums;
		white-space: nowrap;
	}
	.big small {
		font-size: 0.7rem;
		color: var(--muted);
		margin-left: 0.3rem;
		letter-spacing: 0.1em;
	}

	/* live terminal */
	.live {
		display: flex;
		gap: 1.5rem;
		align-items: flex-start;
	}
	.term {
		flex: 1;
		min-width: 0;
		border: 1px solid var(--ink);
		font-family: var(--mono);
		font-size: 0.78rem;
		box-shadow: 6px 6px 0 var(--ink);
	}
	.term-head,
	.term-foot {
		display: flex;
		justify-content: space-between;
		padding: 0.5rem 0.8rem;
	}
	.term-head {
		background: var(--ink);
		color: var(--bg);
	}
	.term-head span:last-child {
		color: var(--teal);
	}
	.term-head .paused {
		color: var(--hair) !important;
	}
	.term-foot {
		gap: 1rem;
		border-top: 1px solid var(--hair);
		color: var(--muted);
		font-size: 0.68rem;
	}
	.term ol {
		list-style: none;
		margin: 0;
		padding: 0.4rem 0;
		height: calc(6 * 1.9rem + 0.8rem);
		overflow: hidden;
	}
	.row {
		all: unset;
		box-sizing: border-box;
		width: 100%;
		display: grid;
		grid-template-columns: 5.5rem 4rem 2.6rem 1fr;
		gap: 0.6rem;
		padding: 0 0.8rem;
		line-height: 1.9rem;
		white-space: nowrap;
		cursor: pointer;
		transition: background 0.15s;
	}
	.row:hover {
		background: var(--teal-soft);
	}
	.row.sel {
		background: var(--teal);
	}
	.row:focus-visible {
		outline: 2px solid var(--navy);
		outline-offset: -2px;
	}
	.row span:last-child {
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.row > span:first-child {
		color: var(--muted);
	}
	.row.sel > span:first-child {
		color: var(--ink);
	}
	.row.blk b {
		color: #fff;
		background: var(--navy);
		text-align: center;
	}
	.row.blk span:last-child {
		text-decoration: line-through;
	}
	.rail {
		display: grid;
		border: 1px solid var(--ink);
		width: 3.5rem;
		text-align: center;
	}
	.rail > * {
		min-height: 44px;
		display: grid;
		place-items: center;
		border: 0;
		border-bottom: 1px solid var(--ink);
		background: none;
		font: 600 0.8rem var(--mono);
		color: inherit;
		text-decoration: none;
		cursor: pointer;
		transition: background 0.2s;
	}
	.rail > :last-child {
		border-bottom: 0;
	}
	.rail .n {
		cursor: default;
		font-variant-numeric: tabular-nums;
	}
	.rail button:hover,
	.rail a:hover {
		background: var(--teal);
	}

	/* inspector */
	.inspect {
		margin-top: 2.5rem;
		min-height: 9.5rem;
	}
	.inspect kbd {
		border: 1px solid var(--muted);
		padding: 0 0.3em;
		letter-spacing: 0;
	}
	.inspect-grid {
		display: grid;
		grid-template-columns: 1.1fr 1fr;
		gap: 2rem;
	}
	.layers {
		list-style: none;
		margin: 0;
		padding: 0;
		font: 0.75rem/1.5 var(--mono);
		white-space: pre-wrap;
	}
	.layers li {
		padding: 0.4rem 0 0.4rem 0.8rem;
		border-left: 2px solid var(--ink);
	}
	.layers li + li {
		margin-left: 0.9rem;
	}
	.layers li + li + li {
		margin-left: 1.8rem;
	}
	.say {
		margin: 0;
		font-family: var(--serif);
		font-size: 1.05rem;
		line-height: 1.55;
	}

	/* diagram */
	.diagram {
		margin: 3rem 0 0;
		max-width: 520px;
	}
	.diagram svg {
		width: 100%;
		display: block;
	}
	.txt text {
		fill: currentColor;
		stroke: none;
		text-anchor: middle;
		font: 400 13px var(--mono);
		letter-spacing: 0.1em;
	}
	.txt .tap {
		font: italic 18px var(--serif);
		letter-spacing: 0;
	}

	/* right */
	.right {
		border-left: 1px solid var(--ink);
		padding: 3rem 2rem 2rem;
		display: flex;
		flex-direction: column;
		gap: 3rem;
		min-width: 0;
	}
	.title {
		font-family: var(--serif);
		font-size: 1.3rem;
		font-weight: 600;
		text-align: center;
		margin: 0 0 1.8rem;
	}
	.title::after {
		content: '';
		display: block;
		width: 2.2rem;
		margin: 0.6rem auto 0;
		border-bottom: 1px solid var(--ink);
	}
	.title.italic {
		font-weight: 400;
	}
	.keys {
		list-style: none;
		padding: 0;
		margin: 0;
		display: grid;
		gap: 0.9rem;
	}
	.keys li {
		display: flex;
		gap: 1rem;
	}
	.num {
		font-family: var(--serif);
		font-weight: 600;
		font-size: 1.15rem;
		line-height: 1;
		min-width: 1.6rem;
		font-variant-numeric: tabular-nums;
	}
	.keys kbd {
		font-weight: 600;
		background: var(--ink);
		color: var(--bg);
		padding: 0.05rem 0.4rem;
	}
	.keys p {
		margin: 0.3rem 0 0;
		font-family: var(--serif);
		font-size: 0.98rem;
		line-height: 1.35;
	}
	pre {
		margin: 1rem 0;
		padding: 0.8rem 0;
		border-block: 1px solid var(--ink);
		white-space: pre-wrap;
		word-break: break-all;
		font-size: 0.85rem;
		line-height: 1.6;
	}
	.send {
		display: block;
		margin: 0 auto 1.5rem;
		min-height: 44px;
		min-width: 6rem;
		background: none;
		border: 0;
		border-bottom: 2px solid var(--ink);
		font: 600 0.95rem var(--serif);
		letter-spacing: 0.08em;
		padding: 0.2rem 0.3rem;
		cursor: pointer;
		color: inherit;
		transition: color 0.2s, transform 0.1s;
	}
	.send:hover {
		color: var(--navy);
	}
	.send:active {
		transform: scale(0.96);
	}
	.steps {
		list-style: none;
		padding: 0;
		margin: 0 0 1.2rem;
		font-size: 0.82rem;
		line-height: 1.45;
	}
	.steps li {
		display: flex;
		gap: 0.8rem;
		padding: 0.55rem 0;
		border-bottom: 1px dotted var(--hair);
	}
	.steps span {
		font: 0.7rem var(--mono);
		color: var(--muted);
		padding-top: 0.1rem;
	}
	.rights {
		margin-top: auto;
		padding-top: 1rem;
		border-top: 1px solid var(--ink);
		text-align: center;
		font-family: var(--serif);
		font-size: 0.72rem;
		letter-spacing: 0.06em;
	}

	/* full-width bands */
	.band {
		grid-column: 1 / -1;
		display: grid;
		grid-template-columns: subgrid;
		border-top: 1px solid var(--ink);
	}
	.band-label {
		padding: 3rem 2rem;
		border-right: 1px solid var(--ink);
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.idx {
		font: 300 2.4rem var(--mono);
		line-height: 1;
	}
	.band-body {
		grid-column: 2 / -1;
		padding: 3rem clamp(1.5rem, 4vw, 4rem);
		min-width: 0;
	}
	.caption {
		margin: 1.5rem 0 0;
		color: var(--muted);
		font-size: 1rem;
	}

	.pipe {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		border-top: 1px solid var(--ink);
		border-left: 1px solid var(--ink);
		min-height: 22rem;
	}
	.pipe li {
		position: relative;
		padding: 1.2rem 1.2rem 1.4rem;
		border-right: 1px solid var(--ink);
		border-bottom: 1px solid var(--ink);
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		transition: background 0.4s var(--ease);
	}
	.pipe li.tap::before {
		content: 'wgmon';
		position: absolute;
		top: 0.9rem;
		right: 1rem;
		font: 0.6rem var(--mono);
		letter-spacing: 0.12em;
		background: var(--navy);
		color: #fff;
		padding: 0.1rem 0.4rem;
	}
	.pipe li.on {
		background: var(--teal-soft);
	}
	.pipe li.on .pipe-n {
		color: var(--ink);
	}
	.pipe-n {
		font: 0.7rem var(--mono);
		color: var(--muted);
		transition: color 0.4s;
	}
	.pipe strong {
		font: 600 1.35rem var(--serif);
	}
	.pipe code {
		font-size: 0.7rem;
		color: var(--navy);
	}
	.pipe p {
		margin: 0.4rem 0 0;
		font-size: 0.82rem;
		line-height: 1.5;
		color: var(--muted);
	}

	.dec-head,
	.dec li {
		display: grid;
		grid-template-columns: 1fr 1.2fr 1.2fr;
		gap: 2rem;
	}
	.dec-head {
		font: 0.68rem var(--mono);
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--muted);
		padding-bottom: 0.7rem;
		border-bottom: 1px solid var(--ink);
	}
	.dec {
		list-style: none;
		margin: 0;
		padding: 0;
		min-height: 20rem;
	}
	.dec li {
		padding: 1.1rem 0;
		border-bottom: 1px solid var(--hair);
		font-size: 0.875rem;
		line-height: 1.55;
	}
	.dec strong {
		font: 600 1.1rem/1.3 var(--serif);
	}
	.dec span:last-child {
		color: var(--muted);
	}

	.tabs {
		display: flex;
		gap: 2rem;
		border-bottom: 1px solid var(--ink);
		overflow-x: auto;
		scrollbar-width: none;
	}
	.tabs button {
		all: unset;
		position: relative;
		display: flex;
		align-items: center;
		gap: 0.5rem;
		min-height: 44px;
		cursor: pointer;
		font-size: 0.9rem;
		color: var(--muted);
		white-space: nowrap;
		transition: color 0.2s;
	}
	.tabs button:hover,
	.tabs button[aria-selected='true'] {
		color: var(--ink);
	}
	.tabs button:focus-visible {
		outline: 2px solid var(--navy);
	}
	.tabs kbd {
		font-size: 0.65rem;
		border: 1px solid currentColor;
		padding: 0 0.3rem;
	}
	.view {
		min-height: 17rem;
		padding-top: 1.5rem;
	}
	.view-note {
		font-family: var(--serif);
		font-size: 1.1rem;
		margin: 0 0 1rem;
		max-width: 60ch;
	}
	.screen {
		margin: 0;
		padding: 1rem 1.2rem;
		border: 1px solid var(--ink);
		background: var(--ink);
		color: var(--bg);
		white-space: pre;
		word-break: normal;
		overflow-x: auto;
		font-size: 0.75rem;
		line-height: 1.75;
		box-shadow: 6px 6px 0 var(--teal);
	}

	.cols {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 3rem;
		min-height: 14rem;
	}
	.cols article p,
	.limits {
		font-family: var(--serif);
		font-size: 1.02rem;
		line-height: 1.6;
		margin: 0;
	}
	.title-l {
		font: 600 1.25rem var(--serif);
		margin: 0 0 0.8rem;
		padding-bottom: 0.6rem;
		border-bottom: 1px solid var(--ink);
	}
	.limits {
		padding-left: 1.1rem;
	}
	.limits li + li {
		margin-top: 0.4rem;
	}

	.end .band-label,
	.end .band-body {
		padding-block: 1.4rem;
	}
	.brand-s {
		font: 700 1.2rem var(--serif);
		text-decoration: none;
	}
	.end-body {
		display: flex;
		flex-wrap: wrap;
		justify-content: space-between;
		align-items: center;
		gap: 1rem;
		font: 0.72rem var(--mono);
		letter-spacing: 0.08em;
		text-transform: uppercase;
	}
	.links {
		display: flex;
		gap: 1.5rem;
		flex-wrap: wrap;
	}
	.links a {
		text-decoration: none;
		border-bottom: 1px solid transparent;
		transition: border-color 0.2s;
	}
	.links a:hover {
		border-color: var(--ink);
	}

	button:focus-visible,
	a:focus-visible {
		outline: 2px solid var(--navy);
		outline-offset: 2px;
	}

	@media (max-width: 1280px) {
		nav {
			gap: 1.4rem;
			padding-left: 2rem;
		}
		.metrics {
			grid-template-columns: repeat(2, minmax(0, 12rem));
		}
	}
	@media (max-width: 1100px) {
		.frame {
			grid-template-columns: minmax(0, 1fr) minmax(0, 2.6fr);
		}
		nav .ext {
			display: none;
		}
		.right {
			grid-column: 1 / -1;
			border-left: 0;
			border-top: 1px solid var(--ink);
			display: grid;
			grid-template-columns: 1fr 1fr;
			column-gap: 3rem;
		}
		.rights {
			grid-column: 1 / -1;
		}
		.pipe {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
		.cols {
			grid-template-columns: 1fr;
			gap: 2rem;
		}
	}
	@media (max-width: 760px) {
		.frame {
			grid-template-columns: minmax(0, 1fr);
		}
		.top {
			display: block;
		}
		.brand {
			border-right: 0;
			border-bottom: 1px solid var(--ink);
			padding: 0.9rem 1rem;
		}
		nav {
			gap: 1.2rem;
			padding: 0 0 0 1rem;
			overflow-x: auto;
			height: 3rem;
			scrollbar-width: none;
		}
		.left,
		.band-label {
			border-right: 0;
			border-bottom: 1px solid var(--ink);
			padding: 2rem 1rem;
		}
		.center,
		.right,
		.band-body {
			padding: 2rem 1rem;
		}
		.band-body {
			grid-column: 1;
		}
		.right {
			display: flex;
		}
		.metrics {
			gap: 1.5rem;
		}
		.rail {
			display: none;
		}
		.term {
			box-shadow: 4px 4px 0 var(--ink);
		}
		.row {
			grid-template-columns: 3.6rem 2.6rem 1fr;
		}
		.row > span:first-child {
			display: none;
		}
		.inspect-grid {
			grid-template-columns: 1fr;
			gap: 1rem;
		}
		.pipe {
			grid-template-columns: 1fr;
		}
		.dec-head {
			display: none;
		}
		.dec li {
			grid-template-columns: 1fr;
			gap: 0.3rem;
		}
	}
</style>
