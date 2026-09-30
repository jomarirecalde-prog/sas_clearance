<?php

declare(strict_types=1);

namespace App\Support;

final class StudentPwa
{
    public static function iconDirectory(): string
    {
        return dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'icons';
    }

    public static function scope(string $appBasePath): string
    {
        $base = rtrim(str_replace('\\', '/', $appBasePath), '/');

        return $base === '' ? '/' : $base . '/';
    }

    public static function ensureIcons(): void
    {
        $dir = self::iconDirectory();
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }

        foreach ([192, 512] as $size) {
            $path = $dir . DIRECTORY_SEPARATOR . 'icon-' . $size . '.png';
            if (!is_file($path) || filesize($path) < 100) {
                file_put_contents($path, self::buildIconPng($size));
            }
        }

        $svgPath = $dir . DIRECTORY_SEPARATOR . 'icon.svg';
        if (!is_file($svgPath)) {
            file_put_contents($svgPath, self::iconSvg());
        }
    }

    public static function iconPath(int $size): string
    {
        self::ensureIcons();

        return self::iconDirectory() . DIRECTORY_SEPARATOR . 'icon-' . $size . '.png';
    }

    /**
     * @return array<string, mixed>
     */
    public static function manifest(string $appBasePath, callable $url): array
    {
        self::ensureIcons();
        $scope = self::scope($appBasePath);
        $startUrl = $url('/app');
        $icon192 = $url('/app/icon/192');
        $icon512 = $url('/app/icon/512');

        return [
            'id' => $startUrl,
            'name' => 'SAFE Student Clearance',
            'short_name' => 'SAFE Student',
            'description' => 'Western Philippines University student clearance app. Track offices, upload requirements, and message signatories.',
            'start_url' => $startUrl,
            'scope' => $scope,
            'display' => 'standalone',
            'display_override' => ['standalone', 'minimal-ui', 'browser'],
            'orientation' => 'portrait-primary',
            'background_color' => '#0f3b4f',
            'theme_color' => '#0f3b4f',
            'lang' => 'en',
            'dir' => 'ltr',
            'categories' => ['education', 'productivity'],
            'prefer_related_applications' => false,
            'icons' => [
                [
                    'src' => $icon192,
                    'sizes' => '192x192',
                    'type' => 'image/png',
                    'purpose' => 'any',
                ],
                [
                    'src' => $icon512,
                    'sizes' => '512x512',
                    'type' => 'image/png',
                    'purpose' => 'any',
                ],
                [
                    'src' => $icon192,
                    'sizes' => '192x192',
                    'type' => 'image/png',
                    'purpose' => 'maskable',
                ],
                [
                    'src' => $icon512,
                    'sizes' => '512x512',
                    'type' => 'image/png',
                    'purpose' => 'maskable',
                ],
            ],
            'shortcuts' => [
                [
                    'name' => 'Dashboard',
                    'short_name' => 'Home',
                    'url' => $url('/dashboard'),
                    'icons' => [['src' => $icon192, 'sizes' => '192x192', 'type' => 'image/png']],
                ],
                [
                    'name' => 'Messages',
                    'short_name' => 'Messages',
                    'url' => $url('/student/messages'),
                    'icons' => [['src' => $icon192, 'sizes' => '192x192', 'type' => 'image/png']],
                ],
            ],
        ];
    }

    public static function serviceWorker(string $appBasePath, callable $url): string
    {
        $offlineUrl = $url('/app/offline');
        $icon192 = $url('/app/icon/192');
        $cacheName = 'safe-student-v1';
        $offlineUrlJs = json_encode($offlineUrl, JSON_UNESCAPED_SLASHES);
        $iconJs = json_encode($icon192, JSON_UNESCAPED_SLASHES);
        $cacheJs = json_encode($cacheName);

        return <<<JS
const CACHE_NAME = {$cacheJs};
const OFFLINE_URL = {$offlineUrlJs};
const PRECACHE = [OFFLINE_URL, {$iconJs}];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
    )).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') {
    return;
  }
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) {
    return;
  }
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(async () => {
        const cached = await caches.match(OFFLINE_URL);
        return cached || new Response('You are offline.', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      })
    );
    return;
  }
  event.respondWith(
    caches.match(request).then((cached) => {
      const networked = fetch(request).then((response) => {
        if (response && response.ok && url.pathname.indexOf('/app/icon/') !== -1) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        }
        return response;
      }).catch(() => cached);
      return cached || networked;
    })
  );
});
JS;
    }

    public static function offlinePage(string $appTitle, string $homeUrl): string
    {
        $title = htmlspecialchars($appTitle, ENT_QUOTES, 'UTF-8');
        $home = htmlspecialchars($homeUrl, ENT_QUOTES, 'UTF-8');

        return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<meta name="theme-color" content="#0f3b4f"><title>' . $title . ' · Offline</title>'
            . '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:Inter,system-ui,sans-serif;background:#0f3b4f;color:#fff;padding:24px;text-align:center}'
            . '.card{max-width:360px}h1{font-size:1.4rem;margin:0 0 .6rem}p{opacity:.85;line-height:1.5}a{color:#ffd966;font-weight:700;text-decoration:none}</style></head>'
            . '<body><div class="card"><h1>You are offline</h1><p>Reconnect to load your clearance dashboard, then try again.</p>'
            . '<p><a href="' . $home . '">Open Student App</a></p></div></body></html>';
    }

    public static function iconSvg(): string
    {
        return <<<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" role="img" aria-label="SAFE Student">
  <rect width="512" height="512" rx="112" fill="#0f3b4f"/>
  <circle cx="256" cy="256" r="168" fill="#ffb947"/>
  <path d="M168 262 l58 58 118-132" fill="none" stroke="#0f3b4f" stroke-width="44" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
SVG;
    }

    public static function buildIconPng(int $size): string
    {
        $size = max(48, min(1024, $size));
        $raw = '';
        $cx = ($size - 1) / 2;
        $cy = ($size - 1) / 2;
        $radius = $size * 0.32;
        $thickness = max(2.2, $size * 0.055);
        $check = [
            [0.33 * $size, 0.52 * $size],
            [0.45 * $size, 0.66 * $size],
            [0.70 * $size, 0.36 * $size],
        ];

        for ($y = 0; $y < $size; $y++) {
            $raw .= "\x00";
            for ($x = 0; $x < $size; $x++) {
                $dx = $x - $cx;
                $dy = $y - $cy;
                $inCircle = ($dx * $dx + $dy * $dy) <= ($radius * $radius);
                $onCheck = self::distanceToPolyline($x, $y, $check) <= $thickness;
                if ($inCircle && $onCheck) {
                    $raw .= "\x0f\x3b\x4f";
                } elseif ($inCircle) {
                    $raw .= "\xff\xb9\x47";
                } else {
                    $raw .= "\x0f\x3b\x4f";
                }
            }
        }

        $ihdr = pack('NNCCCCC', $size, $size, 8, 2, 0, 0, 0);
        $png = "\x89PNG\r\n\x1a\n";
        $png .= self::pngChunk('IHDR', $ihdr);
        $png .= self::pngChunk('IDAT', (string) gzcompress($raw, 9));
        $png .= self::pngChunk('IEND', '');

        return $png;
    }

    /**
     * @param list<array{0:float,1:float}> $points
     */
    private static function distanceToPolyline(float $x, float $y, array $points): float
    {
        $best = PHP_FLOAT_MAX;
        for ($i = 0, $n = count($points) - 1; $i < $n; $i++) {
            $best = min($best, self::distanceToSegment($x, $y, $points[$i][0], $points[$i][1], $points[$i + 1][0], $points[$i + 1][1]));
        }

        return $best;
    }

    private static function distanceToSegment(float $px, float $py, float $ax, float $ay, float $bx, float $by): float
    {
        $abx = $bx - $ax;
        $aby = $by - $ay;
        $len2 = ($abx * $abx) + ($aby * $aby);
        if ($len2 <= 0.0001) {
            return hypot($px - $ax, $py - $ay);
        }
        $t = (($px - $ax) * $abx + ($py - $ay) * $aby) / $len2;
        $t = max(0.0, min(1.0, $t));

        return hypot($px - ($ax + $t * $abx), $py - ($ay + $t * $aby));
    }

    private static function pngChunk(string $type, string $data): string
    {
        return pack('N', strlen($data)) . $type . $data . pack('N', crc32($type . $data));
    }
}
