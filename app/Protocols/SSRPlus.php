<?php

namespace App\Protocols;


class SSRPlus
{
    public $flag = 'ssrplus';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $servers = $this->servers;
        $user = $this->user;
        $uri = '';

        foreach ($servers as $item) {
            if ($item['type'] === 'vmess') {
                $uri .= self::buildVmess($user['uuid'], $item);
            }
            if ($item['type'] === 'vless') {
                $uri .= self::buildVless($user['uuid'], $item);
            }
            if ($item['type'] === 'shadowsocks') {
                $uri .= self::buildShadowsocks($user['uuid'], $item);
            }
            if ($item['type'] === 'trojan') {
                $uri .= self::buildTrojan($user['uuid'], $item);
            }
            if ($item['type'] === 'hysteria') {
                $uri .= self::buildHysteria2($user['uuid'], $item);
            }
        }
        return base64_encode($uri);
    }

    public static function buildShadowsocks($password, $server)
    {
        $name = rawurlencode($server['name']);
        $str = str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode("{$server['cipher']}:{$password}")
        );
        return "ss://{$str}@{$server['host']}:{$server['port']}#{$name}\r\n";
    }

    public static function buildVmess($uuid, $server)
    {
        $config = [
            "v" => "2",
            "ps" => $server['name'],
            "add" => $server['host'],
            "port" => (string)$server['port'],
            "id" => $uuid,
            "aid" => '0',
            "net" => $server['network'],
            "type" => "none",
            "host" => "",
            "path" => "",
            "tls" => $server['tls'] ? "tls" : "",
        ];
        if ($server['tls']) {
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                if (isset($tlsSettings['serverName']) && !empty($tlsSettings['serverName']))
                    $config['sni'] = $tlsSettings['serverName'];
            }
        }
        if ((string)$server['network'] === 'ws') {
            $wsSettings = $server['networkSettings'];
            if (isset($wsSettings['path'])) $config['path'] = $wsSettings['path'];
            if (isset($wsSettings['headers']['Host'])) $config['host'] = $wsSettings['headers']['Host'];
        }
        if ((string)$server['network'] === 'grpc') {
            $grpcSettings = $server['networkSettings'];
            if (isset($grpcSettings['serviceName'])) $config['path'] = $grpcSettings['serviceName'];
        }
        return "vmess://" . base64_encode(json_encode($config)) . "\r\n";
    }

    public static function buildVless($uuid, $server){
        $host = $server['host'];
        $port = $server['port'];
        $name = $server['name'];

        // https://github.com/XTLS/Xray-core/discussions/716
        $config = [
            'type' => $server['network'],
            'encryption' => 'none',
        ];

        if ($server['tls']) {
            if (isset($server['flow']) && !empty($server['flow'])) {
                $config['flow'] = $server['flow'];
            }
            $config['fp'] = Helper::getRandomFingerprint();

            if ($server['tls_settings']) {
                $config['security'] = 'tls';
                $tlsSettings = $server['tls_settings'];
                if (isset($tlsSettings['server_name']) && !empty($tlsSettings['server_name'])) {
                    $config['sni'] = $tlsSettings['server_name'];
                }
                // REALITY
                if ($server['tls'] === 2) {
                    $config['security'] = 'reality';
                    $config['pbk'] = $tlsSettings['public_key'];
                    $config['sid'] = $tlsSettings['short_id'];
                }
            }
        }

        if ((string)$server['network'] === 'ws') {
            if ($server['network_settings']) {
                $wsSettings = $server['network_settings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path'])) {
                    $config['path'] = $wsSettings['path'];
                }
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host'])) {
                    $config['host'] = $wsSettings['headers']['Host'];
                }

            }
        }

        if ((string)$server['network'] === 'grpc') {
            if ($server['network_settings']) {
                $grpcSettings = $server['network_settings'];
                $config['mode'] = 'multi';
                if (isset($grpcSettings['serviceName']) && !empty($grpcSettings['serviceName'])) {
                    $config['serviceName'] = $grpcSettings['serviceName'];
                }
            }
        }

        if ((string)$server['network'] === 'h2') {
            if ($server['network_settings']) {
                $h2Settings = $server['network_settings'];
                if (isset($h2Settings['path']) && !empty($h2Settings['path'])) {
                    $config['path'] = $h2Settings['path'];
                }
                if (isset($h2Settings['host']) && !empty($h2Settings['host'])) {
                    $config['host'] = array($h2Settings['host']);
                }
            }
        }

        $serverconn = "{$uuid}@{$host}:{$port}";
        $query = http_build_query($config);
        $servername = urlencode($name);
        $uri = sprintf("vless://%s?%s#%s\r\n", $serverconn, $query, $servername);
        return $uri;
    }

    public static function buildTrojan($password, $server)
    {
        $name = rawurlencode($server['name']);
        $query = http_build_query([
            'allowInsecure' => $server['allow_insecure'],
            'peer' => $server['server_name'],
            'sni' => $server['server_name']
        ]);
        $uri = "trojan://{$password}@{$server['host']}:{$server['port']}?{$query}#{$name}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildHysteria2($password, $server)
    {
        // hysteria2://letmein@example.com/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=deadbeef&sni=real.example.com
        $config = [
            "sni" => $server['server_name'],
            "fastopen" => 0
        ];
        if (isset($server['obfs_type']) && !empty($server['obfs_type'])) {
            $config['obfs'] = $server['obfs_type'];
            $config['obfs-password'] = $server['server_key'];
        }
        if ($server['insecure']) $config['insecure'] = $server['insecure'];
        $query = http_build_query($config);
        $uri = "hysteria2://{$password}@{$server['host']}:{$server['port']}?{$query}#{$server['name']}";
        $uri .= "\r\n";
        return $uri;
    }
}
