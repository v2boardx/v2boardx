<?php

namespace App\Protocols;

use App\Utils\Helper;

class Shadowrocket
{
    public $flag = 'shadowrocket';
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
        //display remaining traffic and expire date
        $upload = round($user['u'] / (1024*1024*1024), 2);
        $download = round($user['d'] / (1024*1024*1024), 2);
        $totalTraffic = round($user['transfer_enable'] / (1024*1024*1024), 2);
        $expiredDate = date('Y-m-d', $user['expired_at']);
        $uri .= "STATUS=🚀↑:{$upload}GB,↓:{$download}GB,TOT:{$totalTraffic}GB💡Expires:{$expiredDate}\r\n";
        foreach ($servers as $item) {
            if ($item['type'] === 'shadowsocks') {
                $uri .= self::buildShadowsocks($user['uuid'], $item);
            }
            if ($item['type'] === 'vmess') {
                $uri .= self::buildVmess($user['uuid'], $item);
            }
            if ($item['type'] === 'vless') {
                $uri .= self::buildVless($user['uuid'], $item);
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
        if ($server['cipher'] === '2022-blake3-aes-128-gcm') {
            $serverKey = Helper::getServerKey($server['created_at'], 16);
            $userKey = Helper::uuidToBase64($password, 16);
            $password = "{$serverKey}:{$userKey}";
        }
        if ($server['cipher'] === '2022-blake3-aes-256-gcm') {
            $serverKey = Helper::getServerKey($server['created_at'], 32);
            $userKey = Helper::uuidToBase64($password, 32);
            $password = "{$serverKey}:{$userKey}";
        }
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
        $userinfo = base64_encode('auto:' . $uuid . '@' . $server['host'] . ':' . $server['port']);
        $config = [
            'tfo' => 1,
            'remark' => $server['name'],
            'alterId' => 0
        ];
        if ($server['tls']) {
            $config['tls'] = 1;
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                if (isset($tlsSettings['allowInsecure']) && !empty($tlsSettings['allowInsecure']))
                    $config['allowInsecure'] = (int)$tlsSettings['allowInsecure'];
                if (isset($tlsSettings['serverName']) && !empty($tlsSettings['serverName']))
                    $config['peer'] = $tlsSettings['serverName'];
            }
        }
        if ($server['network'] === 'tcp') {
            if ($server['networkSettings']) {
                $tcpSettings = $server['networkSettings'];
                if (isset($tcpSettings['header']['type']) && !empty($tcpSettings['header']['type']))
                    $config['obfs'] = $tcpSettings['header']['type'];
                if (isset($tcpSettings['header']['request']['path'][0]) && !empty($tcpSettings['header']['request']['path'][0]))
                    $config['path'] = $tcpSettings['header']['request']['path'][0];
            }
        }
        if ($server['network'] === 'ws') {
            $config['obfs'] = "websocket";
            if ($server['networkSettings']) {
                $wsSettings = $server['networkSettings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    $config['path'] = $wsSettings['path'];
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    $config['obfsParam'] = $wsSettings['headers']['Host'];
            }
        }
        if ($server['network'] === 'grpc') {
            $config['obfs'] = "grpc";
            if ($server['networkSettings']) {
                $grpcSettings = $server['networkSettings'];
                if (isset($grpcSettings['serviceName']) && !empty($grpcSettings['serviceName']))
                    $config['path'] = $grpcSettings['serviceName'];
            }
            if (isset($tlsSettings)) {
                $config['host'] = $tlsSettings['serverName'];
            } else {
                $config['host'] = $server['host'];
            }
        }
        $query = http_build_query($config, '', '&', PHP_QUERY_RFC3986);
        $uri = "vmess://{$userinfo}?{$query}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildVless($uuid, $server){
        $host = $server['host'];
        $port = $server['port'];
        $name = $server['name'];

        $config = [
            'tfo' => 0,
        ];

        if ($server['tls']) {
            $config['tls'] = 1;
            if (isset($server['flow']) && !empty($server['flow'])) {
                switch ($server['flow']) {
                    case 'xtls-rprx-direct':
                        $config['xtls'] = 1;
                        break;
                    case 'xtls-rprx-vision':
                        $config['xtls'] = 2;
                        break;
                    default:
                        $config['xtls'] = 0;
                        break;
                }
            }

            if ($server['tls_settings']) {
                $tlsSettings = $server['tls_settings'];
                if (isset($tlsSettings['server_name']) && !empty($tlsSettings['server_name'])) {
                    $config['peer'] = $tlsSettings['server_name'];
                }
                // REALITY
                if ($server['tls'] === 2) {
                    $config['pbk'] = $tlsSettings['public_key'];
                    $config['sid'] = $tlsSettings['short_id'];
                }
            }
        }

        if ($server['network'] === 'tcp') {
            $config['obfs'] = 'none';
        }

        if ((string)$server['network'] === 'ws') {
            $config['obfs'] = 'websocket';
            if ($server['network_settings']) {
                $wsSettings = $server['network_settings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path'])) {
                    $config['path'] = $wsSettings['path'];
                }
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host'])) {
                    $config['obfsParam'] = $wsSettings['headers']['Host'];
                }

            }
        }

        if ((string)$server['network'] === 'grpc') {
            $config['obfs'] = 'grpc';
            if ($server['network_settings']) {
                $grpcSettings = $server['network_settings'];
                if (isset($grpcSettings['serviceName']) && !empty($grpcSettings['serviceName'])) {
                    $config['path'] = $grpcSettings['serviceName'];
                }
            }

            if (isset($tlsSettings)) {
                $config['obfsParam'] = $tlsSettings['serverName'];
            } else {
                $config['obfsParam'] = $host;
            }
        }

        if ((string)$server['network'] === 'h2') {
            $config['obfs'] = 'h2';
            if ($server['network_settings']) {
                $h2Settings = $server['network_settings'];
                if (isset($h2Settings['path']) && !empty($h2Settings['path'])) {
                    $config['path'] = $h2Settings['path'];
                }
                if (isset($h2Settings['host']) && !empty($h2Settings['host'])) {
                    $config['obfsParam'] = array($h2Settings['host']);
                }
            }
        }

        $serverconn = base64_encode("auto:{$uuid}@{$host}:{$port}");
        $servername = urlencode($name);
        $query = http_build_query($config);
        $uri = sprintf("vless://%s?remarks=%s&%s\r\n", $serverconn, $servername, $query);
        return $uri;
    }

    public static function buildTrojan($password, $server)
    {
        $name = rawurlencode($server['name']);
        $query = http_build_query([
            'allowInsecure' => $server['allow_insecure'],
            'peer' => $server['server_name']
        ]);
        $uri = "trojan://{$password}@{$server['host']}:{$server['port']}?{$query}&tfo=1#{$name}";
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
