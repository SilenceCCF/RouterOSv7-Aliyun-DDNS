<?php
/**
  Aliyun OpenAPI V3 DDNS 转发代理
 **/

// ------------------- 用户配置开始 -------------------

// 1. 安全令牌 (确保与RouterOS脚本中的一致)
define('SECURITY_TOKEN', 'Any_Random_String_8848!');

// 2. AccessKeyId 白名单 (留空则不处理)
const ALLOWED_ACCESS_KEY_IDS = [
//    'LTAxxxxxxx', // 替换为您自己的 AccessKeyId
];

// 3. 日志文件路径
//    建议将日志文件放在网站根目录之外，或者放在一个配置了禁止访问的目录中。
//    请确保 'logs' 文件夹存在，并且Web服务器用户对其有写入权限。
//    LOG_ENABLED 为日志开关。
define('LOG_FILE', 'ddns_logs/ddns_activity.log');
define('LOG_ENABLED', true); 
// ------------------- 用户配置结束 ---------------------

// --- 安全检查：在执行任何操作之前，首先验证请求的合法性 ---
if (empty($_GET['security_Token']) || $_GET['security_Token'] !== SECURITY_TOKEN) {
	write_log('警告', '拒绝访问：安全令牌无效。'); 
	http_response_code(403);
	die('拒绝访问。');
}

// 检查 AccessKeyId 白名单 (如果白名单不为空)
if (!empty(ALLOWED_ACCESS_KEY_IDS) && (empty($_GET['AccessKeyId']) || !in_array($_GET['AccessKeyId'], ALLOWED_ACCESS_KEY_IDS, true))) {
    write_log('警告', '拒绝访问：AccessKeyId 不在白名单里。');
    http_response_code(403);
    die('拒绝访问。');
}

// --- 工作代码开始 ---

date_default_timezone_set('UTC');

class AliyunDdnsHelper
{
    private const API_HOST = 'dns.aliyuncs.com';
    private const API_VERSION = '2015-01-09';
    private const ALGORITHM = 'ACS3-HMAC-SHA256';

    private $AccessKeyId;
    private $AccessKeySecret;

    public function __construct($accessKeyId, $accessKeySecret) {
        if (empty($accessKeyId) || empty($accessKeySecret)) {
            throw new Exception("AccessKeyId and AccessKeySecret must be provided.");
        }
        $this->AccessKeyId = $accessKeyId;
        $this->AccessKeySecret = $accessKeySecret;
    }
    
    public function handleRequest($getData) {
        $task = $getData['task'] ?? 'unknown';
        $domain = $getData['domainName'] ?? ($getData['rr'] ?? 'unknown');
        write_log('信息', "已收到请求。任务：[{$task}], 域名/主机：[{$domain}]");
        
        switch ($task) {
            case 'query': $this->performQuery($getData); break;
            case 'update': $this->performUpdate($getData); break;
            default:
                write_log('错误', "指定的任务无效：[{$task}]");
                http_response_code(400);
                echo json_encode(['错误' => "任务无效。"]);
        }
    }

    // 查询域名解析
    private function performQuery($getData) {
        $domainName = $getData['domainName'] ?? '';
        if (empty($domainName)) { throw new Exception("查询任务中缺少域名。"); }
        $request = $this->createBaseRequest('GET', 'DescribeSubDomainRecords');
        $request['queryParam'] = ['SubDomain' => $domainName, 'Type' => $getData['recordType'] ?? 'A'];
        $this->signAndCall($request);
    }

    // 更新域名解析
    private function performUpdate($getData) {
        $recordId = $getData['recordId'] ?? '';
        $rr = $getData['rr'] ?? '';
        $newIp = $getData['newIp'] ?? '';
        if (empty($recordId) || !isset($rr) || empty($newIp)) { throw new Exception("更新域名解析任务中缺少 'recordId'、'rr', 或 'newIp' 参数。"); }
        $request = $this->createBaseRequest('GET', 'UpdateDomainRecord');
        $request['queryParam'] = ['RecordId' => $recordId, 'RR' => $rr, 'Value' => $newIp, 'Type' => $getData['recordType'] ?? 'A'];
        $this->signAndCall($request);
    }
    
    private function createBaseRequest($httpMethod, $action) {
        $headers = [ 'host' => self::API_HOST, 'x-acs-action' => $action, 'x-acs-version' => self::API_VERSION, 'x-acs-date' => gmdate('Y-m-d\TH:i:s\Z'), 'x-acs-signature-nonce' => bin2hex(random_bytes(16)), ];
        return ['httpMethod' => $httpMethod, 'canonicalUri' => '/', 'host' => self::API_HOST, 'headers' => $headers, 'queryParam' => [], 'body' => null];
    }
    
    private function signAndCall(&$request) {
        $this->getAuthorization($request);
        $this->callApi($request);
    }
    
    private function getAuthorization(&$request) {
        $request['queryParam'] = $this->processObject($request['queryParam']);
        $canonicalQueryString = $this->buildCanonicalQueryString($request['queryParam']);
        $hashedRequestPayload = hash('sha256', $request['body'] ?? '');
        $request['headers']['x-acs-content-sha256'] = $hashedRequestPayload;
        $canonicalHeaders = $this->buildCanonicalHeaders($request['headers']);
        $signedHeaders = $this->buildSignedHeaders($request['headers']);
        $canonicalRequest = implode("\n", [$request['httpMethod'], $request['canonicalUri'], $canonicalQueryString, $canonicalHeaders, $signedHeaders, $hashedRequestPayload]);
        $hashedCanonicalRequest = hash('sha256', $canonicalRequest);
        $stringToSign = self::ALGORITHM . "\n" . $hashedCanonicalRequest;
        $signature = strtolower(bin2hex(hash_hmac('sha256', $stringToSign, $this->AccessKeySecret, true)));
        $authorization = self::ALGORITHM . " Credential={$this->AccessKeyId},SignedHeaders=$signedHeaders,Signature=$signature";
        $request['headers']['Authorization'] = $authorization;
    }
    
    private function callApi($request) {
        $ch = null;
        try {
            $url = "https://" . $request['host'] . $request['canonicalUri'];
            if (!empty($request['queryParam'])) { $queryString = http_build_query($request['queryParam'], '', '&', PHP_QUERY_RFC3986); $url .= '?' . $queryString; }
            $ch = curl_init();
            curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 15, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_HTTPHEADER => $this->convertHeadersToArray($request['headers'])]);
            $result = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            if (curl_errno($ch)) {
                write_log('错误', 'cURL 错误：' . curl_error($ch));
                header("Content-Type: application/json"); http_response_code(500); echo json_encode(['错误' => 'cURL 错误：' . curl_error($ch)]);
            } else {
                if ($httpCode >= 400) { write_log('错误', "Aliyun API 返回 HTTP {$httpCode}. 结果：{$result}"); }
                header("Content-Type: application/json", true, $httpCode); echo $result;
            }
        } catch (Exception $e) {
            write_log('严重', 'PHP 异常：' . $e->getMessage());
            header("Content-Type: application/json"); http_response_code(500); echo json_encode(['错误' => "代理错误：" . $e->getMessage()]);
        } finally {
            if ($ch) { curl_close($ch); }
        }
    }
    
    private function processObject($value) { if ($value === null) return []; $tmp = []; foreach ($value as $k => $v) { if (0 !== strpos($k, '_')) { $tmp[$k] = $v; } } return self::flatten($tmp); }
    private static function flatten($items = [], $delimiter = '.', $prepend = '') { $flatten = []; foreach ($items as $key => $value) { $pos = \is_int($key) ? $key + 1 : $key; if (\is_object($value)) $value = get_object_vars($value); if (\is_array($value) && !empty($value)) { $flatten = array_merge($flatten, self::flatten($value, $delimiter, $prepend . $pos . $delimiter)); } else { if (\is_bool($value)) $value = true === $value ? 'true' : 'false'; $flatten["$prepend$pos"] = $value; } } return $flatten; }
    private function convertHeadersToArray($headers) { $headerArray = []; foreach ($headers as $key => $value) { $headerArray[] = "$key: $value"; } return $headerArray; }
    private function buildCanonicalQueryString($queryParams) { if (empty($queryParams)) return ''; ksort($queryParams); $params = []; foreach ($queryParams as $k => $v) { $str = rawurlencode($k); if (null !== $v && '' !== $v) { $str .= '=' . rawurlencode($v); } $params[] = $str; } return implode('&', $params); }
    private function buildCanonicalHeaders($headers) { uksort($headers, 'strcasecmp'); $canonicalHeaders = ''; foreach ($headers as $key => $value) { $canonicalHeaders .= strtolower($key) . ':' . trim($value) . "\n"; } return $canonicalHeaders; }
    private function buildSignedHeaders($headers) { $signedHeaders = array_keys($headers); sort($signedHeaders, SORT_STRING | SORT_FLAG_CASE); return implode(';', array_map('strtolower', $signedHeaders)); }
}

/**
 * 日志记录函数
 * @param string $level 日志级别 (e.g., INFO, WARNING, ERROR, SUCCESS)
 * @param string $message 日志消息
 */
function write_log($level, $message) {
    // 检查日志开关。
    if (LOG_ENABLED === false) {
        return;	
    }
    // 默认时区，例如 Asia/Shanghai
    date_default_timezone_set('Asia/Shanghai');
    $timestamp = date('Y-m-d H:i:s T');
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP';
    $logEntry = sprintf("[%s] [%s] [%s] %s" . PHP_EOL, $timestamp, $clientIp, strtoupper($level), $message);
    
    // 使用 @ 符号抑制错误，以防日志文件不可写导致整个脚本崩溃
    @file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
}

// --- 主执行逻辑 ---
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    write_log('警告', '拒绝访问：方法无效。');
    http_response_code(405);
    echo json_encode(['错误' => '只允许 GET 请求。']);
    exit;
}

$log_request_data = $_GET;
// 对 AccessKeySecret 进行脱敏处理
if (isset($log_request_data['AccessKeySecret'])) {
    $log_request_data['AccessKeySecret'] = '[REDACTED]';
}
// 将脱敏后的完整请求参数以JSON格式写入日志
write_log('信息', '收到的请求：' . json_encode($log_request_data));
try {
    $helper = new AliyunDdnsHelper($_GET['AccessKeyId'] ?? null, $_GET['AccessKeySecret'] ?? null);
    $helper->handleRequest($_GET);
} catch (Exception $e) {
    write_log('严重', '主代码块中出现 PHP 异常: ' . $e->getMessage());
    http_response_code(400);
    header("Content-Type: application/json");
    echo json_encode(['错误' => $e->getMessage()]);
}


