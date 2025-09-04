<?php
// Temporarily disable error reporting to prevent HTML output
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Configuration - Edit these values with your actual credentials
$config = [
    'pathao' => [
        'user' => 'ibnasinha125@gmail.com',        // Replace with your Pathao email
        'password' => 'password',             // Replace with your Pathao password
    ],
    'redx' => [
        'phone' => '01764553090',                         // Replace with your RedX phone
        'password' => 'password',               // Replace with your RedX password
    ],
    'steadfast' => [
        'user' => 'ibnasinha125@gmail.com',     // Replace with your Steadfast email
        'password' => 'password',          // Replace with your Steadfast password
    ],
];

// Demo mode flag - set to true to use mock data instead of real API calls
$demoMode = false;

// Normalize phone to local format (e.g., 01712345678) from inputs like +880..., 880..., or 10-digit without leading 0
function normalizePhoneNumber($raw) {
    $digits = preg_replace('/\D+/', '', (string)$raw);
    if ($digits === '') { throw new Exception('Phone number is required'); }
    // If starts with country code 880 (with or without +), convert to local
    if (strpos($digits, '880') === 0) {
        // Use the last 10 digits after country code to make 0 + last10
        $last10 = substr($digits, -10);
        $digits = '0' . $last10;
    } elseif (strlen($digits) === 10) {
        // 10-digit local without leading 0
        $digits = '0' . $digits;
    }
    return $digits;
}

// Phone number validation function (expects normalized local format)
function validatePhoneNumber($phoneNumber) {
    if (!preg_match('/^01[3-9][0-9]{8}$/', $phoneNumber)) {
        throw new Exception('Invalid Bangladeshi phone number. Use local format (e.g., 01712345678). Do not include +88 prefix.');
    }
    return true;
}

// Simple file-based cache wrapper
function cached($key, $ttl, callable $producer) {
    $file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cf_cache_' . md5($key) . '.json';
    if (is_file($file)) {
        $age = time() - filemtime($file);
        if ($age < $ttl) {
            $d = json_decode(@file_get_contents($file), true);
            if (is_array($d)) return $d;
        }
    }
    $res = $producer();
    if (is_array($res) && empty($res['error'])) {
        @file_put_contents($file, json_encode($res), LOCK_EX);
    }
    return $res;
}

// Pathao Service - Real Implementation
function checkPathao($phoneNumber, $username, $password) {
    try {
        // Prepare reusable cURL handle
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 12,
            CURLOPT_FORBID_REUSE => false,
            CURLOPT_ENCODING => '',
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept: application/json, text/plain, */*',
                'Connection: keep-alive',
            ],
        ]);

        // Access token cache
        $tokenFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pathao_token.json';
        $accessToken = null;
        if (is_file($tokenFile)) {
            $tok = json_decode(@file_get_contents($tokenFile), true);
            if (is_array($tok) && !empty($tok['token']) && !empty($tok['ts'])) {
                // reuse for up to 30 min unless 401
                if ((time() - (int)$tok['ts']) < 1800) { $accessToken = $tok['token']; }
            }
        }

        if (!$accessToken) {
            // Step 1: Login to Pathao
            $loginData = json_encode(['username' => $username, 'password' => $password]);
            curl_setopt_array($ch, [
                CURLOPT_URL => 'https://merchant.pathao.com/api/v1/login',
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $loginData,
            ]);
            // override headers to include content-type
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept: application/json, text/plain, */*',
                'Connection: keep-alive',
                'Content-Type: application/json'
            ]);
            $response = curl_exec($ch);
            if ($response === false) {
                $err = curl_error($ch);
                curl_close($ch);
                return ['error' => 'Failed to connect to Pathao API: ' . $err];
            }
            $data = json_decode($response, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                curl_close($ch);
                return ['error' => 'Invalid JSON response from Pathao API'];
            }
            $accessToken = trim($data['access_token'] ?? '');
            if (!$accessToken) {
                curl_close($ch);
                return ['error' => 'No access token received from Pathao - Check credentials'];
            }
            @file_put_contents($tokenFile, json_encode(['token' => $accessToken, 'ts' => time()]), LOCK_EX);
        }

        // Step 2: Get customer delivery data
        $customerData = json_encode(['phone' => $phoneNumber]);
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://merchant.pathao.com/api/v1/user/success',
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $customerData,
        ]);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept: application/json, text/plain, */*',
            'Connection: keep-alive',
            'Content-Type: application/json',
            'Authorization: Bearer ' . $accessToken,
        ]);
        $response = curl_exec($ch);
        $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($http === 401) {
            // token expired — clear and retry once
            @unlink($tokenFile);
            curl_close($ch);
            return checkPathao($phoneNumber, $username, $password);
        }
        if ($response === false) {
            $err = curl_error($ch);
            curl_close($ch);
            return ['error' => 'Failed to retrieve customer data from Pathao: ' . $err];
        }
        curl_close($ch);

        $object = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['error' => 'Invalid JSON response from Pathao customer data API'];
        }

        return [
            'success' => $object['data']['customer']['successful_delivery'] ?? 0,
            'cancel' => ($object['data']['customer']['total_delivery'] ?? 0) - ($object['data']['customer']['successful_delivery'] ?? 0),
            'total' => $object['data']['customer']['total_delivery'] ?? 0,
        ];

    } catch (Exception $e) {
        return ['error' => 'Failed to check Pathao: ' . $e->getMessage()];
    }
}

// Steadfast Service - Real Implementation
function checkSteadfast($phoneNumber, $email, $password) {
    try {
        // Use cURL with cookie jar to maintain session across requests
        $cookieFile = tempnam(sys_get_temp_dir(), 'sf_cookies_');
        if ($cookieFile === false) {
            return ['error' => 'Unable to create temporary cookie storage for Steadfast session'];
        }

        // Step 1: GET login page to obtain CSRF token and initial cookies
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://steadfast.com.bd/login',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 12,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_COOKIEJAR => $cookieFile,
            CURLOPT_COOKIEFILE => $cookieFile,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36',
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.9',
                'Connection: keep-alive',
            ],
        ]);
        $loginPage = curl_exec($ch);
        if ($loginPage === false) {
            $err = curl_error($ch);
            curl_close($ch);
            @unlink($cookieFile);
            return ['error' => 'Failed to connect to Steadfast: ' . $err];
        }

        // Extract CSRF token from the login page
        $token = null;
        if (preg_match('/<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']/', $loginPage, $m)) {
            $token = $m[1];
        }
        if (!$token) {
            curl_close($ch);
            @unlink($cookieFile);
            return ['error' => 'CSRF token not found on Steadfast login page'];
        }
        
        // Step 2: POST login with credentials and CSRF token
        $postFields = http_build_query([
            '_token' => $token,
            'email' => $email,
            'password' => $password,
        ]);
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://steadfast.com.bd/login',
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postFields,
            CURLOPT_HTTPHEADER => [
                    'Content-Type: application/x-www-form-urlencoded',
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36',
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Origin: https://steadfast.com.bd',
                'Referer: https://steadfast.com.bd/login',
            ],
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
        ]);
        $loginResponse = curl_exec($ch);
        if ($loginResponse === false) {
            $err = curl_error($ch);
            curl_close($ch);
            @unlink($cookieFile);
            return ['error' => 'Login to Steadfast failed: ' . $err];
        }

        // Heuristics to determine login success
        $loginFailed = false;
        $errorIndicators = ['invalid', 'incorrect', 'failed', 'error'];
        foreach ($errorIndicators as $indicator) {
            if (stripos($loginResponse, $indicator) !== false) {
                $loginFailed = true;
                break;
            }
        }
        // Do not abort on heuristic login failure; proceed to try fraud endpoint (some envs may still allow access)

        // Step 3: GET fraud data while preserving session cookies
        $targetUrl = 'https://steadfast.com.bd/user/frauds/check/' . rawurlencode($phoneNumber);
        curl_setopt_array($ch, [
            CURLOPT_HTTPGET => true,
            CURLOPT_POST => false,
            CURLOPT_URL => $targetUrl,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36',
                'Accept: application/json, text/plain, */*',
                'X-Requested-With: XMLHttpRequest',
                'Referer: https://steadfast.com.bd/',
                'Connection: keep-alive',
            ],
        ]);
        $fraudResponse = curl_exec($ch);
        if ($fraudResponse === false) {
            $err = curl_error($ch);
            // Try fallback without cookies (public)
            curl_close($ch);
            $ch2 = curl_init();
            curl_setopt_array($ch2, [
                CURLOPT_URL => $targetUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT => 12,
                CURLOPT_HTTPHEADER => [
                    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36',
                    'Accept: application/json, text/plain, */*',
                    'X-Requested-With: XMLHttpRequest',
                    'Connection: keep-alive',
                ],
            ]);
            $fraudResponse = curl_exec($ch2);
            $fallbackErr = $fraudResponse === false ? curl_error($ch2) : '';
            curl_close($ch2);
            if ($fraudResponse === false) {
                @unlink($cookieFile);
                return ['error' => 'Failed to fetch fraud data from Steadfast: ' . $err . ($fallbackErr ? '; fallback: ' . $fallbackErr : '')];
            }
        }
        curl_close($ch);

        // Clean up cookie file
        @unlink($cookieFile);

        // If HTML returned, surface a clear error
        if (stripos($fraudResponse, '<html') !== false || stripos($fraudResponse, '<!DOCTYPE') !== false) {
            if (stripos($fraudResponse, 'not found') !== false || stripos($fraudResponse, '404') !== false) {
                return ['error' => 'Steadfast fraud endpoint not found - Site structure may have changed'];
            }
            return ['error' => 'Steadfast returned HTML instead of JSON for fraud data'];
        }

        // Attempt to parse JSON
        $data = json_decode($fraudResponse, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($data)) {
            $successful = (int)($data['total_delivered'] ?? 0);
            $cancelled = (int)($data['total_cancelled'] ?? 0);
            $total = $successful + $cancelled;

            // Extract fraud messages if present
            $frauds = [];
            if (isset($data['frauds']) && is_array($data['frauds'])) {
                foreach ($data['frauds'] as $fraud) {
                    $frauds[] = [
                        'id' => $fraud['id'] ?? null,
                        'phone' => $fraud['phone'] ?? null,
                        'name' => $fraud['name'] ?? null,
                        'details' => $fraud['details'] ?? null,
                        'created_at' => $fraud['created_at'] ?? null,
                    ];
                }
            }

            $result = [
                'success' => $successful,
                'cancel' => $cancelled,
                'total' => $total,
            ];
            if (!empty($frauds)) {
                $result['frauds'] = $frauds;
            }
            return $result;
        }

        return ['error' => 'Invalid response from Steadfast fraud data API'];
    } catch (Exception $e) {
        return ['error' => 'Failed to check Steadfast: ' . $e->getMessage()];
    }
}

// RedX Service - Real Implementation
function checkRedx($phoneNumber, $loginPhone, $password) {
    try {
        // Lightweight disk cache to avoid rate limits
        $cacheDir = sys_get_temp_dir();
        $phoneKey = preg_replace('/[^0-9]/', '', $phoneNumber);
        $cacheFile = rtrim($cacheDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'redx_cache_' . $phoneKey . '.json';
        $cooldownFile = rtrim($cacheDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'redx_last_call.txt';
        $cacheTtl = 5; // 5 seconds
        $minInterval = 5; // 5 seconds between remote calls

        // Serve from cache if fresh
        if (is_file($cacheFile)) {
            $stat = @stat($cacheFile);
            if ($stat && (time() - $stat['mtime'] <= $cacheTtl)) {
                $cached = json_decode(@file_get_contents($cacheFile), true);
                if (is_array($cached)) {
                    $cached['note'] = ($cached['note'] ?? '') . ' (served from cache)';
                    return $cached;
                }
            }
        }

        // Enforce minimal interval between calls
        if (is_file($cooldownFile)) {
            $last = (int)@file_get_contents($cooldownFile);
            if ($last && (time() - $last) < $minInterval) {
                if (is_file($cacheFile)) {
                    $cached = json_decode(@file_get_contents($cacheFile), true);
                    if (is_array($cached)) {
                        $cached['note'] = 'Recent RedX query throttled; showing cached result';
                        return $cached;
                    }
                }
                return ['error' => 'RedX is rate limited. Please try again in a few seconds.'];
            }
        }

        // Helper: cURL request with status code
        $requestJson = function (string $url, array $opts = []) {
            $ch = curl_init();
            $headers = $opts['headers'] ?? [];
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT => 12,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_ENCODING => '',
                CURLOPT_FORBID_REUSE => false,
            ]);
            if (isset($opts['method']) && strtoupper($opts['method']) === 'POST') {
                curl_setopt($ch, CURLOPT_POST, true);
                if (isset($opts['body'])) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $opts['body']);
                }
            }
            $body = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = $body === false ? curl_error($ch) : '';
            curl_close($ch);
            return [$status, $body, $err];
        };

        // Mark call time
        @file_put_contents($cooldownFile, (string)time(), LOCK_EX);

        // Step 1: Login (with retries/backoff on 429/5xx) with token cache
        $tokenFile = rtrim($cacheDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'redx_token.json';
        $tokenTtl = 5;        // soft TTL for fresh token use
        $tokenHardTtl = 1800; // hard TTL to allow reuse if login is rate limited
        // Try cached token first (soft, then hard)
        if (is_file($tokenFile)) {
            $tok = json_decode(@file_get_contents($tokenFile), true);
            if (is_array($tok) && !empty($tok['token']) && !empty($tok['ts'])) {
                $age = time() - (int)$tok['ts'];
                if ($age < $tokenHardTtl) {
                    // Use token even if soft TTL expired; we'll relogin only on 401
                    $accessToken = $tok['token'];
                }
            }
        }
        $loginPayload = json_encode([
            'phone' => '88' . preg_replace('/[^0-9]/', '', $loginPhone),
            'password' => $password,
        ]);
        $loginHeaders = [
            'Content-Type: application/json',
            'Accept: application/json, text/plain, */*',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ];
        $loginEndpoints = [
            'https://api.redx.com.bd/v4/auth/login',
            'https://api.redx.com.bd/v1/auth/login',
        ];

        $accessToken = $accessToken ?? null;
        $backoffs = [0.5];
        if (!$accessToken) {
            foreach ($loginEndpoints as $endpoint) {
                foreach ($backoffs as $i => $sleep) {
                    [$code, $body, $err] = $requestJson($endpoint, [
                'method' => 'POST',
                        'headers' => $loginHeaders,
                        'body' => $loginPayload,
                    ]);
                    if ($body === false || ($code >= 500 && $code < 600) || $code === 0) {
                        // transient/server/network
                        usleep((int)($sleep * 1_000_000));
                        continue;
                    }
                    if ($code === 429) {
                        // rate limited
                        usleep((int)($sleep * 1_000_000));
                        continue;
                    }
                    if ($code === 404) {
                        // try next endpoint immediately
                        break;
                    }
                    // Accept 200-299 responses
                    if ($code >= 200 && $code < 300) {
                        $json = json_decode($body, true);
                        $token = $json['data']['accessToken'] ?? null;
                        if ($token) { 
                            $accessToken = $token; 
                            // persist token
                            @file_put_contents($tokenFile, json_encode(['token' => $accessToken, 'ts' => time()]), LOCK_EX);
                            break 2; 
                        }
                    }
                    // anything else, backoff small
                    usleep((int)($sleep * 1_000_000));
                }
            }
        }
        
        if (!$accessToken) {
            // If we have cache, serve it instead of hard failing
            if (is_file($cacheFile)) {
                $cached = json_decode(@file_get_contents($cacheFile), true);
                if (is_array($cached)) {
                    $cached['note'] = 'RedX login limited; showing last cached result';
                    return $cached;
                }
            }
            return ['error' => 'RedX login rate limited or unavailable. Please try again shortly.'];
        }

        // Step 2: Fetch stats (retry if 429/5xx)
        $statsUrl = 'https://redx.com.bd/api/redx_se/admin/parcel/customer-success-return-rate?phoneNumber=' . urlencode('88' . preg_replace('/[^0-9]/', '', $phoneNumber));
        $statsHeaders = [
                    'Accept: application/json, text/plain, */*',
                    'Content-Type: application/json',
            'Authorization: Bearer ' . $accessToken,
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ];

        $object = null;
        $retriedAfter401 = false;
        foreach ($backoffs as $sleep) {
            // If we have an accessToken from cache, ensure header is up to date
            $statsHeaders[2] = 'Authorization: Bearer ' . $accessToken;
            [$code, $body, $err] = $requestJson($statsUrl, [ 'headers' => $statsHeaders ]);
            if ($body === false || $code === 0 || ($code >= 500 && $code < 600)) {
                usleep((int)($sleep * 1_000_000));
                continue;
            }
            if ($code === 401 && !$retriedAfter401) {
                // Token expired — delete cached token and re-login once
                @unlink($tokenFile);
                $accessToken = null;
                // force re-login
                foreach ($loginEndpoints as $endpoint) {
                    [$c2, $b2, $e2] = $requestJson($endpoint, [
                        'method' => 'POST', 'headers' => $loginHeaders, 'body' => $loginPayload
                    ]);
                    if ($c2 >= 200 && $c2 < 300) {
                        $j2 = json_decode($b2, true);
                        $t2 = $j2['data']['accessToken'] ?? null;
                        if ($t2) {
                            $accessToken = $t2;
                            @file_put_contents($tokenFile, json_encode(['token' => $accessToken, 'ts' => time()]), LOCK_EX);
                            $statsHeaders[2] = 'Authorization: Bearer ' . $accessToken; // update header
                            $retriedAfter401 = true;
                            break;
                        }
                    }
                }
                if ($retriedAfter401) { continue; }
            }
            if ($code === 429) { // rate limited
                usleep((int)($sleep * 1_000_000));
                continue;
            }
            if ($code === 404) {
                // endpoint moved/unavailable
                break;
            }
            if ($code >= 200 && $code < 300) {
                $json = json_decode($body, true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    $object = $json;
                    break;
                }
            }
            usleep((int)($sleep * 1_000_000));
        }

        if (!$object || !isset($object['data'])) {
            if (is_file($cacheFile)) {
                $cached = json_decode(@file_get_contents($cacheFile), true);
                if (is_array($cached)) {
                    $cached['note'] = 'RedX query limited; showing last cached result';
                    return $cached;
                }
            }
            return ['error' => 'RedX data temporarily unavailable (rate limit or endpoint issue). Try again later.'];
        }

        $result = [
            'success' => (int)($object['data']['deliveredParcels'] ?? 0),
            'cancel' => isset($object['data']['totalParcels'], $object['data']['deliveredParcels'])
                ? ((int)$object['data']['totalParcels'] - (int)$object['data']['deliveredParcels'])
                : 0,
            'total' => (int)($object['data']['totalParcels'] ?? 0),
        ];
        
        // Save cache
        @file_put_contents($cacheFile, json_encode($result), LOCK_EX);
        return $result;

    } catch (Exception $e) {
        return ['error' => 'Failed to check RedX: ' . $e->getMessage()];
    }
}

// Lightweight single-service JSON endpoint for internal fan-out
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['service'], $_GET['phone'])) {
    if (ob_get_level()) { ob_end_clean(); }
    ob_start();
    header('Content-Type: application/json');
    try {
        $phone = $_GET['phone'];
        validatePhoneNumber($phone);
        $s = $_GET['service'];
        if ($s === 'steadfast') { ob_clean(); echo json_encode(cached('steadfast:'.$phone, 300, function() use ($phone,$config){ return checkSteadfast($phone, $config['steadfast']['user'], $config['steadfast']['password']); }), JSON_UNESCAPED_UNICODE); ob_end_flush(); exit; }
        if ($s === 'pathao')    { ob_clean(); echo json_encode(cached('pathao:'.$phone,    300, function() use ($phone,$config){ return checkPathao($phone,  $config['pathao']['user'],    $config['pathao']['password']); }), JSON_UNESCAPED_UNICODE);     ob_end_flush(); exit; }
        if ($s === 'redx')      { ob_clean(); echo json_encode(cached('redx:'.$phone,      300, function() use ($phone,$config){ return checkRedx($phone,    $config['redx']['phone'],     $config['redx']['password']); }), JSON_UNESCAPED_UNICODE);       ob_end_flush(); exit; }
        ob_clean(); echo json_encode(['error' => 'Unknown service']);
    } catch (Exception $e) {
        ob_clean(); echo json_encode(['error' => $e->getMessage()]);
    }
    ob_end_flush();
    exit;
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['phoneNumber'])) {
    // Start output buffering and clean any previous output
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_start();
    
    // Set JSON header
    header('Content-Type: application/json');
    header('Cache-Control: no-cache, must-revalidate');
    
    try {
        $phoneNumber = normalizePhoneNumber($_POST['phoneNumber'] ?? '');
        
        // Log the request for debugging
        error_log("Fraud check request received for phone: " . $phoneNumber);
        
        // Validate phone number
        validatePhoneNumber($phoneNumber);
        
        // Get results from all services
        $results = [];
        
        // Check each service individually to identify which one is failing
        if ($demoMode) {
            // Demo mode - generate mock data for testing
        $results = [
                'steadfast' => [
                    'success' => rand(8, 25),
                    'cancel' => rand(1, 5),
                    'total' => rand(12, 35),
                    'note' => 'Demo mode - Mock data'
                ],
                'pathao' => [
                    'success' => rand(10, 30),
                    'cancel' => rand(0, 4),
                    'total' => rand(15, 40),
                    'note' => 'Demo mode - Mock data'
                ],
                'redx' => [
                    'success' => rand(6, 20),
                    'cancel' => rand(1, 6),
                    'total' => rand(10, 30),
                    'note' => 'Demo mode - Mock data'
                ]
            ];
            error_log("Demo mode enabled - using mock data");
        } else {
            // Real API mode with concurrent fan-out to internal endpoints
            $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://')
                     . $_SERVER['HTTP_HOST']
                     . $_SERVER['PHP_SELF'];

            $endpoints = [
              'steadfast' => $baseUrl . '?service=steadfast&phone=' . urlencode($phoneNumber),
              'pathao'    => $baseUrl . '?service=pathao&phone='    . urlencode($phoneNumber),
              'redx'      => $baseUrl . '?service=redx&phone='      . urlencode($phoneNumber),
            ];

            $mh = curl_multi_init();
            $chs = [];
            foreach ($endpoints as $key => $url) {
                $ch = curl_init();
                curl_setopt_array($ch, [
                    CURLOPT_URL => $url,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_CONNECTTIMEOUT => 5,
                    CURLOPT_TIMEOUT => 12,
                    CURLOPT_HTTPHEADER => ['Accept: application/json', 'Connection: keep-alive'],
                    CURLOPT_ENCODING => '',
                ]);
                $chs[$key] = $ch;
                curl_multi_add_handle($mh, $ch);
            }

            // Execute concurrently
            $running = null;
            do {
                $mrc = curl_multi_exec($mh, $running);
                if ($running) { curl_multi_select($mh, 1.0); }
            } while ($running && $mrc == CURLM_OK);

            // Gather results
            $results = [];
            $apiErrors = 0;
            foreach ($chs as $key => $ch) {
                $body = curl_multi_getcontent($ch);
                $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                if ($code >= 200 && $code < 300) {
                    $json = json_decode($body, true);
                    if (is_array($json)) {
                        $results[$key] = $json;
                    } else {
                        $results[$key] = ['error' => 'Invalid JSON'];
                        $apiErrors++;
                    }
                } else {
                    $results[$key] = ['error' => 'HTTP ' . $code . ' from ' . $key];
                    $apiErrors++;
                }
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
            }
            curl_multi_close($mh);

            // If all APIs failed, provide helpful message and suggest demo mode
            if ($apiErrors >= 3) {
                $results['note'] = 'All courier services are currently unavailable. Please check your internet connection and API credentials. You can temporarily switch to demo mode by setting $demoMode = true in the PHP file.';
                if (isset($results['steadfast']['error'])) { $results['steadfast']['suggestion'] = 'Try checking steadfast.com.bd manually to see if the site is working'; }
                if (isset($results['redx']['error'])) { $results['redx']['suggestion'] = 'RedX API may be temporarily down - try again later'; }
                if (isset($results['pathao']['error'])) { $results['pathao']['suggestion'] = 'Pathao API may be experiencing issues - try again later'; }
            }
        }
        
        // Log the results for debugging
        error_log("Fraud check results: " . json_encode($results));
        
        // Clean output buffer and send JSON
        ob_clean();
        echo json_encode($results, JSON_UNESCAPED_UNICODE);
        
    } catch (Exception $e) {
        error_log("Fraud check error: " . $e->getMessage());
        ob_clean();
        echo json_encode(['error' => $e->getMessage()]);
    }
    
    // End output buffering and exit
    ob_end_flush();
    exit;
}

// Add a simple test endpoint for debugging
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['test'])) {
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_start();
    header('Content-Type: application/json');
    header('Cache-Control: no-cache, must-revalidate');
    
    $response = [
        'status' => 'success',
        'message' => 'PHP is working correctly',
        'timestamp' => date('Y-m-d H:i:s'),
        'php_version' => PHP_VERSION
    ];
    
    ob_clean();
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    ob_end_flush();
    exit;
}

// Add a test endpoint for API credentials
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['test_credentials'])) {
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_start();
    header('Content-Type: application/json');
    header('Cache-Control: no-cache, must-revalidate');
    
    $testResults = [];
    
    // Test Pathao credentials
    try {
        $testResults['pathao'] = checkPathao('01712345678', $config['pathao']['user'], $config['pathao']['password']);
    } catch (Exception $e) {
        $testResults['pathao'] = ['error' => $e->getMessage()];
    }
    
    // Test RedX credentials
    try {
        $testResults['redx'] = checkRedx('01712345678', $config['redx']['phone'], $config['redx']['password']);
    } catch (Exception $e) {
        $testResults['redx'] = ['error' => $e->getMessage()];
    }
    
    // Test Steadfast credentials
    try {
        $testResults['steadfast'] = checkSteadfast('01712345678', $config['steadfast']['user'], $config['steadfast']['password']);
    } catch (Exception $e) {
        $testResults['steadfast'] = ['error' => $e->getMessage()];
    }
    
    ob_clean();
    echo json_encode($testResults);
    ob_end_flush();
    exit;
}

// Add a RedX-specific test endpoint
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['test_redx'])) {
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_start();
    header('Content-Type: application/json');
    
    // Test RedX connection step by step
    $testResults = [];
    
    // Test 1: Basic connectivity
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'timeout' => 10
        ]
    ]);
    
    $response = @file_get_contents('https://api.redx.com.bd', false, $context);
    if ($response === false) {
        $error = error_get_last();
        $testResults['connectivity'] = [
            'status' => 'failed',
            'error' => $error['message'] ?? 'Unknown error',
            'details' => 'Cannot reach RedX API domain'
        ];
    } else {
        $testResults['connectivity'] = [
            'status' => 'success',
            'response_length' => strlen($response),
            'details' => 'RedX API domain is reachable'
        ];
    }
    
    // Test 2: Login endpoint
    $loginData = [
        'phone' => '88' . $config['redx']['phone'],
        'password' => $config['redx']['password'],
    ];
    
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => [
                'Content-Type: application/json',
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept: application/json, text/plain, */*'
            ],
            'content' => json_encode($loginData),
            'timeout' => 15
        ]
    ]);
    
    $response = @file_get_contents('https://api.redx.com.bd/v4/auth/login', false, $context);
    if ($response === false) {
        $error = error_get_last();
        $testResults['login_endpoint'] = [
            'status' => 'failed',
            'error' => $error['message'] ?? 'Unknown error',
            'details' => 'Login endpoint not accessible'
        ];
    } else {
        $testResults['login_endpoint'] = [
            'status' => 'success',
            'response_length' => strlen($response),
            'response_preview' => substr($response, 0, 200),
            'details' => 'Login endpoint is accessible'
        ];
    }
    
    ob_clean();
    echo json_encode($testResults);
    ob_end_flush();
    exit;
}

// Add a Steadfast-specific test endpoint
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['test_steadfast'])) {
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_start();
    header('Content-Type: application/json');
    
    // Test Steadfast connection step by step
    $testResults = [];
    
    // Test 1: Basic connectivity to Steadfast
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'timeout' => 15
        ]
    ]);
    
    $response = @file_get_contents('https://steadfast.com.bd', false, $context);
    if ($response === false) {
        $error = error_get_last();
        $testResults['connectivity'] = [
            'status' => 'failed',
            'error' => $error['message'] ?? 'Unknown error',
            'details' => 'Cannot reach Steadfast website'
        ];
    } else {
        $testResults['connectivity'] = [
            'status' => 'success',
            'response_length' => strlen($response),
            'details' => 'Steadfast website is reachable'
        ];
    }
    
    // Test 2: Login page accessibility
    $response = @file_get_contents('https://steadfast.com.bd/login', false, $context);
    if ($response === false) {
        $error = error_get_last();
        $testResults['login_page'] = [
            'status' => 'failed',
            'error' => $error['message'] ?? 'Unknown error',
            'details' => 'Login page not accessible'
        ];
    } else {
        // Check if login page contains expected elements
        $hasLoginForm = strpos($response, 'login') !== false || strpos($response, 'email') !== false;
        $hasCSRFToken = strpos($response, '_token') !== false;
        
        $testResults['login_page'] = [
            'status' => 'success',
            'response_length' => strlen($response),
            'has_login_form' => $hasLoginForm,
            'has_csrf_token' => $hasCSRFToken,
            'details' => 'Login page is accessible'
        ];
    }
    
    // Test 3: Try to extract CSRF token
    if (isset($testResults['login_page']['status']) && $testResults['login_page']['status'] === 'success') {
        preg_match('/<input type="hidden" name="_token" value="(.*?)"/', $response, $matches);
        $token = $matches[1] ?? null;
        
        if ($token) {
            $testResults['csrf_token'] = [
                'status' => 'success',
                'token_length' => strlen($token),
                'token_preview' => substr($token, 0, 20) . '...',
                'details' => 'CSRF token found successfully'
            ];
        } else {
            $testResults['csrf_token'] = [
                'status' => 'failed',
                'details' => 'CSRF token not found - site structure may have changed'
            ];
        }
    }
    
    ob_clean();
    echo json_encode($testResults);
    ob_end_flush();
    exit;
}

// Add a detailed Steadfast login test endpoint
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['test_steadfast_login'])) {
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_start();
    header('Content-Type: application/json');
    
    // Test Steadfast login step by step
    $testResults = [];
    
    // Step 1: Get login page and CSRF token
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'timeout' => 15
        ]
    ]);
    
    $response = @file_get_contents('https://steadfast.com.bd/login', false, $context);
    if ($response === false) {
        $testResults['step1_get_page'] = [
            'status' => 'failed',
            'error' => 'Cannot access login page'
        ];
    } else {
        preg_match('/<input type="hidden" name="_token" value="(.*?)"/', $response, $matches);
        $token = $matches[1] ?? null;
        
        if ($token) {
            $testResults['step1_get_page'] = [
                'status' => 'success',
                'response_length' => strlen($response),
                'csrf_token' => substr($token, 0, 20) . '...',
                'details' => 'Login page loaded and CSRF token extracted'
            ];
            
            // Step 2: Attempt login
            $loginData = http_build_query([
                '_token' => $token,
                'email' => $config['steadfast']['user'],
                'password' => $config['steadfast']['password'],
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => [
                        'Content-Type: application/x-www-form-urlencoded',
                        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Referer: https://steadfast.com.bd/login',
                        'Origin: https://steadfast.com.bd'
                    ],
                    'content' => $loginData,
                    'timeout' => 15,
                    'follow_location' => true,
                    'max_redirects' => 3
                ]
            ]);
            
            $loginResponse = @file_get_contents('https://steadfast.com.bd/login', false, $context);
            if ($loginResponse === false) {
                $testResults['step2_login'] = [
                    'status' => 'failed',
                    'error' => 'Login request failed'
                ];
            } else {
                $testResults['step2_login'] = [
                    'status' => 'success',
                    'response_length' => strlen($loginResponse),
                    'response_preview' => substr($loginResponse, 0, 300),
                    'details' => 'Login request completed'
                ];
                
                // Step 3: Analyze login response
                $hasError = strpos($loginResponse, 'error') !== false || strpos($loginResponse, 'invalid') !== false;
                $hasSuccess = strpos($loginResponse, 'dashboard') !== false || strpos($loginResponse, 'logout') !== false;
                $stillOnLoginPage = strpos($loginResponse, 'login') !== false && strpos($loginResponse, 'email') !== false;
                
                $testResults['step3_analysis'] = [
                    'status' => 'success',
                    'has_error_message' => $hasError,
                    'incorrect' => strpos($loginResponse, 'incorrect') !== false,
                    'failed' => strpos($loginResponse, 'failed') !== false,
                    'wrong' => strpos($loginResponse, 'wrong') !== false,
                    'has_success_indicator' => $hasSuccess,
                    'still_on_login_page' => $stillOnLoginPage,
                    'response_contains_login' => strpos($loginResponse, 'login') !== false,
                    'response_contains_email' => strpos($loginResponse, 'email') !== false,
                    'response_contains_dashboard' => strpos($loginResponse, 'dashboard') !== false,
                    'details' => 'Login response analyzed'
                ];
            }
        } else {
            $testResults['step1_get_page'] = [
                'status' => 'failed',
                'error' => 'CSRF token not found'
            ];
        }
    }
    
    ob_clean();
    echo json_encode($testResults);
    ob_end_flush();
    exit;
}

// Add a direct Steadfast phone test endpoint to inspect raw JSON for a number
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['test_steadfast_phone'])) {
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_start();
    header('Content-Type: application/json');
    header('Cache-Control: no-cache, must-revalidate');

    $phone = isset($_GET['phone']) ? preg_replace('/[^0-9]/', '', $_GET['phone']) : '';
    if (!$phone || !preg_match('/^01[3-9][0-9]{8}$/', $phone)) {
        ob_clean();
        echo json_encode(['error' => 'Invalid or missing phone parameter']);
        ob_end_flush();
        exit;
    }

    // Try fetching directly (public) first
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'https://steadfast.com.bd/user/frauds/check/' . rawurlencode($phone),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => [
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36',
            'Accept: application/json, text/plain, */*',
        ],
    ]);
    $resp = curl_exec($ch);
    $err = $resp === false ? curl_error($ch) : '';
    curl_close($ch);

    if ($resp === false) {
        ob_clean();
        echo json_encode(['error' => 'Request failed', 'details' => $err]);
        ob_end_flush();
        exit;
    }

    // If it looks like HTML, report it
    if (stripos($resp, '<html') !== false || stripos($resp, '<!DOCTYPE') !== false) {
        ob_clean();
        echo json_encode(['error' => 'HTML received', 'preview' => substr($resp, 0, 300)]);
        ob_end_flush();
        exit;
    }

    // Return the raw JSON from Steadfast so we can see frauds
    $decoded = json_decode($resp, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        ob_clean();
        echo json_encode(['status' => 'ok', 'data' => $decoded], JSON_UNESCAPED_UNICODE);
    } else {
        ob_clean();
        echo json_encode(['error' => 'Invalid JSON', 'preview' => substr($resp, 0, 300)]);
    }
    ob_end_flush();
    exit;
}

// Add a debug endpoint to see raw output
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['debug'])) {
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_start();
    
    // Test a simple API call to see what happens
    try {
        $testResult = checkPathao('01712345678', $config['pathao']['user'], $config['pathao']['password']);
        $output = json_encode($testResult);
    } catch (Exception $e) {
        $output = json_encode(['error' => $e->getMessage()]);
    }
    
    // Show both the raw output and the JSON
    echo "Raw output:\n";
    echo "Length: " . strlen($output) . "\n";
    echo "Content: " . $output . "\n";
    echo "\nJSON decode test:\n";
    $decoded = json_decode($output, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        echo "JSON is valid\n";
        print_r($decoded);
    } else {
        echo "JSON error: " . json_last_error_msg() . "\n";
    }
    
    ob_end_flush();
    exit;
}

// Add a minimal test endpoint
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['minimal'])) {
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_start();
    header('Content-Type: application/json');
    
    // Just return a simple response
    $response = ['test' => 'working', 'time' => time()];
    
    ob_clean();
    echo json_encode($response);
    ob_end_flush();
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Courier Fraud Checker BD</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f6f7fb;
            color: #1f2937;
            line-height: 1.6;
            min-height: 100vh;
            padding: 16px;
        }
        
        .container {
            max-width: 100%;
            margin: 0;
            background: #ffffff;
            border-radius: 0;
            box-shadow: none;
            overflow: hidden;
        }
        @media (min-width: 992px) {
            body { padding: 16px; }
            .container {
                max-width: 1100px;
                margin: 0 auto;
                border-radius: 16px;
                box-shadow: 0 8px 24px rgba(0,0,0,0.06);
            }
        }
        
        @media (max-width: 768px) {
            body { padding: 0; }
            .container {
                max-width: 100%;
                margin: 0;
                border-radius: 0;
                box-shadow: none;
            }
        }
        
        .header {
            background: #ffffff;
            border-bottom: 1px solid #e5e7eb;
            color: #111827;
            padding: 18px 24px;
            text-align: left;
        }
        
        .header h1 { font-size: 18px; margin-bottom: 2px; font-weight: 700; }
        .header p { font-size: 12px; color: #6b7280; }
        
        .search-section {
            padding: 18px 24px 8px;
            text-align: center;
        }
        
        .search-form {
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 32px 0;
            text-align: center;
        }
        
        .phone-input {
            padding: 10px 12px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            font-size: 14px;
            width: 240px;
            transition: all 0.2s ease;
            background: #fff;
        }
        
        .phone-input:focus {
            outline: none;
            border-color: #93c5fd;
            box-shadow: 0 0 0 3px rgba(147, 197, 253, 0.25);
        }
        
        .search-btn {
            background: #2563eb;
            color: white;
            border: none;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 14px;
            cursor: pointer;
            transition: background 0.2s ease;
            font-weight: 600;
        }
        
        .search-btn:hover { background: #1d4ed8; }
        
        .search-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .results-section { padding: 8px 24px 24px; display: none; }
        
        .results-grid { display: block; margin-top: 16px; }
        .results-table { width: 100%; border-collapse: separate; border-spacing: 0; background: #fff; border: 1px solid #e5e7eb; border-radius: 16px; overflow: hidden; table-layout: fixed; }
        .results-table th, .results-table td { padding: 14px 12px; border-bottom: 1px solid #eef2f7; text-align: left; font-size: 16px; }
        .results-table th { background: #f9fafb; color: #111827; font-weight: 700; position: sticky; top: 0; z-index: 1; }
        .results-table tbody tr:nth-child(odd) { background: #fdfefe; }
        .results-table thead th:first-child, .results-table tbody td:first-child, .results-table tfoot td:first-child { width: 40%; }
        .results-table tfoot td { background: #f3f4f6; font-weight: 800; color: #111827; }
        .logo-cell { width: 56px; }
        .logo { width: 36px; height: 36px; object-fit: contain; border-radius: 8px; background: #fff; border: 1px solid #e5e7eb; }
        .num { font-weight: 800; color: #111827; }
        .status-ok { color: #155724; }
        .status-err { color: #b91c1c; }
        .status-cell { word-break: break-word; }
        .note { display: block; margin-top: 2px; font-size: 12px; color: #6b7280; }
        .table-scroll { overflow-x: hidden; }
        @media (max-width: 480px) {
            .results-table th, .results-table td { padding: 8px 8px; font-size: 13px; }
            .logo { width: 24px; height: 24px; }
            .logo-cell { width: 38px; }
        }
        /* UI enhancements */
        .badge { display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 0.8em; font-weight: 600; background: #e9ecef; color: #495057; }
        .badge-green { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .badge-red { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .badge-blue { background: #dbeafe; color: #1e40af; border: 1px solid #bfdbfe; }
        .fraud-notes { margin-top: 16px; text-align: left; }
        .fraud-notes-header { display: flex; align-items: center; justify-content: space-between; cursor: pointer; padding: 10px 12px; border: 1px solid #dc2626; border-radius: 8px; background: #fef2f2; color: #dc2626; }
        .fraud-notes-title { font-weight: 600; color: #dc2626; }
        .fraud-notes-body { display: none; padding: 12px; border: 1px solid #e9ecef; border-top: 0; border-radius: 0 0 8px 8px; background: #fff; max-height: 400px; overflow-y: auto; }
        .fraud-item { border: 1px solid #e9ecef; border-radius: 8px; padding: 12px; background: #fff; }
        .fraud-item + .fraud-item { margin-top: 10px; }
        .fraud-meta { font-size: 0.9em; color: #6c757d; margin-bottom: 6px; }
        .fraud-details { white-space: pre-wrap; line-height: 1.55; color: #212529; }
        .fraud-actions { margin-top: 8px; display: flex; gap: 8px; }
        .btn-secondary { background: #f1f5f9; color: #0f172a; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 6px; cursor: pointer; }
        .btn-secondary:hover { background: #e2e8f0; }
        .chevron { transition: transform 0.2s ease; stroke: #dc2626; }
        /* Neutral style when no Steadfast fraud notes exist */
        .fraud-notes-header.neutral { border-color: #e5e7eb; background: #f9fafb; color: #111827; }
        .fraud-notes-header.neutral .fraud-notes-title { color: #111827; }
        /* Big action button section */
        .big-action { padding: 12px 24px 0; text-align: center; }
        .big-action-btn { display: inline-block; width: 100%; max-width: 560px; padding: 16px 20px; font-size: 16px; font-weight: 700; border-radius: 10px; border: 1px solid #cbd5e1; background: #f1f5f9; color: #0f172a; cursor: pointer; transition: background 0.15s ease, transform 0.05s ease; }
        .big-action-btn:hover { background: #e2e8f0; }
        .big-action-btn:active { transform: translateY(1px); }
        .big-action-btn .icon { margin-right: 8px; }
        
        /* remove card styles not used by table layout */
        
        .error-card {
            background: #fff5f5;
            border: 1px solid #fed7d7;
            color: #c53030;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-top: 20px;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .phone-format {
            background: #e3f2fd;
            border: 1px solid #bbdefb;
            color: #1976d2;
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            font-size: 0.9em;
        }
        
        .phone-format strong {
            color: #1565c0;
        }
        
        .fraud-risk {
            margin-top: 20px;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            font-weight: 600;
            font-size: 1.1em;
        }
        
        .risk-low {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .risk-medium {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        
        .risk-high {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .summary-stats { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 12px; padding: 16px; margin-top: 12px; }
        .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
        .summary-item { background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px; text-align: center; }
        .summary-value { font-size: 1.8em; font-weight: 800; color: #1e40af; margin-bottom: 4px; }
        .summary-label { font-size: 0.85em; color: #6b7280; letter-spacing: 0.3px; text-transform: uppercase; }
        @media (max-width: 768px) {
            .summary-stats { padding: 8px; }
            .summary-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px; }
            .summary-item { padding: 6px; border-radius: 8px; }
            .summary-value { font-size: 1.05em; margin-bottom: 2px; }
            .summary-label { font-size: 0.65em; }
        }
        @media (max-width: 360px) {
            .summary-grid { gap: 4px; }
            .summary-item { padding: 5px; }
            .summary-value { font-size: 0.95em; }
            .summary-label { font-size: 0.6em; }
        }
        
        /* removed config section styles for final product */
        
        @media (max-width: 768px) {
            .search-form {
                flex-direction: column;
                margin: 8px 0 6px 0;
            }
            
            .phone-input {
                width: 100%;
                max-width: 300px;
            }
            
            .results-grid {
                grid-template-columns: 1fr;
                margin-top: 6px;
            }
            
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (min-width: 769px) {
            .search-form {
                margin: 80px 0 32px 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚚 Courier Fraud Checker BD</h1>
            <p>Detect potential fraudulent orders by checking customer delivery behavior</p>
        </div>
        
        <!-- Configuration Section -->
        <!-- configuration section removed for final product -->
        
        <div class="search-section">
            <div class="big-action">
                <button type="button" id="pasteSearchBtn" class="big-action-btn" title="Paste from clipboard and search">
                    <span class="icon">📋</span>Paste & Search
                </button>
            </div>
            <form id="fraudCheckForm" class="search-form">
                <div class="input-group" style="max-width:560px; width:100%;">
                    <span class="input-group-text">📱</span>
                    <input type="text" inputmode="numeric" id="phoneNumber" name="phoneNumber" class="form-control" placeholder="Enter phone number" autocomplete="tel" required>
                    <button type="submit" class="btn btn-primary" id="searchBtn">Check</button>
                </div>
            </form>
        </div>
        
        <div id="resultsSection" class="results-section">
            <div id="loading" class="loading">
                <div class="spinner"></div>
                <p>Checking delivery history across courier services...</p>
            </div>
            
            <div id="resultsGrid" class="results-grid" style="display: none;">
                <div id="summarySection" class="summary-stats" style="display: none;">
                    <div class="summary-grid">
                        <div class="summary-item">
                            <div class="summary-value" id="cardTotalDeliveries">0</div>
                            <div class="summary-label">Total Parcels</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-value" id="cardTotalSuccess">0</div>
                            <div class="summary-label">Total Success</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-value" id="cardSuccessRate">0%</div>
                            <div class="summary-label">Success Rate</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-value" id="cardSteadfastReports">0</div>
                            <div class="summary-label">Steadfast Reports</div>
                        </div>
                    </div>
                </div>
                <div class="table-scroll">
                    <table class="results-table table table-sm table-striped align-middle" id="resultsTable">
                        <thead>
                            <tr>
                                <th>Courier</th>
                                <th>Success</th>
                                <th>Cancelled</th>
                                <th>Total</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                        <tfoot>
                            <tr>
                                <td>Total</td>
                                <td class="num" id="sumSuccess">0</td>
                                <td class="num" id="sumCancel">0</td>
                                <td class="num" id="sumTotal">0</td>
                                <td class="num" id="sumRate"></td>
                            </tr>
                        </tfoot>
                    </table>
                </div>
                <div id="steadfastNotes" style="margin-top:16px"></div>
            </div>
            
            
            <div id="riskAssessment" style="display: none;"></div>
        </div>
    </div>

    <script>
        // Client-side normalization mirroring backend: returns local 11-digit format
        function normalizePhoneClient(raw) {
            const digits = String(raw || '').replace(/\D+/g, '');
            if (!digits) return '';
            if (digits.startsWith('880')) {
                const last10 = digits.slice(-10);
                return '0' + last10;
            }
            if (digits.length === 10) {
                return '0' + digits;
            }
            return digits;
        }
        document.getElementById('fraudCheckForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const rawInput = document.getElementById('phoneNumber').value.trim();
            const phoneNumber = normalizePhoneClient(rawInput);
            const searchBtn = document.getElementById('searchBtn');
            const resultsSection = document.getElementById('resultsSection');
            const loading = document.getElementById('loading');
            const resultsGrid = document.getElementById('resultsGrid');
            const summarySection = document.getElementById('summarySection');
            const riskAssessment = document.getElementById('riskAssessment');
            
            // Validate phone number (after normalization)
            if (!/^01[3-9][0-9]{8}$/.test(phoneNumber)) {
                alert('Please enter a valid Bangladeshi phone number (e.g., 01712345678)');
                return;
            }
            
            // Show loading state
            searchBtn.disabled = true;
            searchBtn.textContent = '⏳ Checking...';
            resultsSection.style.display = 'block';
            loading.style.display = 'block';
            resultsGrid.style.display = 'none';
            summarySection.style.display = 'none';
            riskAssessment.style.display = 'none';
            
            // Make AJAX request
            fetch('index.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'phoneNumber=' + encodeURIComponent(phoneNumber)
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    displayError(data.error);
                } else {
                    displayResults(data);
                    calculateSummary(data);
                    assessRisk(data);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                let errorMessage = 'An error occurred while checking the phone number. ';
                if (error.message) {
                    errorMessage += 'Error: ' + error.message;
                }
                displayError(errorMessage);
            })
            .finally(() => {
                // Reset button state
                searchBtn.disabled = false;
                searchBtn.textContent = 'Check';
            });
        });
        
        function displayResults(data) {
            const loading = document.getElementById('loading');
            const resultsGrid = document.getElementById('resultsGrid');
            
            loading.style.display = 'none';
            resultsGrid.style.display = 'grid';
            
            const table = document.getElementById('resultsTable');
            const tbody = table ? table.querySelector('tbody') : null;
            if (tbody) tbody.innerHTML = '';
            let steadfastFrauds = [];
            let sumSuccess = 0, sumCancel = 0, sumTotal = 0;
            
            // Display results for each courier service
            Object.keys(data).forEach(courier => {
                const result = data[courier];
                const tr = document.createElement('tr');
                const name = courier.charAt(0).toUpperCase() + courier.slice(1);
                let statusHtml = '';
                if (result.error) {
                    statusHtml = `<span class="status-err">${result.error}</span>`;
                } else {
                    statusHtml = `<span class="status-ok">OK</span>${result.note ? ` <span class="note">${result.note}</span>` : ''}`;
                }
                const logo = courier === 'pathao' ? 'pathao.jpg' : courier === 'steadfast' ? 'steadfast.jpg' : 'redx.jpg';
                const s = parseInt(result.success || 0), c = parseInt(result.cancel || 0), t = parseInt(result.total || 0);
                tr.innerHTML = `
                    <td class="logo-cell"><img class="logo" src="icons/${logo}" alt="${name}"></td>
                    <td class="num">${s}</td>
                    <td class="num">${c}</td>
                    <td class="num">${t}</td>
                    <td class="status-cell">${statusHtml}</td>
                `;
                if (tbody) tbody.appendChild(tr);
                if (!result.error) { sumSuccess += s; sumCancel += c; sumTotal += t; }
                if (courier === 'steadfast' && Array.isArray(result.frauds)) {
                    steadfastFrauds = result.frauds;
                }
            });

            // Update totals row
            const sumS = document.getElementById('sumSuccess');
            const sumC = document.getElementById('sumCancel');
            const sumT = document.getElementById('sumTotal');
            const sumR = document.getElementById('sumRate');
            if (sumS) sumS.textContent = sumSuccess;
            if (sumC) sumC.textContent = sumCancel;
            if (sumT) sumT.textContent = sumTotal;
            if (sumR) {
                const rateVal = sumTotal > 0 ? ((sumSuccess / sumTotal) * 100).toFixed(1) + '%' : '0%';
                sumR.innerHTML = `<span class="badge badge-blue">${rateVal}</span>`;
            }

            // Render Steadfast fraud notes shell; lazy-load content on expand
            const notesDiv = document.getElementById('steadfastNotes');
            if (notesDiv) {
                const hasFraud = Array.isArray(steadfastFrauds) && steadfastFrauds.length > 0;
                const headerClass = hasFraud ? 'fraud-notes-header' : 'fraud-notes-header neutral';
                notesDiv.innerHTML = `
                    <div class="fraud-notes" id="fraud-notes-steadfast">
                        <div class="${headerClass}" onclick="toggleFraudNotes('steadfast')">
                            <div class="fraud-notes-title">Steadfast: Reported Fraud Notes</div>
                            <svg class="chevron" id="chev-steadfast" width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6 9l6 6 6-6" stroke="#495057" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        </div>
                        <div class="fraud-notes-body" id="fraud-body-steadfast"></div>
                    </div>
                `;
            }

            // Fraud notes are now closed by default - user must click to expand
        }

        

        function toggleFraudNotes(key, forceOpen = false) {
            const body = document.getElementById(`fraud-body-${key}`);
            const chev = document.getElementById(`chev-${key}`);
            if (!body) return;
            const willOpen = forceOpen ? true : (body.style.display === 'none' || body.style.display === '');
            body.style.display = willOpen ? 'block' : 'none';
            if (chev) { chev.style.transform = willOpen ? 'rotate(180deg)' : 'rotate(0deg)'; }
            if (willOpen && key === 'steadfast' && !body.dataset.loaded) {
                const phone = document.getElementById('phoneNumber').value.trim();
                // Ensure we always fetch with normalized local format
                const normPhone = normalizePhoneClient(phone);
                fetch(`index.php?service=steadfast&phone=${encodeURIComponent(normPhone)}`)
                    .then(r => r.json())
                    .then(res => {
                        const arr = Array.isArray(res.frauds) ? res.frauds : [];
                        if (!arr.length) { body.innerHTML = '<div class="fraud-item">No fraud notes found.</div>'; }
                        else {
                            body.innerHTML = arr.map(f => `
                                <div class="fraud-item">
                                    <div class="fraud-meta">${(f.name||'Unknown')} ${f.phone ? '('+f.phone+')' : ''} ${f.created_at ? '• '+f.created_at : ''}</div>
                                    <div class="fraud-details">${(f.details||'')}</div>
                                    <div class="fraud-actions">
                                        <button class="btn-secondary" onclick="copyFraudText('steadfast', ${f.id || 0})">Copy note</button>
                                    </div>
                                    <textarea id="fraud-text-steadfast-${f.id || 0}" style="position:absolute; left:-9999px; top:-9999px">${(f.details||'')}</textarea>
                                </div>
                            `).join('');
                        }
                        body.dataset.loaded = '1';
                    })
                    .catch(() => {
                        body.innerHTML = '<div class="fraud-item">Failed to load fraud notes.</div>';
                    });
            }
        }

        function copyFraudText(key, id) {
            const ta = document.getElementById(`fraud-text-${key}-${id}`);
            if (!ta) return;
            ta.select();
            ta.setSelectionRange(0, 99999);
            try { document.execCommand('copy'); } catch (e) {}
        }
        
        function calculateSummary(data) {
            let totalSuccess = 0;
            let totalCancel = 0;
            let totalDeliveries = 0;
            let steadfastReports = 0;
            Object.values(data).forEach(result => {
                if (!result.error) {
                    totalSuccess += parseInt(result.success) || 0;
                    totalCancel += parseInt(result.cancel) || 0;
                    totalDeliveries += parseInt(result.total) || 0;
                }
                if (result && Array.isArray(result.frauds)) {
                    steadfastReports = result.frauds.length; // only one service will have this
                }
            });
            const cards = {
                total: document.getElementById('cardTotalDeliveries'),
                success: document.getElementById('cardTotalSuccess'),
                rate: document.getElementById('cardSuccessRate'),
                sf: document.getElementById('cardSteadfastReports'),
            };
            if (cards.total) cards.total.textContent = totalDeliveries;
            if (cards.success) cards.success.textContent = totalSuccess;
            if (cards.rate) {
                const rate = totalDeliveries > 0 ? ((totalSuccess / totalDeliveries) * 100).toFixed(1) + '%' : '0%';
                cards.rate.textContent = rate;
            }
            if (cards.sf) cards.sf.textContent = steadfastReports;
            const summarySection = document.getElementById('summarySection');
            if (summarySection) summarySection.style.display = 'block';
        }
        
        function assessRisk(data) {
            const riskAssessment = document.getElementById('riskAssessment');
            let totalSuccess = 0;
            let totalCancel = 0;
            let totalDeliveries = 0;
            
            Object.values(data).forEach(result => {
                if (!result.error) {
                    totalSuccess += parseInt(result.success) || 0;
                    totalCancel += parseInt(result.cancel) || 0;
                    totalDeliveries += parseInt(result.total) || 0;
                }
            });
            
            let riskLevel = 'low';
            let riskMessage = '';
            let riskClass = 'risk-low';
            
            if (totalDeliveries === 0) {
                riskLevel = 'low';
                riskMessage = '✅ No delivery history found - Low risk customer';
            } else {
                const successRate = totalDeliveries > 0 ? (totalSuccess / totalDeliveries) * 100 : 0;
                const cancelRate = totalDeliveries > 0 ? (totalCancel / totalDeliveries) * 100 : 0;
                
                if (successRate >= 80 && cancelRate <= 10) {
                    riskLevel = 'low';
                    riskMessage = '✅ Excellent delivery record - Low risk customer';
                    riskClass = 'risk-low';
                } else if (successRate >= 60 && cancelRate <= 25) {
                    riskLevel = 'medium';
                    riskMessage = '⚠️ Moderate delivery record - Medium risk customer';
                    riskClass = 'risk-medium';
                } else {
                    riskLevel = 'high';
                    riskMessage = '🚨 Poor delivery record - High risk customer';
                    riskClass = 'risk-high';
                }
            }
            
            riskAssessment.innerHTML = `
                <div class="fraud-risk ${riskClass}">
                    <strong>Risk Assessment:</strong> ${riskMessage}
                </div>
            `;
            
            riskAssessment.style.display = 'block';
        }
        
        function displayError(message) {
            const loading = document.getElementById('loading');
            const resultsGrid = document.getElementById('resultsGrid');
            const summarySection = document.getElementById('summarySection');
            const riskAssessment = document.getElementById('riskAssessment');
            
            loading.style.display = 'none';
            resultsGrid.style.display = 'block';
            summarySection.style.display = 'none';
            riskAssessment.style.display = 'none';
            
            resultsGrid.innerHTML = `
                <div class="error-card" style="grid-column: 1 / -1;">
                    ${message}
                </div>
            `;
        }
        
        // Phone number input formatting (allow paste of +880/880/10-digit; keep digits plus leading +)
        document.getElementById('phoneNumber').addEventListener('input', function(e) {
            const old = e.target.value;
            // keep leading + if present, then digits
            let cleaned = old.replace(/[^+0-9]/g, '');
            cleaned = cleaned.replace(/(?!^)[+]/g, '');
            e.target.value = cleaned;
        });

        // Paste & Search button: paste from clipboard, normalize, set input, and submit
        document.getElementById('pasteSearchBtn').addEventListener('click', async function() {
            const input = document.getElementById('phoneNumber');
            try {
                const text = await navigator.clipboard.readText();
                const normalized = normalizePhoneClient(text);
                input.value = normalized || text.replace(/\D/g, '');
                // Ensure no input is focused to avoid mobile keyboard
                if (document.activeElement) { try { document.activeElement.blur(); } catch (_) {} }
                input.blur();
                // Trigger submit programmatically
                document.getElementById('fraudCheckForm').dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
            } catch (e) {
                if (document.activeElement) { try { document.activeElement.blur(); } catch (_) {} }
                input.blur();
            }
        });
    </script>
</body>
</html>
