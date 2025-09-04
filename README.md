# Courier Fraud Checker BD

A lightweight PHP app to check a Bangladeshi customer's delivery history across Pathao, RedX, and Steadfast to help spot potentially fraudulent orders.

## Features
- Unified results table with totals and overall success rate
- Steadfast "Reported Fraud Notes" (lazy-loaded)
- One-click Paste & Search (clipboard → normalized → search; no mobile keyboard popup)
- Accepts +880/880/10-digit/local formats; normalizes to 11-digit local
- Summary cards: Total Parcels, Total Success, Success Rate, Steadfast Reports
- Responsive UI (mobile-first) and desktop container
- Built-in diagnostic endpoints

## Requirements
- PHP 7.4+ with cURL enabled
- Any web server (XAMPP/LAMPP/WAMP, nginx+php-fpm, etc.)

## Quick Start (XAMPP on Windows)
1. Copy this project folder (e.g., `courier-fraud-checker-bd/`) into `D:/xampp/htdocs/`.
2. Open `index.php` and update the `$config` section with your Pathao, RedX, and Steadfast credentials.
3. Start Apache in XAMPP.
4. Visit `http://localhost/courier-fraud-checker-bd/index.php`.

## Configuration (Credentials)
Currently, credentials are configured directly in `index.php`:

```php
$config = [
    'pathao' => [ 'user' => 'you@example.com', 'password' => 'your-password' ],
    'redx' => [ 'phone' => '01XXXXXXXXX', 'password' => 'your-password' ],
    'steadfast' => [ 'user' => 'you@example.com', 'password' => 'your-password' ],
];
```

- Do not commit real credentials. If you plan to deploy, keep secrets out of version control and rotate them regularly.
- Demo/testing: toggle `$demoMode = true;` in `index.php` to use mock data without calling external services.

## Usage
- Paste & Search: click the big button; it pastes, normalizes, and searches.
- Manual: type a phone and click Check.
- Steadfast notes: click the header to load/expand.

## Phone Normalization
- +880/880 → last 10 digits + leading 0
- 10-digit local → add leading 0
- Final format: `01[3-9][0-9]{8}`

## Internal Endpoints
- `GET index.php?service=steadfast&phone=01XXXXXXXXX`
- `GET index.php?service=pathao&phone=01XXXXXXXXX`
- `GET index.php?service=redx&phone=01XXXXXXXXX`
- Diagnostics: `?test`, `?minimal`, `?test_credentials`, `?test_redx`, `?test_steadfast`, `?test_steadfast_login`, `?test_steadfast_phone&phone=01XXXXXXXXX`

## Caching & Rate Limits
- Lightweight temp-file cache to reduce API hits.
- Token caching and basic throttling for RedX.

## Security
- Avoid storing secrets in source control. Consider using server-level configuration or a secrets manager for production.
- Use HTTPS in production.

## Troubleshooting
- If all services fail, check internet and credentials; use the diagnostic endpoints above.
- Update CA certificates if cURL SSL errors occur.

## Structure
- `index.php` — application (backend + UI)
- `icons/` — courier icons

## License
MIT

## Disclaimer
3rd-party APIs/sites can change at any time; always verify important decisions in official portals.
