# Courier Fraud Checker BD

A comprehensive PHP application designed to help e-commerce businesses in Bangladesh identify potentially fraudulent customers by analyzing their delivery history across multiple courier services. The tool provides a unified interface to check customer behavior patterns across **Pathao**, **RedX**, and **Steadfast** courier services.

## 📑 Table of Contents

- [🚀 Features](#-features)
- [📋 Requirements](#-requirements)
- [🚀 Installation](#-installation)
- [⚙️ Configuration](#️-configuration)
- [📱 Usage Guide](#-usage-guide)
- [🔌 API Documentation](#-api-documentation)
- [🔧 Troubleshooting](#-troubleshooting)
- [🔒 Security Considerations](#-security-considerations)
- [📁 Project Structure](#-project-structure)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [⚠️ Disclaimer](#️-disclaimer)

## 🚀 Features

### Core Functionality
- **Multi-Service Integration**: Simultaneously checks delivery history across Pathao, RedX, and Steadfast
- **Unified Results Dashboard**: Consolidated view with totals and overall success rate calculation
- **Fraud Detection**: Identifies customers with poor delivery records and high cancellation rates
- **Risk Assessment**: Automated risk scoring based on delivery success patterns

### User Experience
- **One-Click Paste & Search**: Clipboard integration for quick phone number input
- **Smart Phone Normalization**: Accepts multiple formats (+880, 880, 10-digit, local) and normalizes to 11-digit local format
- **Responsive Design**: Mobile-first UI that works seamlessly on all devices
- **Real-time Results**: Concurrent API calls for faster response times

### Advanced Features
- **Steadfast Fraud Notes**: Lazy-loaded detailed fraud reports with expandable sections
- **Summary Statistics**: Key metrics including Total Parcels, Success Rate, and Fraud Reports
- **Caching System**: Intelligent caching to reduce API calls and improve performance
- **Rate Limiting**: Built-in throttling to respect API limits
- **Demo Mode**: Testing capability with mock data

### Developer Tools
- **Diagnostic Endpoints**: Built-in testing and debugging endpoints
- **Error Handling**: Comprehensive error reporting and fallback mechanisms
- **API Documentation**: Well-documented internal endpoints for integration

## 📋 Requirements

### System Requirements
- **PHP**: Version 7.4 or higher
- **Extensions**: cURL extension enabled
- **Web Server**: Apache, Nginx, or any PHP-compatible web server
- **Memory**: Minimum 128MB PHP memory limit
- **Storage**: At least 50MB free space for cache files

### Supported Platforms
- **Windows**: XAMPP, WAMP, or IIS with PHP
- **Linux**: Apache/Nginx with PHP-FPM
- **macOS**: MAMP, XAMPP, or native Apache/PHP
- **Cloud**: AWS, DigitalOcean, Vultr, etc.

## 🚀 Installation

### Option 1: XAMPP (Recommended for Windows)

1. **Download and Install XAMPP**
   ```bash
   # Download from https://www.apachefriends.org/
   # Install with Apache and PHP components
   ```

2. **Clone/Download the Project**
   ```bash
   # Option A: Clone with Git
   git clone https://github.com/yourusername/courier-fraud-checker-bd.git
   
   # Option B: Download ZIP and extract
   # Extract to: C:\xampp\htdocs\courier-fraud-checker-bd\
   ```

3. **Configure Credentials**
   ```php
   // Edit index.php and update the $config array
   $config = [
       'pathao' => [
           'user' => 'your-email@example.com',
           'password' => 'your-password'
       ],
       'redx' => [
           'phone' => '01XXXXXXXXX',
           'password' => 'your-password'
       ],
       'steadfast' => [
           'user' => 'your-email@example.com',
           'password' => 'your-password'
       ]
   ];
   ```

4. **Start Services**
   ```bash
   # Start Apache in XAMPP Control Panel
   # Ensure Apache is running on port 80
   ```

5. **Access the Application**
   ```
   http://localhost/courier-fraud-checker-bd/
   ```

### Option 2: Linux/Apache

1. **Install Dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install apache2 php php-curl
   
   # CentOS/RHEL
   sudo yum install httpd php php-curl
   ```

2. **Deploy Application**
   ```bash
   # Clone to web directory
   sudo git clone https://github.com/yourusername/courier-fraud-checker-bd.git /var/www/html/courier-fraud-checker-bd
   
   # Set permissions
   sudo chown -R www-data:www-data /var/www/html/courier-fraud-checker-bd
   sudo chmod -R 755 /var/www/html/courier-fraud-checker-bd
   ```

3. **Configure and Access**
   ```bash
   # Edit credentials in index.php
   sudo nano /var/www/html/courier-fraud-checker-bd/index.php
   
   # Access via browser
   http://your-server-ip/courier-fraud-checker-bd/
   ```

### Option 3: Docker (Advanced)

1. **Create Dockerfile**
   ```dockerfile
   FROM php:7.4-apache
   RUN docker-php-ext-install curl
   COPY . /var/www/html/
   EXPOSE 80
   ```

2. **Build and Run**
   ```bash
   docker build -t courier-fraud-checker .
   docker run -p 8080:80 courier-fraud-checker
   ```

### Option 4: Cloud Deployment

#### DigitalOcean Droplet
```bash
# Create Ubuntu droplet
# Install LAMP stack
sudo apt update && sudo apt install apache2 mysql-server php php-curl

# Deploy application
git clone https://github.com/yourusername/courier-fraud-checker-bd.git /var/www/html/
```

#### AWS EC2
```bash
# Launch EC2 instance with Amazon Linux 2
# Install dependencies
sudo yum update -y
sudo yum install -y httpd php php-curl

# Deploy and configure
sudo git clone https://github.com/yourusername/courier-fraud-checker-bd.git /var/www/html/
```

## ⚙️ Configuration

### Credential Setup
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

## 📱 Usage Guide

### Quick Start
1. **Paste & Search**: Click the "📋 Paste & Search" button to automatically paste from clipboard and search
2. **Manual Entry**: Type a phone number in the input field and click "Check"
3. **View Results**: Review the unified dashboard showing delivery history across all services

### Phone Number Formats
The application accepts multiple phone number formats and automatically normalizes them:

| Input Format | Example | Normalized Output |
|--------------|---------|-------------------|
| International | +8801712345678 | 01712345678 |
| Country Code | 8801712345678 | 01712345678 |
| 10-digit Local | 1712345678 | 01712345678 |
| 11-digit Local | 01712345678 | 01712345678 |

### Understanding Results

#### Summary Cards
- **Total Parcels**: Combined delivery count across all services
- **Total Success**: Number of successful deliveries
- **Success Rate**: Percentage of successful deliveries
- **Steadfast Reports**: Number of fraud reports (if any)

#### Service Results Table
Each courier service shows:
- **Success**: Number of successful deliveries
- **Cancelled**: Number of cancelled/failed deliveries
- **Total**: Total delivery attempts
- **Status**: Service availability and any notes

#### Risk Assessment
The system automatically calculates risk levels:
- **🟢 Low Risk**: 80%+ success rate, ≤10% cancellation rate
- **🟡 Medium Risk**: 60-79% success rate, ≤25% cancellation rate
- **🔴 High Risk**: <60% success rate or >25% cancellation rate

### Advanced Features

#### Steadfast Fraud Notes
- Click on "Steadfast: Reported Fraud Notes" to expand
- View detailed fraud reports with timestamps
- Copy individual fraud notes for reference
- Reports are lazy-loaded to improve performance

#### Demo Mode
For testing without real API calls:
```php
// Set in index.php
$demoMode = true;
```
This generates mock data for all services.

### Best Practices

#### For E-commerce Businesses
1. **Check New Customers**: Verify delivery history before processing large orders
2. **Monitor Patterns**: Look for customers with consistently poor delivery records
3. **Use as Supplement**: Combine with other fraud detection methods
4. **Regular Updates**: Keep the application updated for latest API changes

#### For Developers
1. **Test Credentials**: Use diagnostic endpoints to verify API access
2. **Monitor Performance**: Check response times and error rates
3. **Handle Errors**: Implement proper error handling in integrations
4. **Respect Limits**: Be mindful of API rate limits

## Phone Normalization
- +880/880 → last 10 digits + leading 0
- 10-digit local → add leading 0
- Final format: `01[3-9][0-9]{8}`

## 🔌 API Documentation

### Core Endpoints

#### Main Search Endpoint
```http
POST /index.php
Content-Type: application/x-www-form-urlencoded

phoneNumber=01712345678
```

**Response:**
```json
{
  "pathao": {
    "success": 15,
    "cancel": 2,
    "total": 17
  },
  "redx": {
    "success": 8,
    "cancel": 1,
    "total": 9
  },
  "steadfast": {
    "success": 12,
    "cancel": 3,
    "total": 15,
    "frauds": [
      {
        "id": 123,
        "phone": "01712345678",
        "name": "Customer Name",
        "details": "Fraud details...",
        "created_at": "2024-01-15"
      }
    ]
  }
}
```

#### Individual Service Endpoints
```http
GET /index.php?service=pathao&phone=01712345678
GET /index.php?service=redx&phone=01712345678
GET /index.php?service=steadfast&phone=01712345678
```

### Diagnostic Endpoints

#### System Health Check
```http
GET /index.php?test
```
**Response:**
```json
{
  "status": "success",
  "message": "PHP is working correctly",
  "timestamp": "2024-01-15 10:30:00",
  "php_version": "7.4.33"
}
```

#### Minimal Test
```http
GET /index.php?minimal
```
**Response:**
```json
{
  "test": "working",
  "time": 1705312200
}
```

#### Credential Testing
```http
GET /index.php?test_credentials
```
**Response:**
```json
{
  "pathao": {
    "success": 0,
    "cancel": 0,
    "total": 0
  },
  "redx": {
    "error": "RedX login rate limited"
  },
  "steadfast": {
    "success": 0,
    "cancel": 0,
    "total": 0
  }
}
```

#### Service-Specific Tests
```http
GET /index.php?test_redx
GET /index.php?test_steadfast
GET /index.php?test_steadfast_login
GET /index.php?test_steadfast_phone&phone=01712345678
```

### Error Responses

#### Invalid Phone Number
```json
{
  "error": "Invalid Bangladeshi phone number. Use local format (e.g., 01712345678). Do not include +88 prefix."
}
```

#### Service Unavailable
```json
{
  "error": "Failed to connect to Pathao API: Connection timeout"
}
```

#### Rate Limited
```json
{
  "error": "RedX is rate limited. Please try again in a few seconds."
}
```

### Response Codes
- **200**: Success
- **400**: Bad Request (invalid phone number)
- **500**: Internal Server Error
- **503**: Service Unavailable (API down)

## Caching & Rate Limits
- Lightweight temp-file cache to reduce API hits.
- Token caching and basic throttling for RedX.

## 🔒 Security Considerations

### Credential Management

#### Development Environment
- **Never commit real credentials** to version control
- Use placeholder values in the repository:
  ```php
  $config = [
      'pathao' => [
          'user' => 'your-email@example.com',
          'password' => 'your-password'
      ],
      // ... other services
  ];
  ```

#### Production Environment
- **Use environment variables** or configuration files outside web root:
  ```php
  // config.php (outside web root)
  $config = [
      'pathao' => [
          'user' => $_ENV['PATHAO_USER'] ?? 'fallback@example.com',
          'password' => $_ENV['PATHAO_PASSWORD'] ?? 'fallback-password'
      ]
  ];
  ```

- **Server-level configuration** (recommended):
  ```bash
  # Set environment variables
  export PATHAO_USER="your-email@example.com"
  export PATHAO_PASSWORD="your-secure-password"
  export REDX_PHONE="01XXXXXXXXX"
  export REDX_PASSWORD="your-secure-password"
  export STEADFAST_USER="your-email@example.com"
  export STEADFAST_PASSWORD="your-secure-password"
  ```

### Network Security

#### HTTPS Implementation
- **Always use HTTPS in production**
- Configure SSL certificates properly
- Redirect HTTP to HTTPS:
  ```apache
  # .htaccess
  RewriteEngine On
  RewriteCond %{HTTPS} off
  RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
  ```

#### Firewall Configuration
- Restrict access to admin/diagnostic endpoints
- Block unnecessary ports
- Use fail2ban for intrusion prevention:
  ```bash
  sudo apt install fail2ban
  sudo systemctl enable fail2ban
  ```

### Application Security

#### Input Validation
- Phone numbers are validated using regex: `/^01[3-9][0-9]{8}$/`
- All inputs are sanitized before processing
- SQL injection protection (not applicable - no database)

#### Rate Limiting
- Built-in rate limiting for RedX API calls
- Cache-based throttling to prevent abuse
- Consider implementing additional rate limiting at server level

#### Error Handling
- Sensitive information is not exposed in error messages
- Error logging is configured to prevent information leakage
- Debug mode should be disabled in production

### Server Security

#### File Permissions
```bash
# Set appropriate permissions
chmod 644 index.php
chmod 755 icons/
chmod 600 config.php  # If using external config
```

#### PHP Security Settings
```ini
# php.ini security settings
expose_php = Off
display_errors = Off
log_errors = On
allow_url_fopen = Off
allow_url_include = Off
```

#### Web Server Configuration
```apache
# Apache security headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

### Data Protection

#### Cache Security
- Cache files are stored in system temp directory
- Files are automatically cleaned up
- No sensitive data is cached permanently

#### API Security
- Credentials are not logged in error messages
- API responses don't expose internal system information
- Rate limiting prevents abuse

### Monitoring and Logging

#### Security Logging
```php
// Add to index.php for security monitoring
function logSecurityEvent($event, $details = '') {
    $logEntry = date('Y-m-d H:i:s') . " - $event - $details\n";
    file_put_contents('/var/log/security.log', $logEntry, FILE_APPEND | LOCK_EX);
}

// Log failed login attempts
if ($loginFailed) {
    logSecurityEvent('LOGIN_FAILED', 'IP: ' . $_SERVER['REMOTE_ADDR']);
}
```

#### Regular Security Audits
- Monitor access logs for suspicious activity
- Review error logs for potential security issues
- Update dependencies regularly
- Test security configurations periodically

### Best Practices

1. **Regular Updates**: Keep PHP and web server updated
2. **Backup Strategy**: Regular backups of configuration and data
3. **Access Control**: Limit server access to authorized personnel
4. **Monitoring**: Set up alerts for unusual activity
5. **Documentation**: Maintain security documentation and procedures

### Compliance Considerations

- **Data Privacy**: Ensure compliance with local data protection laws
- **API Terms**: Respect courier service API terms of service
- **Logging**: Implement appropriate data retention policies
- **Access Control**: Implement proper user access controls if needed

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. All Services Return Errors
**Symptoms:** All three courier services show error messages
**Solutions:**
- Check internet connectivity
- Verify API credentials in `index.php`
- Test individual services using diagnostic endpoints:
  ```bash
  curl "http://localhost/courier-fraud-checker-bd/index.php?test_credentials"
  ```
- Enable demo mode temporarily:
  ```php
  $demoMode = true; // Set in index.php
  ```

#### 2. SSL Certificate Errors
**Symptoms:** cURL SSL errors, "SSL certificate problem"
**Solutions:**
- **Windows (XAMPP):** Update CA certificates
  ```bash
  # Download latest cacert.pem from https://curl.se/ca/cacert.pem
  # Add to php.ini:
  curl.cainfo = "C:\xampp\php\cacert.pem"
  ```
- **Linux:** Update system certificates
  ```bash
  sudo apt update && sudo apt install ca-certificates
  # or
  sudo yum update ca-certificates
  ```

#### 3. RedX Rate Limiting
**Symptoms:** "RedX is rate limited" error
**Solutions:**
- Wait 5-10 seconds between requests
- Check if multiple instances are running
- Clear cache files:
  ```bash
  rm /tmp/redx_cache_*.json
  rm /tmp/redx_token.json
  ```

#### 4. Steadfast Login Issues
**Symptoms:** Steadfast returns HTML instead of JSON
**Solutions:**
- Test login process:
  ```bash
  curl "http://localhost/courier-fraud-checker-bd/index.php?test_steadfast_login"
  ```
- Verify credentials are correct
- Check if Steadfast website is accessible:
  ```bash
  curl "https://steadfast.com.bd/login"
  ```

#### 5. Pathao API Errors
**Symptoms:** "No access token received from Pathao"
**Solutions:**
- Verify email and password credentials
- Check if Pathao merchant account is active
- Test with diagnostic endpoint:
  ```bash
  curl "http://localhost/courier-fraud-checker-bd/index.php?test_credentials"
  ```

#### 6. Phone Number Validation Errors
**Symptoms:** "Invalid Bangladeshi phone number" error
**Solutions:**
- Ensure phone number is in correct format: `01XXXXXXXXX`
- Check normalization function:
  ```javascript
  // Test in browser console
  normalizePhoneClient("+8801712345678") // Should return "01712345678"
  ```

#### 7. Performance Issues
**Symptoms:** Slow response times, timeouts
**Solutions:**
- Increase PHP timeout in `php.ini`:
  ```ini
  max_execution_time = 60
  default_socket_timeout = 60
  ```
- Check server resources (CPU, memory)
- Clear cache files:
  ```bash
  rm /tmp/cf_cache_*.json
  ```

#### 8. Mobile/Responsive Issues
**Symptoms:** UI not displaying correctly on mobile
**Solutions:**
- Clear browser cache
- Check viewport meta tag is present
- Test with different browsers
- Verify CSS is loading correctly

### Diagnostic Commands

#### Test System Health
```bash
# Basic PHP test
curl "http://localhost/courier-fraud-checker-bd/index.php?test"

# Minimal functionality test
curl "http://localhost/courier-fraud-checker-bd/index.php?minimal"
```

#### Test Individual Services
```bash
# Test all credentials
curl "http://localhost/courier-fraud-checker-bd/index.php?test_credentials"

# Test specific services
curl "http://localhost/courier-fraud-checker-bd/index.php?test_redx"
curl "http://localhost/courier-fraud-checker-bd/index.php?test_steadfast"
```

#### Test Phone Number Processing
```bash
# Test with a valid phone number
curl "http://localhost/courier-fraud-checker-bd/index.php?service=pathao&phone=01712345678"
```

### Log Files and Debugging

#### Enable Error Logging
```php
// Add to index.php for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', '/path/to/error.log');
```

#### Check PHP Error Logs
```bash
# XAMPP (Windows)
C:\xampp\apache\logs\error.log

# Linux
/var/log/apache2/error.log
# or
/var/log/nginx/error.log
```

#### Monitor Cache Files
```bash
# Check cache directory
ls -la /tmp/cf_cache_*.json
ls -la /tmp/redx_cache_*.json
ls -la /tmp/pathao_token.json
```

### Getting Help

1. **Check Diagnostic Endpoints** - Use built-in testing tools
2. **Review Error Logs** - Check PHP and web server logs
3. **Test Credentials** - Verify API access with individual services
4. **Enable Demo Mode** - Test with mock data to isolate issues
5. **Check Network** - Ensure internet connectivity and firewall settings

## 📁 Project Structure

```
courier-fraud-checker-bd/
├── index.php              # Main application file (backend + frontend)
├── icons/                 # Courier service logos
│   ├── pathao.jpg        # Pathao logo
│   ├── redx.jpg          # RedX logo
│   └── steadfast.jpg     # Steadfast logo
├── README.md             # This documentation file
└── LICENSE               # MIT License file
```

### File Descriptions

- **`index.php`**: Single-file application containing:
  - PHP backend logic for API integration
  - HTML/CSS/JavaScript frontend
  - Configuration management
  - Error handling and logging
  - Diagnostic endpoints

- **`icons/`**: Contains logo images for each courier service used in the results table

- **`README.md`**: Comprehensive documentation including installation, usage, and API reference

- **`LICENSE`**: MIT License file for open source usage

## 🤝 Contributing

We welcome contributions to improve the Courier Fraud Checker BD! Here's how you can help:

### Development Setup

#### Prerequisites
- PHP 7.4+ with cURL extension
- Git
- Web server (Apache/Nginx) or XAMPP
- Code editor (VS Code, PhpStorm, etc.)

#### Getting Started
1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/courier-fraud-checker-bd.git
   cd courier-fraud-checker-bd
   ```

2. **Set up development environment**
   ```bash
   # Copy configuration template
   cp index.php index.php.backup
   
   # Edit index.php with test credentials
   # Set $demoMode = true for testing
   ```

3. **Test the application**
   ```bash
   # Start local server
   php -S localhost:8000
   
   # Test endpoints
   curl "http://localhost:8000/index.php?test"
   ```

### Contribution Guidelines

#### Code Style
- Follow PSR-12 coding standards
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small

#### Testing
- Test all new features with real API calls
- Use diagnostic endpoints to verify functionality
- Test on multiple devices/browsers
- Verify error handling works correctly

#### Pull Request Process
1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clean, documented code
   - Test thoroughly
   - Update documentation if needed

3. **Submit a pull request**
   - Provide clear description of changes
   - Include screenshots for UI changes
   - Reference any related issues

### Areas for Contribution

#### High Priority
- **API Integration Improvements**: Better error handling, retry logic
- **UI/UX Enhancements**: Mobile responsiveness, accessibility
- **Performance Optimization**: Caching improvements, async processing
- **Security Enhancements**: Input validation, rate limiting

#### Medium Priority
- **Additional Courier Services**: Integration with other Bangladeshi couriers
- **Advanced Analytics**: Fraud pattern detection, reporting
- **Configuration Management**: Environment-based config, admin panel
- **Documentation**: API docs, user guides, video tutorials

#### Low Priority
- **Internationalization**: Multi-language support
- **Themes**: Dark mode, custom styling
- **Export Features**: PDF reports, CSV export
- **Integration**: Webhook support, third-party integrations

### Bug Reports

When reporting bugs, please include:
- **Environment**: PHP version, web server, operating system
- **Steps to reproduce**: Clear, numbered steps
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Error messages**: Full error text and logs
- **Screenshots**: If applicable

### Feature Requests

For feature requests, please provide:
- **Use case**: Why is this feature needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches you've thought about
- **Additional context**: Any other relevant information

### Development Best Practices

#### Code Organization
```php
// Group related functions together
// Use consistent naming conventions
// Add proper error handling
// Include input validation
```

#### Testing Strategy
```bash
# Test individual services
curl "http://localhost:8000/index.php?test_credentials"

# Test phone number normalization
curl "http://localhost:8000/index.php?service=pathao&phone=01712345678"

# Test error handling
curl "http://localhost:8000/index.php?service=pathao&phone=invalid"
```

#### Documentation
- Update README.md for new features
- Add inline code comments
- Document API changes
- Include usage examples

### Community Guidelines

- **Be respectful**: Treat all contributors with respect
- **Be constructive**: Provide helpful feedback and suggestions
- **Be patient**: Remember that contributors are volunteers
- **Be inclusive**: Welcome contributors from all backgrounds

### Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Email**: For security-related issues
- **Documentation**: Check existing docs first

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### License Summary
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ❌ No warranty provided
- ❌ No liability assumed

## ⚠️ Disclaimer

**Important Legal Notice:**

- **Third-party APIs**: This application integrates with external courier service APIs that may change at any time without notice
- **No Guarantee**: We cannot guarantee the accuracy or availability of data from courier services
- **Use at Your Own Risk**: Always verify important business decisions through official courier portals
- **API Terms**: Users must comply with the terms of service of all integrated courier services
- **Data Privacy**: Ensure compliance with local data protection laws when processing customer information
- **Regular Updates**: Monitor for API changes and update the application accordingly

**Recommendation**: Use this tool as a supplementary aid for fraud detection, not as the sole basis for business decisions.
