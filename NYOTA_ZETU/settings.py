import os
from decouple import config
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-@pul$@kneu*-+aasa(af^o6q1smh0)o)17+mf5k=l_+#n6v$j1'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

if DEBUG:
    # Development settings - more permissive
    SECURE_CROSS_ORIGIN_OPENER_POLICY = None  # Don't set COOP in development
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
else:
    # Production settings - strict security
    SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin-allow-popups"
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'


# Allow iframe embedding for PDFs
X_FRAME_OPTIONS = 'SAMEORIGIN'

# CORS settings (if using django-cors-headers)
CORS_ALLOWED_ORIGINS = [
    "https://adb166441780.ngrok-free.app",
    'http://localhost:8000',    
    'http://192.168.100.5:8000/',
    'http://127.0.0.1:8000/',
]

CSRF_TRUSTED_ORIGINS = [
    "https://adb166441780.ngrok-free.app",
]

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'main_application',
    'django.contrib.humanize', 
]


AUTH_USER_MODEL = 'main_application.User'

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'main_application.middleware.SessionTimeoutMiddleware',  # Custom session timeout middleware
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'NYOTA_ZETU.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                # Add custom security middleware
                'main_application.middleware.SecurityMonitoringMiddleware',
                'main_application.middleware.URLTrackingMiddleware',
            ],
        },
    },
]

WSGI_APPLICATION = 'NYOTA_ZETU.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'bursary',           # database name
        'USER': 'postgres',          # your postgres username
        'PASSWORD': 'cp7kvt', # your postgres password
        'HOST': 'localhost',         # database server
        'PORT': '5432',              # default postgres port
    }
}



# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]



# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Africa/Nairobi'

USE_I18N = True

USE_TZ = True


STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')    # for `collectstatic` in production

# Media files (user-uploaded content)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# WhiteNoise configuration
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Email Configuration
EMAIL_BACKEND = config('EMAIL_BACKEND')
EMAIL_HOST = config('EMAIL_HOST')
EMAIL_PORT = config('EMAIL_PORT', cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL')


AFRICASTALKING_USERNAME = 'your_username'  # Usually 'sandbox' for testing
AFRICASTALKING_API_KEY = 'your_api_key'
AFRICASTALKING_SENDER_ID = 'KIHARUCDF'  # Your approved sender ID

# Disable SSL certificate verification for development
EMAIL_SSL_CERTFILE = None
EMAIL_SSL_KEYFILE = None
EMAIL_SSL_CA_CERT = None
EMAIL_USE_SSL = False  # Make sure this is False if using TLS

# ==============================
# CDF OFFICE CONTACT INFORMATION
# ==============================
CDF_OFFICE_PHONE = '+254700000000'  
CDF_OFFICE_EMAIL = 'info@kiharucdf.go.ke'
CDF_OFFICE_ADDRESS = 'Kiharu Constituency CDF Office, Murang\'a County'
CDF_WEBSITE_URL = 'https://kiharucdf.go.ke'  

# For Gmail specifically, you might need:
EMAIL_TIMEOUT = 10

# Security monitoring settings
SECURITY_MONITORING = {
    'ENABLED': True,
    'MAX_REQUESTS_PER_MINUTE': 60,
    'MAX_FAILED_LOGINS': 5,
    'ACCOUNT_LOCK_DURATION_MINUTES': 30,
    'SESSION_TIMEOUT_MINUTES': 30,
    'LOG_SECURITY_EVENTS': True,
    'DETECT_SUSPICIOUS_PATTERNS': True,
    'REAL_TIME_ALERTS': True,
}

# Suspicious activity detection settings
SUSPICIOUS_ACTIVITY_DETECTION = {
    'ENABLED': True,
    'UNUSUAL_ACCESS_PATTERN_THRESHOLD': 10,  # requests per minute
    'RAPID_DATA_ACCESS_THRESHOLD': 5,  # pages per minute
    'MULTIPLE_DEVICE_THRESHOLD': 3,  # simultaneous devices
    'RISK_SCORE_THRESHOLD': 70,  # 0-100
    'AUTO_LOCK_HIGH_RISK': True,
    'AUTO_LOCK_RISK_THRESHOLD': 90,
}

# Threat detection patterns (regex)
THREAT_DETECTION_PATTERNS = [
    r'union.*select',  # SQL Injection
    r'<script.*?>',    # XSS
    r'\.\./\.\.',      # Path Traversal
    r'eval\(',         # Code Injection
    r'base64_decode',  # Obfuscation
    r'system\(',       # Command Injection
    r'exec\(',         # Command Injection
    r'wget|curl',      # Remote file inclusion
    r'\$\{.*\}',       # Template injection
]

# Security notification settings
SECURITY_NOTIFICATIONS = {
    'EMAIL_ENABLED': True,
    'SMS_ENABLED': False,
    'NOTIFY_ON_CRITICAL_THREAT': True,
    'NOTIFY_ON_ACCOUNT_LOCK': True,
    'NOTIFY_ON_SUSPICIOUS_ACTIVITY': True,
    'ADMIN_EMAIL': 'security@yourdomain.com',
}

# Audit log retention
AUDIT_LOG_RETENTION_DAYS = 365  # Keep logs for 1 year


# ========================================
# AUTHENTICATION & SESSION SETTINGS (FIXED)
# ========================================

# Fix the LOGIN_URL to point to your actual login view
LOGIN_URL = '/'  # Changed from default '/accounts/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

# Session Configuration - Enhanced for better timeout handling
SESSION_COOKIE_AGE = 3600  # 1 hour in seconds
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True  # Updates session on every request

# Add these additional session settings for better security
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
SESSION_COOKIE_NAME = 'nyotazetu_sessionid'  # Custom session cookie name

# Session timeout warning (optional - for frontend implementation)
SESSION_TIMEOUT_WARNING = 300  # Show warning 5 minutes before expiry


# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'security.log',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'kiharu_system': {  # Replace with your app name
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}


