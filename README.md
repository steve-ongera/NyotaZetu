# Nyota Zetu Bursary Management System

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Django](https://img.shields.io/badge/Django-5.0+-green.svg)
![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Nyota Zetu** (Swahili for "Our Stars") is a comprehensive, AI-powered bursary management system designed for Kenya's County Governments and NG-CDF offices to efficiently manage, allocate, and disburse educational bursaries to deserving students.

## 📋 Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [User Roles](#user-roles)
- [API Documentation](#api-documentation)
- [Security Features](#security-features)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## ✨ Features

### Core Functionality

#### 🎓 Application Management
- **Online Application Portal** - Students apply from anywhere with internet
- **Multi-level Review System** - Ward → Constituency → County review hierarchy
- **Document Upload & Verification** - Support for ID cards, fee statements, academic records
- **Status Tracking** - Real-time application status updates
- **Priority Scoring** - Automated scoring based on need, merit, and vulnerability

#### 💰 Financial Management
- **Budget Allocation** - County-wide and ward-level budget tracking
- **Multiple Bursary Sources** - County Bursary and NG-CDF Bursary support
- **Disbursement Rounds** - Support for multiple disbursement cycles per fiscal year
- **Bulk Cheque Management** - Efficient processing of institutional payments
- **Payment Tracking** - From allocation to disbursement to institutional confirmation

#### 🗺️ Geographic Coverage
- **47 Counties** - Full Kenya coverage
- **Administrative Hierarchy** - County → Constituency → Ward → Location → Sub-location → Village
- **Equitable Distribution** - Ward-based allocation for fairness
- **NG-CDF Integration** - Separate NG-CDF bursary tracking

#### 🤖 AI-Powered Analytics
- **Demand Forecasting** - Predict future bursary needs
- **Allocation Optimization** - AI-recommended allocations based on historical data
- **Performance Trends** - Track success rates and impact
- **Geographic Analysis** - Identify underserved areas
- **Fraud Detection** - Anomaly detection in applications

#### 🔒 Security Features
- **Two-Factor Authentication (2FA)** - SMS-based verification codes
- **Account Lockout Protection** - Automatic lockout after failed attempts
- **Audit Logging** - Complete audit trail of all actions
- **Role-Based Access Control** - Granular permissions system
- **IP Tracking** - Security monitoring and threat detection

#### 📊 Transparency & Reporting
- **Public Reports** - Annual and quarterly transparency reports
- **Beneficiary Lists** - Searchable database of awardees
- **Budget Utilization** - Real-time spending tracking
- **Success Stories** - Beneficiary testimonials
- **Performance Dashboards** - Interactive analytics

#### 📱 Communication
- **SMS Notifications** - Application status updates via SMS
- **Email Notifications** - Detailed communications
- **System Notifications** - In-app notification center
- **Announcement System** - Public notices and deadlines

### Additional Features

- **Multi-institution Support** - High schools, colleges, universities, technical institutes
- **Special Needs Accommodation** - Disability and special circumstances tracking
- **Guardian Management** - Multiple guardian/parent support
- **Sibling Information** - Family context for better assessment
- **Previous Allocation Tracking** - Historical bursary receipt records
- **FAQ System** - Self-service support
- **Mobile Responsive** - Works on all devices

## 🏗️ System Architecture

### Technology Stack

**Backend:**
- Django 5.0+ (Python Web Framework)
- PostgreSQL 15+ (Primary Database)
- Redis (Caching & Session Management)
- Celery (Asynchronous Task Queue)

**Frontend:**
- HTML5, CSS3, JavaScript
- Bootstrap 5 (UI Framework)
- Chart.js (Data Visualization)
- DataTables (Advanced Tables)

**AI/ML:**
- scikit-learn (Machine Learning)
- pandas & numpy (Data Processing)
- TensorFlow (Deep Learning - Optional)

**Infrastructure:**
- Docker & Docker Compose
- Nginx (Web Server)
- Gunicorn (WSGI Server)
- Let's Encrypt (SSL/TLS)

**Third-Party Services:**
- Africa's Talking (SMS Gateway)
- AWS S3 / MinIO (File Storage)
- Sentry (Error Tracking)

### Database Schema

The system uses 40+ interconnected models organized into:
- **User Management** - Authentication, authorization, security
- **Administrative Hierarchy** - Geographic and political boundaries
- **Application Processing** - Applications, documents, reviews
- **Financial Management** - Allocations, disbursements, budgets
- **Communication** - Notifications, SMS, emails
- **Analytics** - AI models, reports, snapshots
- **Public Information** - FAQs, announcements, testimonials

## 📋 Prerequisites

- Python 3.11 or higher
- PostgreSQL 15 or higher
- Redis 7.0 or higher
- Node.js 18+ (for frontend asset management)
- Docker & Docker Compose (optional, for containerized deployment)
- 4GB RAM minimum (8GB recommended)
- 20GB disk space minimum

## 🚀 Installation

### Option 1: Local Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/nyota-zetu.git
cd nyota-zetu

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Edit .env with your configurations
nano .env

# Create PostgreSQL database
createdb nyota_zetu

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load initial data (Kenya counties, constituencies, wards)
python manage.py loaddata fixtures/kenya_administrative_units.json

# Collect static files
python manage.py collectstatic --noinput

# Run development server
python manage.py runserver
```

### Option 2: Docker Deployment

```bash
# Clone the repository
git clone https://github.com/yourusername/nyota-zetu.git
cd nyota-zetu

# Copy and configure environment
cp .env.example .env
nano .env

# Build and start containers
docker-compose up -d

# Run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Load initial data
docker-compose exec web python manage.py loaddata fixtures/kenya_administrative_units.json
```

Access the application at: `http://localhost:8000`

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1,yourdomain.com

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/nyota_zetu
DB_NAME=nyota_zetu
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432

# Redis
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1

# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# SMS Configuration (Africa's Talking)
AFRICAS_TALKING_USERNAME=your_username
AFRICAS_TALKING_API_KEY=your_api_key
AFRICAS_TALKING_SENDER_ID=NYOTAZETU

# File Storage
USE_S3=False
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_STORAGE_BUCKET_NAME=nyota-zetu-files
AWS_S3_REGION_NAME=us-east-1

# Security
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
SECURE_SSL_REDIRECT=True
SECURE_HSTS_SECONDS=31536000

# 2FA Settings
TFA_CODE_EXPIRY_MINUTES=2
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION_MINUTES=30

# Application Settings
COUNTY_NAME=Murang'a County
COUNTY_CODE=047
DEFAULT_FROM_EMAIL=noreply@nyotazetu.go.ke
```

### County-Specific Configuration

1. **Set County Information:**
   - Navigate to Django Admin → Counties
   - Add or edit your county details
   - Set county officials, contact information

2. **Configure Fiscal Year:**
   - Admin → Fiscal Years → Add New
   - Set budget allocations
   - Configure disbursement rounds

3. **Ward Allocations:**
   - Within Fiscal Year, add ward-specific budgets
   - Ensure equitable distribution

4. **Bursary Categories:**
   - Define categories (High School, University, etc.)
   - Set min/max amounts per category

## 📖 Usage

### For County Administrators

1. **Initial Setup:**
   ```bash
   python manage.py setup_county --county="Murang'a" --code="047"
   ```

2. **Create Fiscal Year:**
   - Set budget allocations
   - Configure disbursement rounds
   - Open applications

3. **Manage Applications:**
   - Review submitted applications
   - Assign to ward committees
   - Monitor progress through review levels

4. **Process Allocations:**
   - Approve applications
   - Generate allocations
   - Create bulk cheques
   - Track disbursements

### For Applicants

1. **Register Account:**
   - Visit registration page
   - Provide personal details
   - Verify phone number (2FA)

2. **Complete Profile:**
   - Add guardian information
   - Upload required documents
   - Provide academic details

3. **Submit Application:**
   - Select fiscal year
   - Choose institution
   - Specify amount needed
   - Submit supporting documents

4. **Track Status:**
   - View application status
   - Receive SMS/email updates
   - Respond to document requests

### For Reviewers

1. **Access Review Dashboard:**
   - Login with reviewer credentials
   - View assigned applications

2. **Review Applications:**
   - Verify documents
   - Score applications
   - Add comments
   - Make recommendations

3. **Forward/Approve:**
   - Forward to next level
   - Approve/reject applications
   - Suggest allocation amounts

## 👥 User Roles

| Role | Permissions | Description |
|------|-------------|-------------|
| **Applicant** | Apply, view own applications, upload documents | Students applying for bursaries |
| **Ward Admin** | Review ward applications, verify documents | Ward-level first review |
| **Constituency Admin** | Review constituency applications, recommend amounts | Constituency-level review |
| **County Admin** | Final approval, budget management, system configuration | County government officials |
| **Finance Officer** | Process disbursements, generate cheques, financial reports | County treasury staff |
| **Reviewer** | Review and score applications | Committee members |
| **Super Admin** | Full system access, user management | System administrators |

## 🔌 API Documentation

### Authentication

```bash
# Obtain JWT token
POST /api/auth/token/
{
  "username": "user@example.com",
  "password": "password123"
}

# Verify 2FA code
POST /api/auth/2fa/verify/
{
  "code": "123-456"
}
```

### Applications

```bash
# List applications
GET /api/applications/

# Create application
POST /api/applications/
{
  "fiscal_year": 1,
  "institution": 5,
  "amount_requested": 50000,
  ...
}

# Get application details
GET /api/applications/{id}/

# Update application
PATCH /api/applications/{id}/

# Upload document
POST /api/applications/{id}/upload-document/
```

### Reports

```bash
# Get dashboard statistics
GET /api/reports/dashboard/

# Generate allocation report
GET /api/reports/allocations/?fiscal_year=2024

# Export beneficiaries
GET /api/reports/beneficiaries/export/?format=csv
```

Full API documentation available at: `/api/docs/`

## 🔐 Security Features

### Two-Factor Authentication
- SMS-based OTP for login
- 2-minute code expiry
- Session-based verification

### Account Protection
- Maximum 5 failed login attempts
- 30-minute automatic lockout
- IP-based monitoring

### Data Protection
- Encrypted passwords (PBKDF2)
- HTTPS enforcement
- CSRF protection
- SQL injection prevention
- XSS protection

### Audit Trail
- All actions logged
- IP address tracking
- User agent recording
- Data change history

### Role-Based Access
- Granular permissions
- Object-level permissions
- Department-based access control

## 🧪 Testing

```bash
# Run all tests
python manage.py test

# Run specific test module
python manage.py test applications.tests

# Run with coverage
coverage run --source='.' manage.py test
coverage report
coverage html
```

## 📊 Performance Optimization

- **Database Indexing** - Optimized queries with proper indexes
- **Caching** - Redis-based caching for frequently accessed data
- **Query Optimization** - select_related() and prefetch_related()
- **Celery Tasks** - Asynchronous processing for heavy operations
- **CDN Integration** - Static file delivery via CDN
- **Database Connection Pooling** - Efficient connection management

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Coding Standards

- Follow PEP 8 style guide
- Write comprehensive docstrings
- Add unit tests for new features
- Update documentation

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- User Manual: `/docs/user-manual.pdf`
- Admin Guide: `/docs/admin-guide.pdf`
- API Reference: `/api/docs/`

### Contact
- **Email:** support@nyotazetu.go.ke
- **Phone:** +254 700 000 000
- **Website:** https://nyotazetu.go.ke

### Issue Tracking
Report bugs and request features on our [GitHub Issues](https://github.com/yourusername/nyota-zetu/issues) page.

## 🙏 Acknowledgments

- Kenya County Governments
- National Government Constituencies Development Fund (NG-CDF)
- Ministry of Education
- All contributors and beta testers

## 📅 Roadmap

### Version 1.1 (Q1 2026)
- [ ] Mobile app (Android/iOS)
- [ ] USSD application interface
- [ ] M-Pesa direct disbursement
- [ ] Biometric verification

### Version 1.2 (Q2 2026)
- [ ] AI-powered fraud detection enhancement
- [ ] Blockchain-based verification
- [ ] Multi-language support (Swahili, English)
- [ ] Offline application mode

### Version 2.0 (Q4 2026)
- [ ] National-level aggregation
- [ ] Inter-county transfers
- [ ] Scholarship management
- [ ] Alumni tracking system

---

**Built with ❤️ for Kenya's Students**

*"Nyota Zetu - Empowering Kenya's Stars Through Education"*