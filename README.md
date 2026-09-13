# 🏠 RentManager — Professional Property Management System

A full-featured, production-ready rent management platform for multi-unit properties. Manage tenants, track monthly rent, verify payments with OCR, send automated notifications, and generate comprehensive financial audits—all from your browser, accessible anywhere.

**Live Demo Features**: Month-wise rent history, deposit tracking, tenant lifecycle management, payment screenshot verification, WhatsApp automation, Excel bulk import/export, and CA-audit-ready financial reports.

---

## 🚀 DEPLOY FOR FREE IN 5 MINUTES (Render.com)

### Prerequisites
- GitHub account (free)
- Render.com account (free)
- Optional: Meta Developer account (for WhatsApp notifications)

### Step 1 — Prepare Code on GitHub
1. Go to **github.com** → Click **New** → Create repository named `rent-manager` → Create
2. Download **GitHub Desktop** from github.com/desktop
3. Clone the new repo to your computer
4. Copy all files from this project into the cloned folder
5. In GitHub Desktop: **Commit to main** → **Push origin**

### Step 2 — Deploy on Render.com
1. Go to **render.com** → Sign up free with GitHub
2. Click **New +** → **Web Service**
3. Connect your `rent-manager` GitHub repository
4. Fill in settings:
   - **Name:** `rent-manager`
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --workers 2 --bind 0.0.0.0:$PORT --timeout 120`
5. Set **Environment Variables:**
   | Variable | Value | Notes |
   |----------|-------|-------|
   | `SECRET_KEY` | `any-random-string-xyz123abc` | Session encryption key |
   | `ADMIN_PASSWORD` | `YourSecurePassword123!` | **CHANGE this immediately** |
   | `FLASK_ENV` | `production` | Production mode |
   | `DATABASE_URL` | *(auto-filled)* | PostgreSQL: add free DB below |
   | `OCRSPACE_API_KEY` | `helloworld` | Free OCR.space API key |
   | `ACCESS_TOKEN` | *(optional)* | Meta WhatsApp Business API token |
   | `PHONE_NUMBER_ID` | *(optional)* | Your WhatsApp Business phone number ID |

6. **Optional — Add PostgreSQL (free 90 days):**
   - In Render dashboard → New + → PostgreSQL
   - Create → Copy **Internal Database URL**
   - Paste into `DATABASE_URL` env var above
   - *Note: Free tier auto-deletes after 90 days. Upgrade to Starter ($7/mo) for persistent storage.*

7. Click **Create Web Service** → Wait 2-3 minutes
8. You'll see: `Your site is live at https://rent-manager-abc123.onrender.com`

### Step 3 — First Login & Setup
- Open your Render URL
- **Login:** `admin` / (the password you set in `ADMIN_PASSWORD`)
- Go to **Settings → Change Password** immediately
- Go to **Settings → Change Username** to customize (optional)

---

## 💻 RUN LOCALLY ON YOUR COMPUTER

### System Requirements
- Python 3.9 or higher
- SQLite3 (included with Python) or PostgreSQL

### Setup Instructions

```bash
# 1. Extract/clone the project and open terminal in the folder
cd "Rent Manager"

# 2. Create Python virtual environment
python -m venv venv

# Activate (choose your OS):
source venv/bin/activate              # macOS / Linux
venv\Scripts\activate                 # Windows

# 3. Install all dependencies
pip install -r requirements.txt

# 4. Create .env file with configuration
copy .env.example .env                # Windows
# OR
cp .env.example .env                  # macOS / Linux

# Edit .env with your values:
# SECRET_KEY=your-random-key-here
# ADMIN_PASSWORD=your-password-here
# FLASK_ENV=development
# DATABASE_URL=sqlite:///rent.db

# 5. Run the application
python app.py

# 6. Open browser and go to:
# http://localhost:5000
```

**First-time Login:**
- Username: `admin`
- Password: *(value you set in .env `ADMIN_PASSWORD`)*

---

## 📋 FEATURE OVERVIEW

| Feature | Purpose | Key Abilities |
|---------|---------|---------------|
| **Dashboard** | Home overview | KPIs, collection status, 6-month trend, overdue alerts |
| **Rent Tracker** | Current month management | View all units, mark paid, send reminders (1 click) |
| **Rent History** | Month-wise records | View/add/edit past/current month records, bulk mark paid |
| **Tenants** | Renter profiles | Add, edit, view history, upload photo/agreement, track vacate settlement |
| **Payment Verify** | Payment confirmation | Upload screenshot → OCR extracts amount & transaction ID (or manual entry) |
| **Vacate Settlement** | Deposit management | Deduct repairs/paint, calculate final return amount, track vacated tenants |
| **Common Expenses** | Shared costs | Add expense → auto-splits across X units (e.g., 6 flats) |
| **Building Expenses** | Maintenance costs | Log repairs, maintenance with category & receipt upload |
| **Income & Expenses** | Financial dashboard | 6-month trend chart, monthly income vs. expenses breakdown |
| **CA Audit** | Tax/audit reporting | P&L, debit/credit ledger by tenant, FY calculations (April–March), deposit tracking |
| **Reminders** | Tenant notifications | Manual WhatsApp/SMS triggers, log all sent reminders |
| **Bulk Import/Export** | Data management | Upload `.xlsx` → auto-import tenants, rent records, expenses; export to Excel |
| **Admin Settings** | User management | Change password, change username, login management |
| **API Health Check** | Monitoring | `/health` endpoint for uptime monitoring |

---

## 💬 PAYMENT VERIFICATION → OCR MAGIC

### Supported Payment Apps (Free OCR)
✅ PhonePe | ✅ Google Pay | ✅ Paytm | ✅ CRED | ✅ NEFT Bank Slips | ✅ Any text-based screenshot

### How It Works

1. Tenant pays via UPI/bank → Takes screenshot
2. You upload screenshot in **Payment Verify** page
3. **OCR Engine** (OCR.space) automatically reads:
   - **₹ Amount** — extracts exact rupee value
   - **Transaction ID** — UTR, Txn ID, UPI Ref, or phone number
4. System shows detected values → You confirm → Mark Paid
5. *(Optional)* Manually override if OCR misses (rare)

### Tesseract OCR (Alternative — Local Processing)

If you want **on-device OCR** instead of cloud API (better privacy):

**Windows:**
```
1. Download: github.com/UB-Mannheim/tesseract/wiki
2. Install → Note install path (e.g., C:\Program Files\Tesseract-OCR)
3. Add to .env:
   TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
```

**Ubuntu/Linux/Render:**
```bash
# Add to Render build command (before pip install):
apt-get install -y tesseract-ocr && pip install -r requirements.txt
```

**macOS:**
```bash
brew install tesseract
```

*Note: If Tesseract is not installed, screenshot upload still works but requires manual amount confirmation.*

---

## 🤖 AUTOMATED WHATSAPP NOTIFICATIONS

### Setup (5 minutes)

1. **Create Meta Business Account:**
   - Go to **developers.facebook.com**
   - Create a Business App
   - Add **WhatsApp** product

2. **Get Credentials:**
   - **Access Token** — Copy from App Settings
   - **Phone Number ID** — From WhatsApp Business account

3. **Add to Render:**
   - `ACCESS_TOKEN` = your Token
   - `PHONE_NUMBER_ID` = your Phone ID

4. **Send Reminders:**
   - Dashboard → **Reminders** panel → Click phone icon → Auto-sends template message
   - Or automatic daily reminders at **9:00 AM IST** (daily_scheduler)

### Message Template (Rent Reminder)
```
Hello {{name}}, your rent of ₹{{amount}} is due on {{due_date}}.
```

---

## 📊 EXCEL BULK IMPORT & EXPORT

### Import Tenants & Historical Data

**Go to:** Settings → Upload Excel

**Excel Format** (Download template from template link):

| Sheet Name | Columns | Purpose |
|-----------|---------|---------|
| **Tenants** | Name, Phone, Email, Unit, Occupancy, Amount, Deposit, Join Date, Vacate Date, Status, Payment Method, Notes | Import tenant database |
| **Rent Records** | Tenant Name, Month, Year, Rent Amount, Status | Import historical rent payments |
| **Common Expenses** | Date, Description, Amount, Category, Split Units, Notes | Import shared cost expenses |
| **Building Expenses** | Date, Description, Amount, Category, Notes | Import maintenance costs |
| **Vacate Settlements** | Tenant Name, Deposit, Repair Cost, Other Deduction, Return Amount | Import deposit settlements |

**Export:** Click **Download Excel** button to export current data for backup/reporting.

---

## 🔐 ADMIN & SECURITY

### Default Credentials
- **Username:** `admin`
- **Password:** *(set via `ADMIN_PASSWORD` env var)*

### First Steps (MANDATORY)
1. Login with default credentials
2. Go to **Settings → Change Password** → Set strong password
3. Go to **Settings → Change Username** → Customize (optional)
4. Logout and re-login to verify

### Deployment Security Checklist
- ✅ Set unique `SECRET_KEY` in production
- ✅ Set strong `ADMIN_PASSWORD` (min 8 chars, mixed case)
- ✅ Use HTTPS only (Render auto-provides)
- ✅ Regularly backup database (`./backup/` folder)
- ✅ Monitor `/health` endpoint for uptime

---

## 🗄️ DATABASE SCHEMA

### Core Tables

**Tenants** — Renter information
```
id, name, phone, email, unit, amount, due_date, 
join_date, vacated_date, occupancy_status (Active/Vacated), 
deposit, notes, photo_path, agreement_path, payment_method
```

**RentRecord** — Month-wise payment tracking (UNIQUE: tenant_id + month + year)
```
id, tenant_id, tenant_name, month, year, rent_amount, paid_amount, 
status (Paid/Pending), payment_date, payment_method, transaction_id, 
payment_screenshot, carried_forward, notes
```

**CommonExpense** — Shared unit costs
```
id, description, amount, category, split_units (default: 6), 
date, notes, per_unit (calculated)
```

**BuildingExpense** — Building/maintenance costs
```
id, description, amount, category, date, receipt_path, notes
```

**VacateSettlement** — Deposit tracking for vacated tenants
```
id, tenant_id, deposit_held, repair_cost, other_deduction, 
deduction_notes, return_amount, settlement_date
```

**ReminderLog** — History of all reminders sent
```
id, tenant_id, tenant_name, channel (whatsapp/sms), 
status (sent/failed), message, sent_at
```

**Admin** — User credentials
```
id, username, password_hash
```

---

## 🔄 BACKGROUND JOBS (APScheduler)

These run automatically on Render/local deployment:

| Job | Trigger | Purpose |
|-----|---------|---------|
| Daily Reminders | 9:00 AM IST | Send WhatsApp to tenants with today/upcoming due rents |
| Monthly Reset | 1st of month, 12:01 AM IST | Auto-reset all tenant statuses to "Pending" |
| Database Backup | 12:05 AM IST | Copy SQLite DB to `./backup/` (local only) |

---

## 📡 API ENDPOINTS (All Protected by Login)

### Authentication
- `GET/POST /login` — Admin login
- `GET /logout` — Logout
- `POST /change-password` — Change admin password
- `POST /change-username` — Change admin username

### Dashboard & Tracking
- `GET /` — Dashboard (home)
- `GET /rent-tracker` — Current month tenants
- `GET /rent-history` — Historical records (queryable by month/year)
- `GET /api/dashboard` — JSON dashboard data

### Rent Records (Month-wise)
- `GET/POST /rent-history/add` — Add new monthly record
- `GET/POST /rent-history/edit/<id>` — Edit record
- `POST /rent-history/mark-paid/<id>` — Mark record as paid
- `POST /rent-history/mark-unpaid/<id>` — Revert to unpaid
- `POST /rent-history/delete/<id>` — Delete record

### Tenants & Payments (Current Month)
- `GET /renters` — All tenants list
- `GET /renters/detail/<id>` — Individual tenant profile + history
- `GET/POST /renters/add` — Add new tenant
- `GET/POST /renters/edit/<id>` — Edit tenant
- `POST /renters/delete/<id>` — Delete tenant
- `GET/POST /renters/vacate/<id>` — Mark as vacated, settle deposit
- `GET/POST /tenant/verify-payment/<id>` — OCR screenshot or manual entry
- `POST /tenant/mark-paid/<id>` — Quick mark paid
- `POST /tenant/mark-unpaid/<id>` — Revert to unpaid
- `POST /tenant/remind/<id>` — Send WhatsApp/SMS reminder
- `POST /tenant/force-paid/<id>` — Force mark paid with screenshot

### Expenses
- `GET /common-expenses` — Shared expense list
- `POST /common-expenses/add` — Add common expense
- `POST /common-expenses/delete/<id>` — Delete expense
- `GET /building-expenses` — Maintenance/repairs list
- `POST /building-expenses/add` — Add building expense
- `POST /building-expenses/delete/<id>` — Delete expense

### Reporting
- `GET /income-expenses` — Income vs. expenses (6-month trends)
- `GET /ca-audit` — CA audit report (P&L, ledger, FY-based)
- `GET /reminders` — Reminder logs

### Data Management
- `GET/POST /upload/excel` — Bulk import tenants/records/expenses
- `GET /download/excel` — Export current data to Excel

### Health Check
- `GET /health` — Uptime monitoring (returns 200 OK)

---

## ⚙️ ENVIRONMENT VARIABLES

Create a `.env` file (copy `.env.example` and modify):

```bash
# Core
SECRET_KEY=YourRandomString123!WithSpecialChars@
ADMIN_PASSWORD=StrongPasswordHere123!
FLASK_ENV=production

# Database (optional for local — defaults to SQLite)
DATABASE_URL=                    # Leave blank for SQLite
                                 # OR postgresql://user:pass@localhost:5432/rentdb

# OCR (for payment verification)
OCRSPACE_API_KEY=helloworld      # Free tier API key (leave as-is)
TESSERACT_CMD=                   # Windows: C:\Program Files\Tesseract-OCR\tesseract.exe
                                 # Leave blank for Linux/macOS (if installed via apt/brew)

# WhatsApp (optional)
ACCESS_TOKEN=                    # Meta WhatsApp Business API token
PHONE_NUMBER_ID=                 # Your WhatsApp Business phone number ID

# SMS (optional — requires Fast2SMS account)
FAST2SMS_KEY=                    # Your Fast2SMS API key (optional)

# Anthropic (optional — fallback for AI features)
ANTHROPIC_API_KEY=               # Not used in current version
```

---

## 🐛 TROUBLESHOOTING

### "Application Error" on Render
- **Cause:** Free tier sleeps after 15 mins of inactivity
- **Fix:** Wait 30 seconds, refresh page

### Database Lost on Render (Free Tier)
- **Cause:** Render free tier has no persistent disk; data resets after deployment
- **Fix:** Upgrade to Starter ($7/mo) OR add free PostgreSQL database
  ```
  Render → New + → PostgreSQL (free 90 days) → Copy Internal Database URL
  → Paste into DATABASE_URL env var
  ```

### WhatsApp Not Sending
- **Check:** 
  1. Is `ACCESS_TOKEN` set in Render env vars?
  2. Is `PHONE_NUMBER_ID` set correctly?
  3. Log into Meta → Check app is approved for production
  4. Check Render logs for API errors

### Payment OCR Not Detecting Amount
- **Cause:** Screenshot quality too low, unusual app design, or language mismatch
- **Fix:** 
  1. Request clearer screenshot (crop to transaction details)
  2. Use **Manual Entry** option
  3. Ensure amount is in written form (₹), not symbol-only

### Excel Import Fails
- **Check:**
  1. File is `.xlsx` or `.xls` format (not `.csv`)
  2. Sheet names match exactly: "Tenants", "Rent Records", etc.
  3. No blank rows between header and data
  4. Dates are in `YYYY-MM-DD` format

### Site is Slow
- **Cause:** Render free tier is resource-limited
- **Fix:** Upgrade to Starter or Performance tier

---

## 📦 TECH STACK & DEPENDENCIES

| Component | Version | Purpose |
|-----------|---------|---------|
| **Python** | 3.11.9 | Runtime |
| Flask | 3.0.3+ | Web framework |
| Flask-SQLAlchemy | 3.1.1+ | ORM |
| SQLAlchemy | 2.0.30+ | Database abstraction |
| APScheduler | 3.10.4+ | Background jobs |
| Requests | 2.31.0+ | HTTP (WhatsApp, OCR, SMS) |
| Pillow | 10.4.0+ | Image processing |
| openpyxl | 3.1.2+ | Excel import/export |
| Werkzeug | 3.0.3+ | Security, file handling |
| Gunicorn | 22.0.0+ | Production server |
| psycopg2-binary | 2.9.9+ | PostgreSQL driver |
| python-dotenv | 1.0.1+ | Environment config |
| pytz | 2024.1+ | Timezone handling |

---

## 📄 PROJECT STRUCTURE

```
Rent Manager/
├── app.py                    # Flask app, all routes (1200+ lines)
├── models.py                 # Database models (7 tables)
├── scheduler.py              # APScheduler background jobs
├── whatsapp.py               # Meta WhatsApp Cloud API integration
├── ocr_parser.py             # Payment screenshot OCR parsing
├── requirements.txt          # Python dependencies
├── runtime.txt               # Python version (3.11.9)
├── Procfile                  # Heroku deployment
├── render.yaml               # Render deployment config
├── .env.example              # Environment template
├── .gitignore                # Git ignore rules
├── README.md                 # This file
├── static/
│   └── uploads/              # User-uploaded files (photos, agreements, receipts)
├── templates/
│   ├── base.html             # Base template
│   ├── dashboard.html        # Home page
│   ├── rent_tracker.html     # Current month tracking
│   ├── rent_history.html     # Historical records
