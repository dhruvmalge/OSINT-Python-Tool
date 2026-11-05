import csv
import io
import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse, parse_qs

import qrcode
import requests
from flask import (
    Flask, abort, flash, make_response, redirect, render_template,
    request, session, url_for
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from user_agents import parse as parse_ua

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cybersecurity-lab-secret-key")

database_url = os.environ.get("DATABASE_URL", "sqlite:///analytics.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

csrf = CSRFProtect(app)

if os.environ.get("TRUST_PROXY", "0") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db = SQLAlchemy(app)
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", generate_password_hash("admin"))
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
RETENTION_DAYS = max(1, int(os.environ.get("RETENTION_DAYS", "90")))
GEO_LOOKUP = os.environ.get("GEO_LOOKUP", "1") == "1"
MAX_LOOKUP_TIMEOUT = 3


class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    destination = db.Column(db.Text, nullable=False)
    campaign = db.Column(db.String(120), default="", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    is_honeypot = db.Column(db.Boolean, default=False)  # Security lab feature: Canary / Honeypot mode
    active = db.Column(db.Boolean, default=True, nullable=False)


class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey("link.id"), nullable=False, index=True)
    visited_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    country = db.Column(db.String(100), default="")
    region = db.Column(db.String(100), default="")
    city = db.Column(db.String(100), default="")
    isp = db.Column(db.String(180), default="")
    vpn = db.Column(db.String(20), default="unknown")
    browser = db.Column(db.String(100), default="")
    os = db.Column(db.String(100), default="")
    device = db.Column(db.String(100), default="")
    screen = db.Column(db.String(40), default="")
    language = db.Column(db.String(40), default="")
    timezone = db.Column(db.String(80), default="")
    referrer_host = db.Column(db.String(180), default="")
    is_unique = db.Column(db.Boolean, default=True)
    is_bot = db.Column(db.Boolean, default=False)
    threat_score = db.Column(db.Integer, default=0)       # Advanced OSINT/Threat indicator score
    utm_source = db.Column(db.String(100), default="")
    utm_medium = db.Column(db.String(100), default="")
    utm_campaign = db.Column(db.String(100), default="")
    consent_version = db.Column(db.String(20), default="1")


def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped


def valid_destination(value):
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def new_slug(length=8):
    alphabet = string.ascii_letters + string.digits
    while True:
        slug = "".join(secrets.choice(alphabet) for _ in range(length))
        existing = db.session.execute(db.select(Link).filter_by(slug=slug)).scalar_one_or_none()
        if not existing:
            return slug


def visitor_ip():
    return request.remote_addr or ""


def lookup_ip_context(ip):
    result = {"threat_score": 0}
    if not GEO_LOOKUP or not ip:
        return result
    try:
        response = requests.get(
            f"https://ipwho.is/{ip}",
            params={"fields": "success,country,region,city,connection,security"},
            timeout=MAX_LOOKUP_TIMEOUT,
        )
        payload = response.json()
        if payload.get("success"):
            connection = payload.get("connection") or {}
            security = payload.get("security") or {}
            is_vpn_proxy = any(security.get(k) for k in ("vpn", "proxy", "tor"))
            
            # Calculate a mock threat/risk indicator for educational telemetry
            threat = 15 if is_vpn_proxy else 0
            if security.get("tor"):
                threat = 90

            result = {
                "country": payload.get("country", "")[:100],
                "region": payload.get("region", "")[:100],
                "city": payload.get("city", "")[:100],
                "isp": connection.get("isp", "")[:180],
                "vpn": "yes" if is_vpn_proxy else "no",
                "threat_score": threat
            }
    except (requests.RequestException, ValueError, TypeError):
        pass
    return result


def base_url():
    return PUBLIC_BASE_URL or request.url_root.rstrip("/")


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USER and check_password_hash(ADMIN_PASSWORD_HASH, password):
            # Flask-WTF stores the CSRF signing token in the session under
            # "csrf_token". Preserve it when clearing pre-login session data;
            # otherwise the next protected POST (for example, Create Link or
            # Logout) fails with "The CSRF session token is missing".
            csrf_session_token = session.get("csrf_token")
            session.clear()
            if csrf_session_token:
                session["csrf_token"] = csrf_session_token
            session["admin"] = True
            session.permanent = True
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.post("/logout")
@admin_required
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
@admin_required
def dashboard():
    try:
        retention_cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
        db.session.execute(db.delete(Visit).where(Visit.visited_at < retention_cutoff))
        db.session.commit()
    except Exception:
        db.session.rollback()

    search_query = request.args.get("q", "").strip()
    stmt = db.select(Link).order_by(Link.created_at.desc())
    if search_query:
        stmt = stmt.filter(Link.title.ilike(f"%{search_query}%") | Link.slug.ilike(f"%{search_query}%"))

    links = db.session.execute(stmt).scalars().all()
    total = db.session.execute(db.select(db.func.count(Visit.id))).scalar() or 0
    
    since = datetime.now(timezone.utc) - timedelta(days=30)
    recent = db.session.execute(db.select(db.func.count(Visit.id)).filter(Visit.visited_at >= since)).scalar() or 0
    
    latest_rows = db.session.execute(
        db.select(Visit, Link)
        .join(Link, Visit.link_id == Link.id)
        .order_by(Visit.visited_at.desc())
        .limit(30)
    ).all()
    latest = [(visit, link) for visit, link in latest_rows]

    daily = []
    for i in range(13, -1, -1):
        day = (datetime.now(timezone.utc).date() - timedelta(days=i))
        start = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        count = db.session.execute(
            db.select(db.func.count(Visit.id)).filter(Visit.visited_at >= start, Visit.visited_at < end)
        ).scalar() or 0
        daily.append({"day": day.strftime("%b %d"), "count": count})

    return render_template("dashboard.html", links=links, total=total,
                           recent=recent, latest=latest, daily=daily,
                           base=base_url(), search_query=search_query)


@app.route("/links/create", methods=["POST"])
@admin_required
def create_link():
    title = request.form.get("title", "").strip()[:120]
    destination = request.form.get("destination", "").strip()
    campaign = request.form.get("campaign", "").strip()[:120]
    expires_str = request.form.get("expires_at", "").strip()
    raw_password = request.form.get("password", "").strip()
    is_honeypot = True if request.form.get("is_honeypot") == "on" else False

    if not title or not valid_destination(destination):
        flash("Enter a title and a valid http:// or https:// destination.", "error")
        return redirect(url_for("dashboard"))

    expires_at = None
    if expires_str:
        try:
            expires_at = datetime.fromisoformat(expires_str).replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    password_hash = generate_password_hash(raw_password) if raw_password else None

    link = Link(
        slug=new_slug(),
        title=title,
        destination=destination,
        campaign=campaign,
        expires_at=expires_at,
        password_hash=password_hash,
        is_honeypot=is_honeypot
    )
    db.session.add(link)
    db.session.commit()
    flash("Advanced tracking link / canary created successfully.", "success")
    return redirect(url_for("dashboard"))


@app.post("/links/<int:link_id>/toggle")
@admin_required
def toggle_link(link_id):
    link = db.get_or_404(Link, link_id)
    link.active = not link.active
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.get("/links/<int:link_id>/analytics")
@admin_required
def link_analytics(link_id):
    link = db.get_or_404(Link, link_id)
    visits = db.session.execute(
        db.select(Visit).filter_by(link_id=link.id).order_by(Visit.visited_at.desc()).limit(100)
    ).scalars().all()
    total_visits = db.session.execute(db.select(db.func.count(Visit.id)).filter_by(link_id=link.id)).scalar() or 0
    unique_visits = db.session.execute(db.select(db.func.count(Visit.id)).filter_by(link_id=link.id, is_unique=True)).scalar() or 0
    
    return render_template("link_analytics.html", link=link, visits=visits, total_visits=total_visits, unique_visits=unique_visits, base=base_url())


@app.get("/links/<int:link_id>/qr.png")
@admin_required
def qr_code(link_id):
    link = db.get_or_404(Link, link_id)
    url = f"{base_url()}/r/{link.slug}"
    image = qrcode.make(url)
    output = io.BytesIO()
    image.save(output, format="PNG")
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "image/png"
    response.headers["Content-Disposition"] = f'attachment; filename="{link.slug}.png"'
    return response


@app.get("/export.csv")
@admin_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["visit_time_utc", "link", "campaign", "is_unique", "is_bot", "threat_score", "utm_source", 
                     "utm_medium", "utm_campaign", "country", "region", "city", "isp", 
                     "vpn_proxy_tor", "browser", "os", "device", "screen", "language", "timezone", "referrer_host"])
    rows = db.session.execute(
        db.select(Visit, Link).join(Link).order_by(Visit.visited_at.desc())
    ).all()
    for visit, link in rows:
        writer.writerow([visit.visited_at.isoformat(), link.title, link.campaign, visit.is_unique, visit.is_bot, visit.threat_score,
                         visit.utm_source, visit.utm_medium, visit.utm_campaign,
                         visit.country, visit.region, visit.city, visit.isp, visit.vpn,
                         visit.browser, visit.os, visit.device, visit.screen,
                         visit.language, visit.timezone, visit.referrer_host])
    response = make_response("\ufeff" + output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=security-intelligence-export.csv"
    return response


@app.get("/export.pdf")
@admin_required
def export_pdf():
    # Professional Executive PDF Report using ReportLab
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#4f46e5'),
        spaceAfter=10
    )
    
    story.append(Paragraph("Cybersecurity Intelligence & Telemetry Report", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles['Normal']))
    story.append(Spacer(1, 12))

    total_visits = db.session.execute(db.select(db.func.count(Visit.id))).scalar() or 0
    total_links = db.session.execute(db.select(db.func.count(Link.id))).scalar() or 0
    high_threats = db.session.execute(db.select(db.func.count(Visit.id)).filter(Visit.threat_score > 50)).scalar() or 0

    summary_data = [
        ["Total Links & Canaries", str(total_links)],
        ["Total Telemetry Hits", str(total_visits)],
        ["High Threat / VPN / Tor Hits", str(high_threats)]
    ]
    summary_table = Table(summary_data, colWidths=[220, 280])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#0f172a')),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    story.append(Paragraph("Recent Intelligence Log Feed", styles['Heading2']))
    story.append(Spacer(1, 6))

    rows = db.session.execute(
        db.select(Visit, Link).join(Link).order_by(Visit.visited_at.desc()).limit(20)
    ).all()

    table_data = [["Time (UTC)", "Link Title", "Country", "Risk", "Device / Browser"]]
    for visit, link in rows:
        risk_label = f"High ({visit.threat_score})" if visit.threat_score > 50 else f"Low ({visit.threat_score})"
        table_data.append([
            visit.visited_at.strftime('%m-%d %H:%M'),
            link.title[:18],
            visit.country or 'N/A',
            risk_label,
            f"{visit.device[:12]} / {visit.browser[:10]}"
        ])

    t = Table(table_data, colWidths=[85, 110, 75, 90, 140])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#4f46e5')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t)

    doc.build(story)
    buffer.seek(0)
    
    response = make_response(buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=security-intelligence-report.pdf"
    return response


@app.route("/r/<slug>", methods=["GET", "POST"])
def tracked_link(slug):
    link = db.session.execute(db.select(Link).filter_by(slug=slug, active=True)).scalar_one_or_none()
    if not link:
        abort(404)

    # Check expiration
    if link.expires_at and datetime.now(timezone.utc) > link.expires_at:
        abort(404, description="This tracking link has expired.")

    # Password protection workflow
    if link.password_hash:
        if request.method == "POST" and "link_password" in request.form:
            if not check_password_hash(link.password_hash, request.form.get("link_password", "")):
                flash("Incorrect security password.", "error")
                return render_template("password_prompt.html", link=link)
        else:
            return render_template("password_prompt.html", link=link)

    # Parse UTM tags
    parsed_url = urlparse(link.destination)
    query_params = parse_qs(parsed_url.query)
    utm_source = query_params.get("utm_source", [""])[0]
    utm_medium = query_params.get("utm_medium", [""])[0]
    utm_campaign = query_params.get("utm_campaign", [""])[0]

    if request.method == "GET":
        return render_template("consent.html", link=link)

    if request.form.get("consent") != "yes":
        return redirect(link.destination, code=302)

    # Bot & Crawler Telemetry Analysis
    ua_string = request.headers.get("User-Agent", "")
    ua = parse_ua(ua_string)
    bot_keywords = ["bot", "crawler", "spider", "pingdom", "lighthouse", "slackbot", "whatsapp", "scanner"]
    is_bot = any(keyword in ua_string.lower() for keyword in bot_keywords)

    # Unique visitor status via session fingerprinting
    session_key = f"visited_link_{link.id}"
    is_unique = False
    if not session.get(session_key):
        session[session_key] = True
        is_unique = True

    ip_context = lookup_ip_context(visitor_ip())
    threat_score = ip_context.get("threat_score", 0)
    
    # Honeypot boost
    if link.is_honeypot:
        threat_score += 40

    referrer = urlparse(request.referrer).hostname if request.referrer else ""
    
    visit = Visit(
        link_id=link.id,
        country=ip_context.get("country", ""),
        region=ip_context.get("region", ""),
        city=ip_context.get("city", ""),
        isp=ip_context.get("isp", ""),
        vpn=ip_context.get("vpn", "unknown"),
        browser=ua.browser.family[:100],
        os=ua.os.family[:100],
        device=(ua.device.family or "Unknown")[:100],
        screen=request.form.get("screen", "")[:40],
        language=request.form.get("language", "")[:40],
        timezone=request.form.get("timezone", "")[:80],
        referrer_host=(referrer or "")[:180],
        is_unique=is_unique,
        is_bot=is_bot,
        threat_score=threat_score,
        utm_source=utm_source[:100],
        utm_medium=utm_medium[:100],
        utm_campaign=utm_campaign[:100],
    )
    db.session.add(visit)
    db.session.commit()
    return redirect(link.destination, code=302)


@app.get("/privacy")
def privacy():
    return render_template("privacy.html", retention=RETENTION_DAYS,
                           geo_enabled=GEO_LOOKUP)


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", message="Page or canary link not found."), 404


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)