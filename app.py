from flask import Flask, render_template, request, jsonify, send_file
import sqlite3
import csv
import random
import uuid
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "privacy_assessment.db"
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

# Educational weights from the project specification.
WEIGHTS = {
    "profile": 10,
    "personal": 15,
    "location": 15,
    "content": 10,
    "connections": 10,
    "tagging": 5,
    "security": 15,
    "apps": 5,
    "social_engineering": 10,
    "footprint": 5,
}

QUESTIONS = [
    # Profile
    ("profile_visibility", "Profile Visibility", "Is your social-media profile publicly visible?", ["PUBLIC","FRIENDS","PRIVATE"]),
    ("search_visibility", "Profile Visibility", "Can search engines discover your profile?", ["YES","NO","NOT SURE"]),
    ("followers_public", "Profile Visibility", "Is your follower/friend list visible to people you do not know?", ["YES","NO","NOT SURE"]),
    ("discoverability", "Profile Visibility", "Can unknown people easily find your profile using your name or handle?", ["YES","NO","NOT SURE"]),
    # Personal information
    ("phone_public", "Personal Information", "Is your phone number publicly visible?", ["YES","NO"]),
    ("email_public", "Personal Information", "Is your personal email publicly visible?", ["YES","NO"]),
    ("birthday_public", "Personal Information", "Is your full birth date publicly visible?", ["YES","NO"]),
    ("home_info_public", "Personal Information", "Do you publicly expose home-related information?", ["YES","NO"]),
    ("workplace_public", "Personal Information", "Is your workplace publicly visible?", ["YES","NO"]),
    ("education_public", "Personal Information", "Is your school/college publicly visible?", ["YES","NO"]),
    ("relationship_public", "Personal Information", "Are family or relationship details publicly visible?", ["YES","NO"]),
    # Location
    ("location_public", "Location Privacy", "Do you publicly share your current location?", ["YES","NO","SOMETIMES"]),
    ("realtime_location", "Location Privacy", "Do you share real-time check-ins or live location?", ["YES","NO","SOMETIMES"]),
    ("travel_posts", "Location Privacy", "Do you post travel plans before or during a trip?", ["YES","NO","SOMETIMES"]),
    ("geotagging", "Location Privacy", "Do your photos/posts commonly contain location tags?", ["YES","NO","NOT SURE"]),
    ("location_patterns", "Location Privacy", "Could your posts reveal a repeated daily location pattern?", ["YES","NO","NOT SURE"]),
    # Content
    ("posts_public", "Posts & Content", "Are many of your posts publicly visible?", ["YES","NO","SOMETIMES"]),
    ("old_posts_reviewed", "Posts & Content", "Do you regularly review old public posts?", ["YES","NO","SOMETIMES"]),
    ("photo_privacy", "Posts & Content", "Do you review who can see photos before posting?", ["YES","NO","SOMETIMES"]),
    ("metadata_awareness", "Posts & Content", "Do you know that images can contain metadata such as timestamps/device information?", ["YES","NO","NOT SURE"]),
    # Connections
    ("unknown_connections", "Friends / Followers", "Do you accept connection requests from unknown people?", ["OFTEN","SOMETIMES","RARELY","NEVER"]),
    ("follower_review", "Friends / Followers", "Do you periodically review followers/connections?", ["YES","NO","SOMETIMES"]),
    ("friend_controls", "Friends / Followers", "Can unknown people follow or subscribe to your content?", ["YES","NO","NOT SURE"]),
    # Tagging
    ("tag_review_enabled", "Tagging & Mentions", "Is tag review enabled?", ["YES","NO","NOT SURE"]),
    ("anyone_tag", "Tagging & Mentions", "Can anyone tag you?", ["YES","NO","NOT SURE"]),
    ("mention_control", "Tagging & Mentions", "Can unknown users mention your account?", ["YES","NO","NOT SURE"]),
    # Security
    ("mfa_enabled", "Authentication & Account Security", "Do you use multi-factor authentication (MFA)?", ["YES","NO","NOT SURE"]),
    ("unique_password", "Authentication & Account Security", "Do you use a unique password for this account?", ["YES","NO","NOT SURE"]),
    ("password_manager", "Authentication & Account Security", "Do you use a password manager where appropriate?", ["YES","NO","NOT SURE"]),
    ("login_alerts", "Authentication & Account Security", "Are login/security alerts enabled?", ["YES","NO","NOT SURE"]),
    ("sessions_reviewed", "Authentication & Account Security", "Do you review active sessions/devices?", ["YES","NO","SOMETIMES"]),
    ("recovery_reviewed", "Authentication & Account Security", "Have you reviewed account recovery options recently?", ["YES","NO","SOMETIMES"]),
    # Apps
    ("third_party_reviewed", "Third-Party Apps", "Do you regularly review connected third-party applications?", ["YES","NO","SOMETIMES"]),
    ("unused_apps_removed", "Third-Party Apps", "Do you remove unused integrations?", ["YES","NO","SOMETIMES"]),
    ("permissions_reviewed", "Third-Party Apps", "Do you review permissions granted to connected apps?", ["YES","NO","SOMETIMES"]),
    # Social engineering
    ("suspicious_links", "Messaging & Social Engineering", "Can you identify suspicious or unexpected links/messages?", ["YES","NO","NOT SURE"]),
    ("verification_codes", "Messaging & Social Engineering", "Do you know never to share verification codes with others?", ["YES","NO","NOT SURE"]),
    ("suspicious_dms", "Messaging & Social Engineering", "Do you respond to suspicious direct messages?", ["OFTEN","SOMETIMES","RARELY","NEVER"]),
    ("impersonation_awareness", "Messaging & Social Engineering", "Do you verify unfamiliar accounts before trusting them?", ["YES","NO","SOMETIMES"]),
    # Footprint
    ("unused_accounts", "Digital Footprint", "Do you have old/unused social accounts that you have not reviewed?", ["YES","NO","NOT SURE"]),
    ("public_comments", "Digital Footprint", "Do you have old public comments/posts that you have not reviewed?", ["YES","NO","SOMETIMES"]),
    ("privacy_settings_reviewed", "Digital Footprint", "Do you periodically review your privacy settings?", ["YES","NO","SOMETIMES"]),
    ("old_public_content", "Digital Footprint", "Do you still have past public content you no longer need?", ["YES","NO","NOT SURE"]),
]

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            assessment_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            overall_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            category_scores TEXT NOT NULL,
            finding_types TEXT NOT NULL
        )
        """)

def risk_level(score):
    if score <= 20:
        return "LOW"
    if score <= 40:
        return "MODERATE"
    if score <= 70:
        return "HIGH"
    return "CRITICAL"

def yes_risk(value):
    return {"YES": 1.0, "NO": 0.0, "SOMETIMES": 0.5, "NOT SURE": 0.6}.get(value, 0.0)

def visibility_risk(value):
    return {"PUBLIC": 1.0, "FRIENDS": 0.45, "PRIVATE": 0.0}.get(value, 0.0)

def connection_risk(value):
    return {"OFTEN": 1.0, "SOMETIMES": 0.6, "RARELY": 0.25, "NEVER": 0.0}.get(value, 0.0)

def security_inverse(value):
    return {"YES": 0.0, "NO": 1.0, "NOT SURE": 0.6, "SOMETIMES": 0.5}.get(value, 0.0)

def score_from_answers(a):
    """Return category scores (0-100), overall score, and findings."""
    def avg(values):
        return (sum(values) / len(values) * 100) if values else 0.0

    categories = {}
    findings = []

    profile_vals = [
        visibility_risk(a.get("profile_visibility")),
        yes_risk(a.get("search_visibility")),
        yes_risk(a.get("followers_public")),
        yes_risk(a.get("discoverability")),
    ]
    categories["Profile Exposure"] = round(avg(profile_vals), 1)
    if a.get("profile_visibility") == "PUBLIC":
        findings.append(("Profile Exposure", "Profile is public", "Review audience controls and limit unnecessary public information.", "IMPORTANT"))
    if a.get("search_visibility") == "YES":
        findings.append(("Profile Exposure", "Search-engine visibility enabled", "Review discoverability/search visibility settings.", "GOOD PRACTICE"))

    personal_vals = [yes_risk(a.get(k)) for k in [
        "phone_public","email_public","birthday_public","home_info_public",
        "workplace_public","education_public","relationship_public"
    ]]
    categories["Personal Information"] = round(avg(personal_vals), 1)
    labels = {
        "phone_public":"Phone number reported publicly visible",
        "email_public":"Personal email reported publicly visible",
        "birthday_public":"Full birthday reported publicly visible",
        "home_info_public":"Home-related information reported publicly visible",
        "workplace_public":"Workplace reported publicly visible",
        "education_public":"Education information reported publicly visible",
        "relationship_public":"Family/relationship information reported publicly visible",
    }
    for k, label in labels.items():
        if a.get(k) == "YES":
            findings.append(("Personal Information", label, "Limit visibility of unnecessary personal information.", "IMMEDIATE"))

    location_vals = [yes_risk(a.get(k)) for k in [
        "location_public","realtime_location","travel_posts","geotagging","location_patterns"
    ]]
    categories["Location Exposure"] = round(avg(location_vals), 1)
    if a.get("realtime_location") in ("YES","SOMETIMES"):
        findings.append(("Location Exposure","Real-time location sharing reported",
                         "Avoid publicly broadcasting real-time location unless intentionally needed.","IMMEDIATE"))
    if a.get("travel_posts") in ("YES","SOMETIMES"):
        findings.append(("Location Exposure","Travel plans shared before/during trips",
                         "Consider posting travel content after leaving the location.","IMPORTANT"))
    if a.get("geotagging") == "YES":
        findings.append(("Location Exposure","Geotagging reported",
                         "Review or disable location tags when they are unnecessary.","IMPORTANT"))

    content_vals = [yes_risk(a.get("posts_public")), security_inverse(a.get("old_posts_reviewed")),
                    security_inverse(a.get("photo_privacy")), yes_risk(a.get("metadata_awareness"))]
    categories["Content Exposure"] = round(avg(content_vals), 1)
    if a.get("old_posts_reviewed") == "NO":
        findings.append(("Content Exposure","Old public posts not regularly reviewed",
                         "Review and restrict or remove unnecessary historical public content.","IMPORTANT"))
    if a.get("photo_privacy") == "NO":
        findings.append(("Content Exposure","Photo audience is not regularly reviewed",
                         "Check audience settings before posting photos.","GOOD PRACTICE"))

    connection_vals = [
        connection_risk(a.get("unknown_connections")),
        security_inverse(a.get("follower_review")),
        yes_risk(a.get("friend_controls")),
    ]
    categories["Connection Risk"] = round(avg(connection_vals), 1)
    if a.get("unknown_connections") in ("OFTEN","SOMETIMES"):
        findings.append(("Connection Risk","Unknown connection requests may be accepted",
                         "Verify unfamiliar profiles before accepting requests.","IMPORTANT"))

    tagging_vals = [security_inverse(a.get("tag_review_enabled")),
                    yes_risk(a.get("anyone_tag")),
                    yes_risk(a.get("mention_control"))]
    categories["Tagging Risk"] = round(avg(tagging_vals), 1)
    if a.get("tag_review_enabled") == "NO":
        findings.append(("Tagging Risk","Tag review is disabled",
                         "Enable tag review where the platform supports it.","IMPORTANT"))

    security_vals = [security_inverse(a.get(k)) for k in [
        "mfa_enabled","unique_password","password_manager","login_alerts",
        "sessions_reviewed","recovery_reviewed"
    ]]
    categories["Account Security"] = round(avg(security_vals), 1)
    if a.get("mfa_enabled") == "NO":
        findings.append(("Account Security","MFA is disabled",
                         "Enable MFA using a strong supported method.","IMMEDIATE"))
    if a.get("login_alerts") == "NO":
        findings.append(("Account Security","Login/security alerts are disabled",
                         "Enable login alerts where available.","IMPORTANT"))

    apps_vals = [security_inverse(a.get(k)) for k in [
        "third_party_reviewed","unused_apps_removed","permissions_reviewed"
    ]]
    categories["Third-Party Apps"] = round(avg(apps_vals), 1)
    if a.get("third_party_reviewed") == "NO":
        findings.append(("Third-Party Apps","Connected applications are not regularly reviewed",
                         "Review and revoke unnecessary application access.","IMPORTANT"))

    social_vals = [
        security_inverse(a.get("suspicious_links")),
        security_inverse(a.get("verification_codes")),
        connection_risk(a.get("suspicious_dms")),
        security_inverse(a.get("impersonation_awareness")),
    ]
    categories["Social Engineering"] = round(avg(social_vals), 1)
    if a.get("suspicious_links") == "NO":
        findings.append(("Social Engineering","Suspicious-link awareness reported as low",
                         "Pause and verify unexpected links/messages before interacting.","IMPORTANT"))
    if a.get("verification_codes") == "NO":
        findings.append(("Social Engineering","Verification-code safety awareness needs improvement",
                         "Never share one-time verification codes with another person.","IMMEDIATE"))

    footprint_vals = [
        yes_risk(a.get("unused_accounts")),
        yes_risk(a.get("public_comments")),
        security_inverse(a.get("privacy_settings_reviewed")),
        yes_risk(a.get("old_public_content")),
    ]
    categories["Digital Footprint"] = round(avg(footprint_vals), 1)
    if a.get("privacy_settings_reviewed") == "NO":
        findings.append(("Digital Footprint","Privacy settings are not regularly reviewed",
                         "Schedule periodic privacy-setting reviews.","GOOD PRACTICE"))
    if a.get("unused_accounts") == "YES":
        findings.append(("Digital Footprint","Unused accounts reported",
                         "Review, secure, or close accounts that are no longer needed.","GOOD PRACTICE"))

    # Map category names to the specified weights.
    key_map = {
        "Profile Exposure":"profile", "Personal Information":"personal",
        "Location Exposure":"location", "Content Exposure":"content",
        "Connection Risk":"connections", "Tagging Risk":"tagging",
        "Account Security":"security", "Third-Party Apps":"apps",
        "Social Engineering":"social_engineering", "Digital Footprint":"footprint"
    }
    overall = sum(categories[name] * WEIGHTS[key_map[name]] / 100 for name in categories)
    overall = round(max(0, min(100, overall)), 1)
    return categories, overall, findings

def simulate_improvement(answers):
    improved = dict(answers)
    changes = {
        "phone_public":"NO", "email_public":"NO", "birthday_public":"NO",
        "location_public":"NO", "realtime_location":"NO", "travel_posts":"NO",
        "geotagging":"NO", "tag_review_enabled":"YES", "mfa_enabled":"YES",
        "login_alerts":"YES", "third_party_reviewed":"YES",
        "unused_apps_removed":"YES", "permissions_reviewed":"YES",
        "old_posts_reviewed":"YES", "privacy_settings_reviewed":"YES",
        "unknown_connections":"NEVER",
    }
    improved.update(changes)
    return improved

def generate_synthetic_dataset(n=1000):
    path = DATA_DIR / "social_media_privacy_assessments.csv"
    fields = ["profile_id"] + [q[0] for q in QUESTIONS] + ["risk_score","risk_level"]
    rng = random.Random(42)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for _ in range(n):
            answers = {}
            for key, _, _, options in QUESTIONS:
                # Generate realistic but entirely fictional responses.
                answers[key] = rng.choice(options)
            cats, score, _ = score_from_answers(answers)
            row = {"profile_id": str(uuid.uuid4())[:8], **answers,
                   "risk_score": score, "risk_level": risk_level(score)}
            writer.writerow(row)
    return path

@app.route("/")
def index():
    return render_template("index.html", questions=QUESTIONS)

@app.post("/api/assess")
def assess():
    data = request.get_json(silent=True) or {}
    answers = data.get("answers", {})
    # Only accept known questionnaire keys.
    known = {q[0] for q in QUESTIONS}
    answers = {k: v for k, v in answers.items() if k in known}
    categories, score, findings = score_from_answers(answers)

    assessment_id = str(uuid.uuid4())
    finding_types = "; ".join(sorted(set(f[0] for f in findings))) or "None"
    category_text = "; ".join(f"{k}={v}" for k,v in categories.items())

    with sqlite3.connect(DB_PATH) as con:
        con.execute("""INSERT INTO assessments
            (assessment_id,created_at,overall_score,risk_level,category_scores,finding_types)
            VALUES (?,?,?,?,?,?)""",
            (assessment_id, datetime.now().isoformat(timespec="seconds"),
             score, risk_level(score), category_text, finding_types))

    return jsonify({
        "assessment_id": assessment_id,
        "score": score,
        "risk_level": risk_level(score),
        "categories": categories,
        "findings": [
            {"category": f[0], "finding": f[1], "recommendation": f[2], "priority": f[3]}
            for f in findings
        ],
    })

@app.post("/api/simulate")
def simulate():
    data = request.get_json(silent=True) or {}
    answers = data.get("answers", {})
    _, before, _ = score_from_answers(answers)
    improved = simulate_improvement(answers)
    categories_after, after, findings_after = score_from_answers(improved)
    return jsonify({
        "before": before,
        "after": after,
        "reduction": round(before - after, 1),
        "after_level": risk_level(after),
        "categories_after": categories_after,
        "remaining_findings": len(findings_after)
    })

@app.get("/api/stats")
def stats():
    with sqlite3.connect(DB_PATH) as con:
        total, avg = con.execute("SELECT COUNT(*), AVG(overall_score) FROM assessments").fetchone()
        levels = dict(con.execute(
            "SELECT risk_level, COUNT(*) FROM assessments GROUP BY risk_level"
        ).fetchall())
    return jsonify({"total": total or 0, "average": round(avg or 0, 1), "levels": levels})

@app.get("/api/checklist")
def checklist():
    return jsonify([
        "Review profile visibility",
        "Hide unnecessary contact information",
        "Review birthday visibility",
        "Review location sharing",
        "Avoid unnecessary real-time location posts",
        "Review tagging permissions",
        "Review followers/friends",
        "Verify unfamiliar requests",
        "Enable MFA",
        "Enable login alerts where available",
        "Review active sessions",
        "Review connected apps",
        "Remove unused integrations",
        "Review old public posts",
        "Review photo privacy",
        "Be cautious with unexpected links",
        "Never share verification codes",
        "Review privacy settings periodically",
    ])

@app.get("/download/dataset")
def download_dataset():
    path = generate_synthetic_dataset(1000)
    return send_file(path, as_attachment=True)

if __name__ == "__main__":
    init_db()
    print("Starting Social Media Privacy Risk Assessment Framework")
    print("Open http://127.0.0.1:5000")
    app.run(debug=True)
