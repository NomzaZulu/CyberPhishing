
# ============================================================
# CYBERGUARD ENGINE
# AI-Powered Phishing & Cyber Threat Detection
# ============================================================

# -------------------------
# IMPORTS
# -------------------------

import re
from urllib.parse import parse_qs, unquote
from urllib.parse import urlparse

import tldextract
from transformers import pipeline


# ============================================================
# 1. LOAD AI PHISHING MODEL
# ============================================================

print("Loading CyberGuard phishing model...")

classifier = pipeline(
    "text-classification",
    model="ealvaradob/bert-finetuned-phishing",
    truncation=True,
    max_length=512
)

print("Phishing classifier loaded successfully!")


# ============================================================
# 2. SAFETY WARNING DETECTOR
# ============================================================

def is_safety_warning(text):

    warning_phrases = [
        "never ask for your otp",
        "never ask for your pin",
        "never ask for your password",
        "do not share your otp",
        "do not share your pin",
        "do not provide your password",
        "never share your otp",
        "never share your password"
    ]

    return any(
        phrase in text.lower()
        for phrase in warning_phrases
    )


# ============================================================
# 3. MESSAGE INDICATOR DETECTOR
# ============================================================

def detect_indicator_categories(message):

    text = message.lower()
    categories = {}

    category_rules = {

        "Urgency or Threat": [
            "urgent",
            "immediately",
            "hurry",
            "within 30 minutes",
            "act now",
            "last warning",
            "expires today",
            "account will be closed",
            "account will be suspended",
            "account will be blocked",
            "account has been suspended",
            "account has been blocked",
            "account has been closed"
        ],

        "Credential Request": [
            "enter your password",
            "provide your password",
            "share your password",
            "send your password",
            "confirm your password",
            "verify your password",

            "enter otp",
            "share otp",
            "send otp",
            "provide otp",

            "enter the otp",
            "share the otp",
            "send the otp",
            "provide the otp",

            "enter your pin",
            "share your pin",
            "provide your pin",

            "enter the pin",
            "share the pin",
            "provide the pin",

            "enter cvv",
            "share cvv",
            "provide cvv",

            "enter the cvv",
            "share the cvv",
            "provide the cvv",

            "verify your account",
            "confirm your identity"
        ],

        "Financial Request": [
            "pay now",
            "make a payment",
            "complete the payment",
            "send money",
            "transfer money",
            "send the money",
            "pay a fee",
            "pay the fee",
            "claim fee",
            "enter your card details",
            "provide your card details",
            "credit card details",
            "debit card details",
            "bank account details",
            "share your bank details",
            "send your bank details"
        ],

        "Suspicious Action": [
            "click here",
            "click the link",
            "login here",
            "sign in here",
            "open the link",
            "download the attachment",
            "update your details",
            "reset your password"
        ],

        "Prize or Reward Scam": [
            "won a lottery",
            "won a prize",
            "claim your prize",
            "claim your reward",
            "lucky draw",
            "processing fee",
            "cash prize"
        ]
    }

    safety_warning = is_safety_warning(text)

    for category, keywords in category_rules.items():

        matches = [
            keyword
            for keyword in keywords
            if keyword in text
        ]

        if category == "Credential Request" and safety_warning:
            matches = []

        if matches:
            categories[category] = matches

    # Payment amount detection
    payment_pattern = r"\bpay\s+(?:₹|\$|€|£)?\s*\d+"

    if re.search(payment_pattern, text):

        categories.setdefault(
            "Financial Request",
            []
        ).append("payment amount detected")

    return categories


# ============================================================
# 4. MESSAGE RISK SCORE
# ============================================================

def calculate_category_score(categories):

    category_points = {

        "Urgency or Threat": 15,
        "Credential Request": 25,
        "Financial Request": 20,
        "Suspicious Action": 10,
        "Prize or Reward Scam": 20
    }

    total_score = sum(
        category_points.get(category, 0)
        for category in categories
    )

    # High-risk combinations

    if (
        "Urgency or Threat" in categories
        and "Financial Request" in categories
    ):
        total_score += 20

    if (
        "Urgency or Threat" in categories
        and "Credential Request" in categories
    ):
        total_score += 20

    if (
        "Prize or Reward Scam" in categories
        and "Financial Request" in categories
    ):
        total_score += 30

    return min(total_score, 100)


# ============================================================
# 5. HIGH-RISK COMBINATION DETECTOR
# ============================================================

def detect_high_risk_combinations(message):

    text = message.lower()
    combinations = []

    prize_terms = [
        "won",
        "prize",
        "reward",
        "lottery",
        "cash prize",
        "lucky draw"
    ]

    payment_terms = [
        "pay",
        "payment",
        "fee",
        "charge",
        "transfer",
        "send money"
    ]

    negative_payment_phrases = [
        "no payment required",
        "no payment is required",
        "without payment",
        "no fee required",
        "no fee is required",
        "you do not need to pay"
    ]

    prize_detected = any(
        term in text
        for term in prize_terms
    )

    payment_detected = (
        any(
            term in text
            for term in payment_terms
        )
        and not any(
            phrase in text
            for phrase in negative_payment_phrases
        )
    )

    if prize_detected and payment_detected:
        combinations.append(
            "Prize scam requesting payment"
        )

    return combinations


# ============================================================
# 6. MESSAGE REPORT
# ============================================================

def create_cyberguard_report(message, result):

    model_label = result["label"]
    model_score = result["score"] * 100

    categories = detect_indicator_categories(message)

    total_indicator_score = calculate_category_score(
        categories
    )

    combinations = detect_high_risk_combinations(
        message
    )

    # Recommendation

    if "Prize scam requesting payment" in combinations:

        recommendation = (
            "This message mentions a prize and requests payment. "
            "Do not pay any fee to claim an unexpected prize."
        )

    elif "Credential Request" in categories:

        recommendation = (
            "This message may request sensitive information. "
            "Never share your passwords, OTPs, PINs, or CVV."
        )

    elif "Financial Request" in categories:

        recommendation = (
            "This message involves a financial activity. "
            "Verify the recipient and payment request through "
            "an official channel."
        )

    elif "Suspicious Action" in categories:

        recommendation = (
            "Avoid clicking unknown links or entering sensitive "
            "information on unverified websites."
        )

    else:

        recommendation = (
            "Remain cautious with unexpected messages and requests."
        )

    # Final risk calculation

    if model_label == "phishing":

        risk_score = round(
            (model_score * 0.6)
            + (total_indicator_score * 0.4),
            2
        )

        status = "Potential Phishing Threat"

    elif total_indicator_score >= 20:

        risk_score = total_indicator_score

        if total_indicator_score >= 40:
            status = "Suspicious Content Detected"
        else:
            status = "Potentially Suspicious Content"

    else:

        risk_score = total_indicator_score

        status = "No Immediate Threat Detected"

    # Risk level

    if risk_score >= 75:
        risk_level = "High Risk"

    elif risk_score >= 20:
        risk_level = "Medium Risk"

    else:
        risk_level = "Low Risk"

    return {

        "message": message,

        "status": status,

        "risk_level": risk_level,

        "risk_score": round(
            risk_score,
            2
        ),

        "model_prediction": model_label,

        "model_confidence": round(
            model_score,
            2
        ),

        "indicator_score": total_indicator_score,

        "high_risk_combinations": combinations,

        "detected_categories": categories,

        "recommendation": recommendation
    }


# ============================================================
# 7. URL ANALYZER
# ============================================================

def analyze_url(url):

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "http://" + url

    parsed = urlparse(url)

    extracted = tldextract.extract(
        parsed.netloc
    )

    domain = extracted.domain
    suffix = extracted.suffix

    registered_domain = (
        f"{domain}.{suffix}"
        if suffix
        else domain
    )

    subdomain = extracted.subdomain

    full_domain = parsed.hostname or ""

    suspicious_keywords = [

        "login",
        "verify",
        "account",
        "password",
        "update",
        "secure",
        "signin",
        "confirm",
        "bank",
        "wallet",
        "recover"
    ]

    features = {

        "uses_https":
            parsed.scheme == "https",

        "url_length":
            len(url),

        "domain_length":
            len(registered_domain),

        "subdomain_count":
            len(
                subdomain.split(".")
            )
            if subdomain
            else 0,

        "has_ip_address":
            bool(
                re.match(
                    r"^\d{1,3}(\.\d{1,3}){3}$",
                    full_domain
                )
            ),

        "has_at_symbol":
            "@" in url,

        "has_many_hyphens":
            domain.count("-") > 2,

        "has_punycode":
            "xn--" in full_domain.lower(),

        "has_encoded_chars":
            "%" in url,

        "dot_count":
            url.count("."),

        "path_depth":
            len([
                part
                for part in parsed.path.split("/")
                if part
            ]),

        "has_suspicious_extension":
            parsed.path.lower().endswith(
                (
                    ".exe",
                    ".scr",
                    ".zip",
                    ".rar"
                )
            ),

        "suspicious_keywords":
            [
                word
                for word in suspicious_keywords
                if word in url.lower()
            ]
    }

    return features


# ============================================================
# 8. URL INDICATORS
# ============================================================

def detect_url_indicators(url):

    features = analyze_url(url)

    indicators = []

    if features["has_ip_address"]:
        indicators.append(
            "IP address used instead of domain"
        )

    if features["has_at_symbol"]:
        indicators.append(
            "@ symbol in URL"
        )

    if features["has_many_hyphens"]:
        indicators.append(
            "Multiple hyphens in domain"
        )

    if features["has_punycode"]:
        indicators.append(
            "Punycode domain detected"
        )

    if features["has_encoded_chars"]:
        indicators.append(
            "Encoded characters in URL"
        )

    if not features["uses_https"]:
        indicators.append(
            "No HTTPS"
        )

    if features["suspicious_keywords"]:
        indicators.append(
            "Suspicious keywords: "
            + ", ".join(
                features["suspicious_keywords"]
            )
        )

    if features["has_suspicious_extension"]:
        indicators.append(
            "Suspicious file extension"
        )

    if features["subdomain_count"] >= 2:
        indicators.append(
            "Multiple subdomains"
        )

    if features["url_length"] > 100:
        indicators.append(
            "Unusually long URL"
        )

    return indicators


# ============================================================
# 9. BRAND IMPERSONATION
# ============================================================

def detect_brand_impersonation(url):

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "http://" + url

    parsed = urlparse(url)

    extracted = tldextract.extract(
        parsed.netloc
    )

    registered_domain = (
        f"{extracted.domain}.{extracted.suffix}"
        if extracted.suffix
        else extracted.domain
    )

    full_domain = parsed.hostname or ""

    brands = [

        "paypal",
        "amazon",
        "google",
        "microsoft",
        "apple",
        "netflix",
        "instagram",
        "facebook",
        "whatsapp",
        "bank"
    ]

    detected = []

    for brand in brands:

        if brand in full_domain.lower():

            if not registered_domain.lower().startswith(
                brand + "."
            ):

                detected.append(brand)

    return detected


# ============================================================
# 10. URL RISK SCORE
# ============================================================

def calculate_url_risk(url):

    features = analyze_url(url)

    impersonated_brands = detect_brand_impersonation(
        url
    )

    score = 0
    reasons = []

    if features["has_ip_address"]:

        score += 30

        reasons.append(
            "IP address used instead of domain"
        )

    if features["has_at_symbol"]:

        score += 25

        reasons.append(
            "@ symbol in URL"
        )

    if features["has_many_hyphens"]:

        score += 10

        reasons.append(
            "Multiple hyphens in domain"
        )

    if features["has_punycode"]:

        score += 25

        reasons.append(
            "Punycode domain detected"
        )

    if features["has_encoded_chars"]:

        score += 10

        reasons.append(
            "Encoded characters in URL"
        )

    if not features["uses_https"]:

        score += 10

        reasons.append(
            "No HTTPS"
        )

    if features["suspicious_keywords"]:

        score += min(
            len(
                features["suspicious_keywords"]
            ) * 5,
            15
        )

        reasons.append(
            "Suspicious keywords: "
            + ", ".join(
                features["suspicious_keywords"]
            )
        )

    if features["has_suspicious_extension"]:

        score += 20

        reasons.append(
            "Suspicious file extension"
        )

    if features["subdomain_count"] >= 2:

        score += 10

        reasons.append(
            "Multiple subdomains"
        )

    if features["url_length"] > 100:

        score += 10

        reasons.append(
            "Unusually long URL"
        )

    if impersonated_brands:

        score += 35

        reasons.append(
            "Possible brand impersonation: "
            + ", ".join(
                impersonated_brands
            )
        )

    score = min(
        score,
        100
    )

    if score >= 75:
        risk_level = "High Risk"

    elif score >= 30:
        risk_level = "Medium Risk"

    else:
        risk_level = "Low Risk"

    return {

        "url": url,

        "risk_score": score,

        "risk_level": risk_level,

        "reasons": reasons,

        "possible_impersonated_brands":
            impersonated_brands
    }


# ============================================================
# 11. URL REPORT
# ============================================================

def create_url_report(url):

    result = calculate_url_risk(url)

    report = {

        "url":
            result["url"],

        "status": (
            "Potentially Suspicious URL"
            if result["risk_score"] >= 30
            else
            "No Immediate URL Threat Detected"
        ),

        "risk_level":
            result["risk_level"],

        "risk_score":
            result["risk_score"],

        "possible_impersonated_brands":
            result[
                "possible_impersonated_brands"
            ],

        "detected_indicators":
            result["reasons"]
    }

    if result[
        "possible_impersonated_brands"
    ]:

        brands = ", ".join(
            result[
                "possible_impersonated_brands"
            ]
        )

        report["recommendation"] = (

            f"The URL may be impersonating {brands}. "
            "Verify the domain through the organization's "
            "official website before entering sensitive information."
        )

    elif result["risk_score"] >= 30:

        report["recommendation"] = (

            "This URL contains suspicious characteristics. "
            "Avoid entering passwords, OTPs, payment information, "
            "or other sensitive data unless the destination is verified."
        )

    else:

        report["recommendation"] = (

            "No major suspicious URL indicators were detected. "
            "Still verify the destination before entering sensitive information."
        )

    return report


# ============================================================
# 12. URL EXTRACTION
# ============================================================

def extract_urls(message):

    url_pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(
        url_pattern,
        message
    )

    cleaned_urls = []

    for url in urls:

        url = url.rstrip(
            ".,!?;:)"
        )

        cleaned_urls.append(url)

    return cleaned_urls


# ============================================================
# 13. COMBINED CYBERGUARD ANALYSIS
# ============================================================

def analyze_message_and_urls(message):

    model_result = classifier(message)[0]

    message_report = create_cyberguard_report(
        message,
        model_result
    )

    urls = extract_urls(message)

    url_reports = []

    for url in urls:

        url_report = create_url_report(
            url
        )

        url_reports.append(
            url_report
        )

    return {

        "message_report":
            message_report,

        "url_reports":
            url_reports
    }


# ============================================================
# CYBERGUARD ENGINE READY
# ============================================================

print()
print("=" * 60)
print("CYBERGUARD ENGINE READY")
print("=" * 60)



# ============================================================
# QR CODE PHISHING ANALYSIS
# ============================================================

import cv2


def decode_qr_image_file(filename):
    image = cv2.imread(filename)

    if image is None:
        return None

    detector = cv2.QRCodeDetector()

    data, points, _ = detector.detectAndDecode(image)

    if data:
        return data.strip()

    return None


def classify_qr_payload(data):
    if not data:
        return "No Data"

    data = data.strip()

    # URL
    if re.match(r"^https?://", data, re.IGNORECASE):
        return "URL"

    # UPI
    if re.match(r"^upi://pay\?", data, re.IGNORECASE):
        return "UPI"

    # EMAIL
    # Examples:
    # account@example.com
    # account@example.com?subject=Hello&body=Test
    # mailto:account@example.com?subject=Hello&body=Test
    email_pattern = (
        r"^(?:mailto:)?"
        r"[^@\s]+@[^@\s]+\.[^@\s]+"
        r"(?:\?.*)?$"
    )

    if re.match(email_pattern, data, re.IGNORECASE):
        return "EMAIL"

    # PHONE
    phone_pattern = r"^(?:tel:)?\+?[0-9][0-9() \-]{6,}$"

    if re.match(phone_pattern, data, re.IGNORECASE):
        return "PHONE"

    # Everything else
    return "TEXT"




def analyze_qr_payload(decoded_data):
    if not decoded_data:
        return None

    payload_type = classify_qr_payload(decoded_data)

    if payload_type == "URL":

        result = create_url_report(decoded_data)

    elif payload_type == "UPI":

        result = calculate_upi_risk(decoded_data)

    elif payload_type == "EMAIL":

        result = calculate_email_qr_risk(decoded_data)

    elif payload_type == "TEXT":

        model_result = classifier(decoded_data)[0]

        result = create_cyberguard_report(
            decoded_data,
            model_result
        )

    elif payload_type == "PHONE":

        result = {
            "status": "Phone QR Payload Detected",
            "payload": decoded_data,
            "recommendation": (
                "Verify the phone number before calling."
            )
        }

    else:

        result = {
            "status": "Unable to analyze QR payload",
            "payload": decoded_data
        }

    return {
        "payload": decoded_data,
        "payload_type": payload_type,
        "analysis": result
    }





def scan_qr_file(filename):
    decoded_data = decode_qr_image_file(filename)

    if not decoded_data:
        return {
            "status": "No QR code detected",
            "payload": None,
            "payload_type": None,
            "analysis": None
        }

    return analyze_qr_payload(decoded_data)



# ============================================================
# UPI QR ANALYSIS
# ============================================================

from urllib.parse import urlparse, parse_qs, unquote


def analyze_upi_qr(data):
    parsed = urlparse(data)

    params = parse_qs(parsed.query)

    def get_param(name):
        value = params.get(name, [""])[0]
        return unquote(value)

    return {
        "upi_id": get_param("pa"),
        "payee_name": get_param("pn"),
        "amount": get_param("am"),
        "currency": get_param("cu"),
        "transaction_note": get_param("tn")
    }


def calculate_upi_risk(data):
    details = analyze_upi_qr(data)

    score = 0
    reasons = []

    upi_id = details["upi_id"]
    payee_name = details["payee_name"]
    amount = details["amount"]
    currency = details["currency"]

    if not upi_id:
        score += 30
        reasons.append("Missing UPI payment address")

    if not payee_name:
        score += 10
        reasons.append("Missing payee name")

    if amount:
        try:
            amount_value = float(amount)

            if amount_value > 10000:
                score += 10
                reasons.append(
                    "High payment amount specified"
                )

        except ValueError:
            score += 15
            reasons.append(
                "Invalid payment amount"
            )

    if currency and currency.upper() != "INR":
        score += 20
        reasons.append(
            f"Unexpected currency: {currency}"
        )

    if upi_id:

        suspicious_terms = [
            "verify",
            "refund",
            "reward",
            "prize",
            "support",
            "security",
            "urgent",
            "claim"
        ]

        matched_terms = [
            term
            for term in suspicious_terms
            if term in upi_id.lower()
        ]

        if matched_terms:
            score += 20
            reasons.append(
                "Suspicious terms in UPI ID: "
                + ", ".join(matched_terms)
            )

    score = min(score, 100)

    if score >= 75:
        risk_level = "High Risk"
    elif score >= 30:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    return {
        "upi_details": details,
        "risk_score": score,
        "risk_level": risk_level,
        "detected_indicators": reasons
    }


# ============================================================
# UPDATED QR PAYLOAD ANALYZER
# ============================================================



def analyze_email_qr(data):
    """
    Parse an email QR payload into:
    email, subject, and body.
    """

    if not data:
        return {
            "email": "",
            "subject": "",
            "body": ""
        }

    data = data.strip()

    # Remove mailto: prefix if present
    if data.lower().startswith("mailto:"):
        data = data[7:]

    # Separate email address and query parameters
    if "?" in data:
        email, query = data.split("?", 1)
    else:
        email = data
        query = ""

    email = unquote(email).strip()

    params = parse_qs(query)

    subject = unquote(
        params.get("subject", [""])[0]
    )

    body = unquote(
        params.get("body", [""])[0]
    )

    return {
        "email": email,
        "subject": subject,
        "body": body
    }



def calculate_email_qr_risk(data):
    details = analyze_email_qr(data)

    score = 0
    reasons = []

    email = details["email"]
    subject = details["subject"]
    body = details["body"]

    # ========================================================
    # EMAIL ADDRESS
    # ========================================================

    if not email:
        score += 30
        reasons.append("Missing email address")

    elif not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ):
        score += 25
        reasons.append("Invalid email address format")

    # ========================================================
    # SUSPICIOUS EMAIL ADDRESS
    # ========================================================

    if email:

        local_part = email.split("@")[0].lower()

        suspicious_email_terms = [
            "urgent",
            "alert",
            "refund",
            "winner",
            "prize",
            "claim",
            "security",
            "support"
        ]

        matched_terms = [
            term
            for term in suspicious_email_terms
            if term in local_part
        ]

        if matched_terms:
            score += 5

            reasons.append(
                "Suspicious terms in email address: "
                + ", ".join(matched_terms)
            )

    # ========================================================
    # SUBJECT ANALYSIS
    # ========================================================

    subject_text = subject.lower()

    urgency_terms = [
        "urgent",
        "immediately",
        "suspended",
        "action required",
        "account locked",
        "security alert"
    ]

    matched_subject_terms = [
        term
        for term in urgency_terms
        if term in subject_text
    ]

    if matched_subject_terms:

        score += 15

        reasons.append(
            "Urgency or threat indicators in email subject: "
            + ", ".join(matched_subject_terms)
        )

    # ========================================================
    # BODY ANALYSIS
    # ========================================================

    body_text = body.lower()

    credential_patterns = [
        "enter your password",
        "provide your password",
        "password",
        "otp",
        "one time password",
        "pin",
        "cvv",
        "credit card number",
        "debit card number"
    ]

    matched_body_terms = []

    for term in credential_patterns:

        if term in body_text:

            # Avoid double-counting password
            if term == "password" and (
                "enter your password" in body_text
                or "provide your password" in body_text
            ):
                continue

            matched_body_terms.append(term)

    if matched_body_terms:

        score += 25

        reasons.append(
            "Sensitive-information request in email body: "
            + ", ".join(matched_body_terms)
        )

    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = min(score, 100)

    if score >= 75:
        risk_level = "High Risk"

    elif score >= 30:
        risk_level = "Medium Risk"

    else:
        risk_level = "Low Risk"

    return {
        "email_details": details,
        "risk_score": score,
        "risk_level": risk_level,
        "detected_indicators": reasons
    }




# ============================================================
# FRAUDULENT WEBSITE ANALYZER
# ============================================================

def analyze_fraudulent_website(url):

    url_report = create_url_report(url)

    score = url_report["risk_score"]

    indicators = list(
        url_report.get(
            "detected_indicators",
            []
        )
    )

    brands = list(
        url_report.get(
            "possible_impersonated_brands",
            []
        )
    )

    website_indicators = []

    try:

        features = analyze_url(url)

        website_keywords = [
            "login",
            "signin",
            "sign-in",
            "verify",
            "verification",
            "account",
            "secure",
            "security",
            "update",
            "payment",
            "wallet",
            "bank",
            "password",
            "credential",
            "otp",
            "confirm"
        ]

        matched_keywords = [
            word
            for word in website_keywords
            if word in url.lower()
        ]

        if matched_keywords:

            website_indicators.append(
                "Website URL contains sensitive-action keywords: "
                + ", ".join(matched_keywords)
            )

        if features.get("subdomain_count", 0) >= 2:

            website_indicators.append(
                "Website uses multiple subdomains"
            )

        if features.get("has_ip_address"):

            website_indicators.append(
                "Website uses an IP address instead of a domain name"
            )

        if features.get("has_punycode"):

            website_indicators.append(
                "Website uses a Punycode domain that may represent a lookalike domain"
            )

        if not features.get("uses_https"):

            website_indicators.append(
                "Website does not use HTTPS"
            )

    except Exception:

        website_indicators.append(
            "Website analysis could not evaluate all URL features"
        )

    for indicator in website_indicators:

        if indicator not in indicators:

            indicators.append(indicator)

    if brands:

        website_indicators.append(
            "Possible impersonation of: "
            + ", ".join(brands)
        )

    if score >= 75:

        website_status = (
            "Potentially Fraudulent Website"
        )

    elif score >= 30:

        website_status = (
            "Suspicious Website"
        )

    else:

        website_status = (
            "No Immediate Website Threat Detected"
        )

    if score >= 75:

        recommendation = (
            "Do not enter passwords, OTPs, payment details, "
            "or other sensitive information on this website. "
            "Verify the organization's official domain independently."
        )

    elif score >= 30:

        recommendation = (
            "This website contains suspicious characteristics. "
            "Verify the domain and organization independently "
            "before entering sensitive information."
        )

    else:

        recommendation = (
            "No major fraudulent-website indicators were detected. "
            "Still verify the website before entering sensitive information."
        )

    return {

        "url": url,

        "status": website_status,

        "risk_level": url_report["risk_level"],

        "risk_score": score,

        "possible_impersonated_brands": brands,

        "detected_indicators": indicators,

        "website_indicators": website_indicators,

        "recommendation": recommendation
    }
