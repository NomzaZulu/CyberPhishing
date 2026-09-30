import streamlit as st

from cyberphishing_engine import (
    analyze_message_and_urls,
    scan_qr_file,
    analyze_fraudulent_website
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberGuard",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ CyberGuard")

st.subheader(
    "AI-Powered Cyber Threat, Phishing & "
    "Digital Impersonation Detection"
)

st.write(
    "Analyze emails, SMS, social-media messages, "
    "suspicious URLs, fraudulent websites, and QR codes "
    "for potential cyber threats."
)

st.divider()


# ============================================================
# MESSAGE / URL SCANNER
# ============================================================

st.header("📩 Message & URL Scanner")

message = st.text_area(
    "Enter a message to analyze",
    placeholder=(
        "Paste an email, SMS, social-media message, "
        "or suspicious message here..."
    ),
    height=180
)

if st.button(
    "🔍 Scan Message",
    type="primary",
    use_container_width=True
):

    if not message.strip():

        st.warning(
            "Please enter a message before scanning."
        )

    else:

        with st.spinner(
            "CyberGuard is analyzing the message..."
        ):

            try:

                result = analyze_message_and_urls(message)

                message_report = result["message_report"]
                url_reports = result["url_reports"]

                st.divider()

                st.header("🛡️ CyberGuard Threat Report")

                # ------------------------------------------------
                # MESSAGE SUMMARY
                # ------------------------------------------------

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.metric(
                        "Status",
                        message_report["status"]
                    )

                with col2:

                    st.metric(
                        "Risk Level",
                        message_report["risk_level"]
                    )

                with col3:

                    st.metric(
                        "Risk Score",
                        f'{message_report["risk_score"]} / 100'
                    )

                # ------------------------------------------------
                # THREAT INDICATORS
                # ------------------------------------------------

                st.subheader(
                    "⚠️ Detected Threat Indicators"
                )

                categories = message_report.get(
                    "detected_categories",
                    {}
                )

                if categories:

                    for category, indicators in categories.items():

                        st.markdown(
                            f"### ⚠️ {category}"
                        )

                        for indicator in indicators:

                            st.write(
                                f"• `{indicator}`"
                            )

                else:

                    st.success(
                        "No suspicious message indicators detected."
                    )

                # ------------------------------------------------
                # URL ANALYSIS
                # ------------------------------------------------

                if url_reports:

                    st.divider()

                    st.header("🔗 URL Analysis")

                    for url_report in url_reports:

                        st.code(
                            url_report["url"],
                            language=None
                        )

                        url_col1, url_col2, url_col3 = st.columns(3)

                        with url_col1:

                            st.metric(
                                "Status",
                                url_report["status"]
                            )

                        with url_col2:

                            st.metric(
                                "Risk Level",
                                url_report["risk_level"]
                            )

                        with url_col3:

                            st.metric(
                                "Risk Score",
                                f'{url_report["risk_score"]} / 100'
                            )

                        brands = url_report.get(
                            "possible_impersonated_brands",
                            []
                        )

                        if brands:

                            st.warning(
                                "⚠️ Possible Brand Impersonation: "
                                + ", ".join(brands)
                            )

                        indicators = url_report.get(
                            "detected_indicators",
                            []
                        )

                        if indicators:

                            st.markdown(
                                "**Detected URL Indicators:**"
                            )

                            for indicator in indicators:

                                st.write(
                                    f"• {indicator}"
                                )

                        st.info(
                            url_report["recommendation"]
                        )

                # ------------------------------------------------
                # MESSAGE RECOMMENDATION
                # ------------------------------------------------

                st.divider()

                st.subheader("💡 Recommendation")

                st.info(
                    message_report["recommendation"]
                )

            except Exception as e:

                st.error(
                    "An error occurred during analysis."
                )

                st.exception(e)


# ============================================================
# QR CODE SCANNER
# ============================================================

st.divider()

st.header("📷 QR Code Scanner")

st.write(
    "Upload a QR code image. CyberGuard will decode the QR "
    "payload and analyze it for potential phishing threats."
)

qr_file = st.file_uploader(
    "Upload QR Code Image",
    type=["png", "jpg", "jpeg"],
    key="qr_uploader"
)


if qr_file is not None:

    # --------------------------------------------------------
    # SHOW UPLOADED QR
    # --------------------------------------------------------

    st.image(
        qr_file,
        caption="Uploaded QR Code",
        width=250
    )

    # --------------------------------------------------------
    # SCAN BUTTON
    # --------------------------------------------------------

    if st.button(
        "🔍 Scan QR Code",
        type="primary",
        use_container_width=True,
        key="scan_qr_button"
    ):

        try:

            temp_filename = "uploaded_qr.png"

            with open(temp_filename, "wb") as f:

                f.write(qr_file.getbuffer())

            # ------------------------------------------------
            # RUN QR ANALYSIS
            # ------------------------------------------------

            with st.spinner(
                "CyberGuard is decoding and analyzing the QR code..."
            ):

                qr_result = scan_qr_file(
                    temp_filename
                )

            # ------------------------------------------------
            # NO QR DETECTED
            # ------------------------------------------------

            if qr_result["payload"] is None:

                st.error(
                    "No QR code could be detected in the image."
                )

            else:

                payload = qr_result["payload"]
                payload_type = qr_result["payload_type"]
                analysis = qr_result["analysis"]

                st.divider()

                st.header(
                    "🛡️ QR Threat Report"
                )

                # ------------------------------------------------
                # DECODED PAYLOAD
                # ------------------------------------------------

                st.subheader(
                    "📦 Decoded QR Payload"
                )

                st.code(
                    payload,
                    language=None
                )

                st.metric(
                    "Payload Type",
                    payload_type
                )

                st.divider()

                # =================================================
                # URL QR
                # =================================================

                if payload_type == "URL":

                    st.subheader(
                        "🔗 URL Analysis"
                    )

                    col1, col2, col3 = st.columns(3)

                    with col1:

                        st.metric(
                            "Status",
                            analysis["status"]
                        )

                    with col2:

                        st.metric(
                            "Risk Level",
                            analysis["risk_level"]
                        )

                    with col3:

                        st.metric(
                            "Risk Score",
                            f'{analysis["risk_score"]} / 100'
                        )

                    brands = analysis.get(
                        "possible_impersonated_brands",
                        []
                    )

                    if brands:

                        st.warning(
                            "⚠️ Possible Brand Impersonation: "
                            + ", ".join(brands)
                        )

                    indicators = analysis.get(
                        "detected_indicators",
                        []
                    )

                    if indicators:

                        st.markdown(
                            "**Detected URL Indicators:**"
                        )

                        for indicator in indicators:

                            st.write(
                                f"• {indicator}"
                            )

                    st.info(
                        analysis["recommendation"]
                    )

                # =================================================
                # UPI QR
                # =================================================

                elif payload_type == "UPI":

                    st.subheader(
                        "💳 UPI Payment Analysis"
                    )

                    col1, col2, col3 = st.columns(3)

                    with col1:

                        st.metric(
                            "Status",
                            "UPI Payment QR"
                        )

                    with col2:

                        st.metric(
                            "Risk Level",
                            analysis["risk_level"]
                        )

                    with col3:

                        st.metric(
                            "Risk Score",
                            f'{analysis["risk_score"]} / 100'
                        )

                    st.subheader(
                        "💳 UPI Details"
                    )

                    upi_details = analysis.get(
                        "upi_details",
                        {}
                    )

                    upi_col1, upi_col2 = st.columns(2)

                    with upi_col1:

                        st.write("**UPI ID:**")

                        st.code(
                            upi_details.get(
                                "upi_id",
                                "Not provided"
                            )
                        )

                        st.write("**Payee Name:**")

                        st.write(
                            upi_details.get(
                                "payee_name",
                                "Not provided"
                            )
                        )

                        st.write("**Currency:**")

                        st.write(
                            upi_details.get(
                                "currency",
                                "Not specified"
                            )
                        )

                    with upi_col2:

                        st.write("**Amount:**")

                        st.write(
                            upi_details.get(
                                "amount",
                                "Not specified"
                            )
                        )

                        st.write("**Transaction Note:**")

                        st.write(
                            upi_details.get(
                                "transaction_note",
                                "None"
                            )
                        )

                    indicators = analysis.get(
                        "detected_indicators",
                        []
                    )

                    if indicators:

                        st.warning(
                            "⚠️ Detected UPI Indicators"
                        )

                        for indicator in indicators:

                            st.write(
                                f"• {indicator}"
                            )

                    else:

                        st.success(
                            "No suspicious UPI indicators detected."
                        )

                # =================================================
                # TEXT QR
                # =================================================

                elif payload_type == "TEXT":

                    st.subheader(
                        "📝 Message Analysis"
                    )

                    col1, col2, col3 = st.columns(3)

                    with col1:

                        st.metric(
                            "Status",
                            analysis["status"]
                        )

                    with col2:

                        st.metric(
                            "Risk Level",
                            analysis["risk_level"]
                        )

                    with col3:

                        st.metric(
                            "Risk Score",
                            f'{analysis["risk_score"]} / 100'
                        )

                    categories = analysis.get(
                        "detected_categories",
                        {}
                    )

                    if categories:

                        st.subheader(
                            "⚠️ Detected Threat Indicators"
                        )

                        for category, indicators in categories.items():

                            st.markdown(
                                f"### ⚠️ {category}"
                            )

                            for indicator in indicators:

                                st.write(
                                    f"• `{indicator}`"
                                )

                    else:

                        st.success(
                            "No suspicious message indicators detected."
                        )

                    if "recommendation" in analysis:

                        st.info(
                            analysis["recommendation"]
                        )

                # =================================================
                # EMAIL QR
                # =================================================

                elif payload_type == "EMAIL":

                    st.subheader(
                        "📧 Email QR Analysis"
                    )

                    col1, col2, col3 = st.columns(3)

                    with col1:

                        st.metric(
                            "Status",
                            analysis.get(
                                "status",
                                "Email QR Payload Detected"
                            )
                        )

                    with col2:

                        st.metric(
                            "Risk Level",
                            analysis.get(
                                "risk_level",
                                "Unknown"
                            )
                        )

                    with col3:

                        st.metric(
                            "Risk Score",
                            f'{analysis.get("risk_score", 0)} / 100'
                        )

                    email_details = analysis.get(
                        "email_details",
                        {}
                    )

                    if email_details:

                        st.subheader(
                            "📧 Email Details"
                        )

                        email_col1, email_col2 = st.columns(2)

                        with email_col1:

                            st.write(
                                "**Email Address:**"
                            )

                            st.code(
                                email_details.get(
                                    "email",
                                    "Not provided"
                                )
                            )

                            st.write(
                                "**Subject:**"
                            )

                            st.write(
                                email_details.get(
                                    "subject",
                                    "No subject"
                                )
                            )

                        with email_col2:

                            st.write(
                                "**Body:**"
                            )

                            st.write(
                                email_details.get(
                                    "body",
                                    "No body"
                                )
                            )

                    indicators = analysis.get(
                        "detected_indicators",
                        []
                    )

                    if indicators:

                        st.warning(
                            "⚠️ Detected Email Threat Indicators"
                        )

                        for indicator in indicators:

                            st.write(
                                f"• {indicator}"
                            )

                    else:

                        st.success(
                            "No suspicious email indicators detected."
                        )

                # =================================================
                # PHONE QR
                # =================================================

                elif payload_type == "PHONE":

                    st.subheader(
                        "📞 Phone QR Payload"
                    )

                    st.info(
                        analysis.get(
                            "status",
                            "Phone QR Payload Detected"
                        )
                    )

                    st.code(
                        payload,
                        language=None
                    )

                    if "recommendation" in analysis:

                        st.info(
                            analysis["recommendation"]
                        )

                # =================================================
                # UNKNOWN
                # =================================================

                else:

                    st.warning(
                        "This QR payload type is not currently "
                        "supported for detailed analysis."
                    )

                    st.code(
                        payload,
                        language=None
                    )

        except Exception as e:

            st.error(
                "An error occurred while scanning the QR code."
            )

            st.exception(e)


# ============================================================
# FRAUDULENT WEBSITE SCANNER
# ============================================================

st.divider()

st.header("🌐 Fraudulent Website Scanner")

st.write(
    "Enter a website URL. CyberGuard will analyze the domain "
    "for suspicious characteristics, possible impersonation, "
    "and other fraudulent-website indicators."
)

website_url = st.text_input(
    "Enter Website URL",
    placeholder="https://example.com",
    key="website_url_input"
)

if st.button(
    "🔍 Analyze Website",
    type="primary",
    use_container_width=True,
    key="analyze_website_button"
):

    if not website_url.strip():

        st.warning(
            "Please enter a website URL before analyzing."
        )

    else:

        with st.spinner(
            "CyberGuard is analyzing the website..."
        ):

            try:

                website_result = analyze_fraudulent_website(
                    website_url.strip()
                )

                st.divider()

                st.header(
                    "🛡️ Website Threat Report"
                )

                # ------------------------------------------------
                # SUMMARY
                # ------------------------------------------------

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.metric(
                        "Status",
                        website_result["status"]
                    )

                with col2:

                    st.metric(
                        "Risk Level",
                        website_result["risk_level"]
                    )

                with col3:

                    st.metric(
                        "Risk Score",
                        f'{website_result["risk_score"]} / 100'
                    )

                # ------------------------------------------------
                # ANALYZED URL
                # ------------------------------------------------

                st.subheader(
                    "🔗 Analyzed Website"
                )

                st.code(
                    website_result["url"],
                    language=None
                )

                # ------------------------------------------------
                # BRAND IMPERSONATION
                # ------------------------------------------------

                brands = website_result.get(
                    "possible_impersonated_brands",
                    []
                )

                if brands:

                    st.subheader(
                        "⚠️ Possible Brand Impersonation"
                    )

                    st.warning(
                        "Possible impersonated brand(s): "
                        + ", ".join(brands)
                    )

                # ------------------------------------------------
                # WEBSITE INDICATORS
                # ------------------------------------------------

                website_indicators = website_result.get(
                    "website_indicators",
                    []
                )

                if website_indicators:

                    st.subheader(
                        "⚠️ Website Indicators"
                    )

                    for indicator in website_indicators:

                        st.write(
                            f"• {indicator}"
                        )

                # ------------------------------------------------
                # ALL DETECTED INDICATORS
                # ------------------------------------------------

                indicators = website_result.get(
                    "detected_indicators",
                    []
                )

                if indicators:

                    st.subheader(
                        "🔎 Detected Threat Indicators"
                    )

                    for indicator in indicators:

                        st.write(
                            f"• {indicator}"
                        )

                else:

                    st.success(
                        "No suspicious website indicators detected."
                    )

                # ------------------------------------------------
                # RECOMMENDATION
                # ------------------------------------------------

                st.subheader(
                    "💡 Recommendation"
                )

                st.info(
                    website_result["recommendation"]
                )

            except Exception as e:

                st.error(
                    "An error occurred during website analysis."
                )

                st.exception(e)


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberGuard Prototype — AI-assisted cyber threat detection. "
    "Risk scores are decision-support signals and are not "
    "guaranteed proof of malicious activity."
)
