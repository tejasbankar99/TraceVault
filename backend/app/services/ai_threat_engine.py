"""
ai_threat_engine.py
===================
Three-layer threat scoring engine for TraceVault:

  Layer 1: Rule-based engine  — fast, deterministic, weighted scoring
  Layer 2: ML classifier      — scikit-learn TF-IDF + Random Forest
  Layer 3: Google Gemini API  — LLM narrative analysis

Final score = weighted combination of all three layers.
"""

from __future__ import annotations

import json
import os
import pickle
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from google import genai
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class GeminiAnalysisResult:
    """Structured output from the Gemini LLM analysis layer."""
    threat_categories: list
    gemini_score: int
    urgency_indicators: list
    impersonation_analysis: dict
    social_engineering_patterns: list
    bec_indicators: list
    explanation: str
    recommended_actions: list
    confidence: str
    raw_response: dict = field(default_factory=dict)


@dataclass
class ThreatAnalysisResult:
    """Final aggregated threat analysis result from all three layers."""
    threat_score: int
    severity: str
    threat_categories: list
    rule_score: int
    ml_score: int
    gemini_score: int
    triggered_rules: list
    ai_explanation: str
    urgency_indicators: list
    impersonation_analysis: dict
    social_engineering_patterns: list
    bec_indicators: list
    shap_features: dict
    recommended_actions: list
    confidence: str


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AIThreatEngine:
    """
    Orchestrates all three analysis layers and produces a combined ThreatAnalysisResult.

    Usage::

        engine = AIThreatEngine()
        result = await engine.analyze(parsed_email, header_forensics, auth_result, iocs)
    """

    def __init__(self) -> None:
        self.gemini_client: Optional[genai.Client] = None
        self.ml_model: Optional[RandomForestClassifier] = None
        self.vectorizer: Optional[TfidfVectorizer] = None
        self._initialize_gemini()
        self._initialize_ml_model()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _initialize_gemini(self) -> None:
        """Initialize Gemini client from GOOGLE_API_KEY environment variable."""
        api_key = os.getenv("GOOGLE_API_KEY", "")
        if api_key and api_key not in ("", "your-gemini-api-key-from-ai.google.dev"):
            self.gemini_client = genai.Client(api_key=api_key)

    def _initialize_ml_model(self) -> None:
        """
        Load pre-trained model if it exists on disk; otherwise bootstrap a
        minimal default model trained on built-in phishing / benign samples.

        For production: train on PhishingCorpus / CEAS dataset and save the
        resulting .pkl files to /app/models/.
        """
        model_path = Path("/app/models/phishing_classifier.pkl")
        vectorizer_path = Path("/app/models/tfidf_vectorizer.pkl")

        if model_path.exists() and vectorizer_path.exists():
            with open(model_path, "rb") as f:
                self.ml_model = pickle.load(f)
            with open(vectorizer_path, "rb") as f:
                self.vectorizer = pickle.load(f)
        else:
            # Bootstrap with built-in samples so the engine is always ready.
            self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2))
            self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self._train_default_model()

    def _train_default_model(self) -> None:
        """
        Train a minimal default model on hard-coded phishing / benign samples.
        Persists the trained artefacts to /app/models/ for subsequent starts.
        """
        phishing_samples = [
            "Your account has been suspended. Click here to verify your identity immediately.",
            "Urgent: Your payment failed. Update your billing information now.",
            "You have won a prize. Click to claim your reward.",
            "Your account will be deleted in 24 hours. Verify now.",
            "Security alert: Unusual activity detected on your account.",
            "Your password expires today. Reset it immediately to avoid lockout.",
            "Congratulations! Your PayPal account has a pending transfer.",
            "Action required: Confirm your email address to avoid suspension.",
            "Your Netflix subscription failed. Update payment method.",
            "IRS Tax Refund: You are eligible for $500 refund. Click here.",
            "Your Microsoft account is at risk. Sign in to secure it.",
            "Click below to verify your bank account immediately.",
            "Invoice attached. Please process payment within 24 hours.",
            "Your login was attempted from an unknown location. Verify now.",
            "Final notice: Unpaid invoice. Pay now to avoid legal action.",
            "Verify your Apple ID or your account will be closed.",
            "HR Department: Please review and sign the attached document.",
            "IT Support: Your password will expire. Click to reset.",
            "Dear customer, your shipment is on hold. Pay customs fee.",
            "Account locked. Verify identity to restore access.",
        ]
        benign_samples = [
            "Thanks for your order. Your shipment is on its way.",
            "Meeting reminder for tomorrow at 3 PM.",
            "Your monthly newsletter is ready to read.",
            "Thank you for signing up for our service.",
            "Your invoice for last month is attached.",
            "Team update: We shipped new features this week.",
            "Happy birthday! Wishing you a great day.",
            "Your appointment is confirmed for next Monday.",
            "Welcome to our platform! Here are some tips to get started.",
            "Your subscription has been renewed successfully.",
            "Weekly report attached. Please review before Monday.",
            "Hi, just following up on our conversation yesterday.",
            "The conference call has been rescheduled to Friday.",
            "Your photo album is ready to view.",
            "New comment on your post.",
            "Your flight details are confirmed.",
            "Recipe of the week: Chicken Tikka Masala",
            "Job application received. We will be in touch.",
            "Your package has been delivered.",
            "Thank you for your feedback.",
        ]

        texts = phishing_samples + benign_samples
        labels = [1] * len(phishing_samples) + [0] * len(benign_samples)

        X = self.vectorizer.fit_transform(texts)
        self.ml_model.fit(X, labels)

        # Persist so future starts can load directly.
        try:
            os.makedirs("/app/models", exist_ok=True)
            with open("/app/models/phishing_classifier.pkl", "wb") as f:
                pickle.dump(self.ml_model, f)
            with open("/app/models/tfidf_vectorizer.pkl", "wb") as f:
                pickle.dump(self.vectorizer, f)
        except OSError:
            # Non-critical — model is already in memory.
            pass

    # ------------------------------------------------------------------
    # Layer 1: Rule-based scoring
    # ------------------------------------------------------------------

    def compute_rule_score(
        self,
        parsed_email,
        header_forensics,
        auth_result,
        iocs,
    ) -> tuple[int, list[str]]:
        """
        Deterministic rule-based scorer.

        Scoring breakdown
        -----------------
        Authentication failures:
          SPF fail / permerror  → +25
          SPF softfail          → +15
          DKIM fail             → +20
          DMARC fail            → +15
          All three fail bonus  → +10

        Header anomalies (per anomaly type):
          MISMATCH_FROM_RETURN_PATH → +20
          REPLY_HIJACKING           → +20
          TIMESTAMP_ANOMALY         → +15

        IOC-based:
          Lookalike domain (max 2×25=50)  → +25 each
          URL shortener (first hit)        → +15
          CRITICAL severity IOC            → +30 each

        Attachments:
          Dangerous extension              → +25 each

        Content:
          Urgency keyword count × 3 (max 15)
          Phishing keyword count × 5 (max 20)

        Cap: 100 points.

        Returns
        -------
        (score: int, triggered_rules: list[str])
        """
        score = 0
        triggered_rules: list[str] = []

        # --- Authentication checks ----------------------------------------
        if auth_result:
            if auth_result.spf_result in ("fail", "permerror"):
                score += 25
                triggered_rules.append("SPF authentication failed")
            elif auth_result.spf_result == "softfail":
                score += 15
                triggered_rules.append("SPF softfail detected")

            if auth_result.dkim_result == "fail":
                score += 20
                triggered_rules.append("DKIM signature verification failed")

            if auth_result.dmarc_result == "fail":
                score += 15
                triggered_rules.append("DMARC policy check failed")

            if (
                auth_result.spf_result in ("fail", "permerror")
                and auth_result.dkim_result == "fail"
                and auth_result.dmarc_result == "fail"
            ):
                score += 10
                triggered_rules.append("Complete authentication failure (SPF+DKIM+DMARC)")

        # --- Header anomalies ------------------------------------------------
        if header_forensics:
            for anomaly in (header_forensics.anomalies or []):
                if anomaly.anomaly_type == "MISMATCH_FROM_RETURN_PATH":
                    score += 20
                    triggered_rules.append("From/Return-Path domain mismatch detected")
                elif anomaly.anomaly_type == "REPLY_HIJACKING":
                    score += 20
                    triggered_rules.append("Reply-To domain mismatch (reply hijacking)")
                elif anomaly.anomaly_type == "TIMESTAMP_ANOMALY":
                    score += 15
                    triggered_rules.append("Suspicious timestamp anomaly in relay headers")

        # --- IOC-based scoring -----------------------------------------------
        lookalike_count = 0
        url_shortener_count = 0
        for ioc in (iocs or []):
            if getattr(ioc, "is_lookalike", False):
                lookalike_count += 1
                if lookalike_count <= 2:
                    score += 25
                    target = getattr(ioc, "lookalike_target", "unknown")
                    triggered_rules.append(f"Lookalike domain mimicking '{target}'")

            if getattr(ioc, "is_shortened_url", False):
                url_shortener_count += 1
                if url_shortener_count == 1:
                    score += 15
                    triggered_rules.append("URL shortener used (hides destination)")

            if getattr(ioc, "severity", "") == "CRITICAL":
                score += 30
                value = str(getattr(ioc, "ioc_value", ""))[:50]
                triggered_rules.append(f"High-severity IOC: {value}")

        # --- Attachment analysis ---------------------------------------------
        if parsed_email and getattr(parsed_email, "attachments", None):
            dangerous_exts = {
                ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".jar",
                ".scr", ".com", ".pif", ".hta", ".msi", ".reg", ".wsf",
                ".lnk",
            }
            for att in parsed_email.attachments:
                filename = getattr(att, "filename", "") or ""
                ext = os.path.splitext(filename)[1].lower()
                if ext in dangerous_exts:
                    score += 25
                    triggered_rules.append(f"Dangerous attachment type: {filename}")

        # --- Content analysis ------------------------------------------------
        body_text = ""
        if parsed_email:
            body_text = (
                (getattr(parsed_email, "body_text", "") or "")
                + " "
                + (getattr(parsed_email, "subject", "") or "")
            )
        body_lower = body_text.lower()

        from app.utils.constants import URGENCY_KEYWORDS, PHISHING_KEYWORDS

        urgency_count = sum(1 for kw in URGENCY_KEYWORDS if kw in body_lower)
        phishing_count = sum(1 for kw in PHISHING_KEYWORDS if kw in body_lower)

        urgency_score = min(urgency_count * 3, 15)
        phishing_score = min(phishing_count * 5, 20)
        score += urgency_score + phishing_score

        if urgency_count > 2:
            triggered_rules.append(
                f"High urgency language detected ({urgency_count} indicators)"
            )
        if phishing_count > 0:
            triggered_rules.append(
                f"Phishing language patterns detected ({phishing_count} indicators)"
            )

        return min(score, 100), triggered_rules

    # ------------------------------------------------------------------
    # Layer 2: ML classifier
    # ------------------------------------------------------------------

    def compute_ml_score(self, parsed_email) -> tuple[float, dict]:
        """
        Run TF-IDF + Random Forest classifier on the email body.

        Returns
        -------
        (probability_of_phishing: float, top_features: dict)
            probability_of_phishing is in [0.0, 1.0].
            top_features maps feature token → importance score (SHAP-lite).
        """
        try:
            body = ""
            if parsed_email:
                body = (
                    f"{getattr(parsed_email, 'subject', '') or ''} "
                    f"{getattr(parsed_email, 'body_text', '') or ''}"
                )

            if not body.strip() or self.ml_model is None or self.vectorizer is None:
                return 0.5, {}

            X = self.vectorizer.transform([body])
            proba = self.ml_model.predict_proba(X)[0]
            phishing_proba = float(proba[1]) if len(proba) > 1 else float(proba[0])

            # Lightweight SHAP-alternative: feature importance × presence in input.
            feature_names = self.vectorizer.get_feature_names_out()
            importances = self.ml_model.feature_importances_
            nonzero_indices = X.nonzero()[1]
            top_features = dict(
                sorted(
                    {
                        feature_names[i]: float(importances[i])
                        for i in nonzero_indices
                    }.items(),
                    key=lambda kv: kv[1],
                    reverse=True,
                )[:10]
            )

            return phishing_proba, top_features

        except Exception:
            return 0.5, {}

    # ------------------------------------------------------------------
    # Layer 3: Gemini LLM analysis
    # ------------------------------------------------------------------

    async def analyze_with_gemini(
        self,
        parsed_email,
        header_forensics,
        auth_result,
        iocs,
        rule_score: int,
    ) -> GeminiAnalysisResult:
        """
        Send a structured forensic prompt to Gemini 2.0 Flash and parse
        the JSON response into a GeminiAnalysisResult.

        Falls back gracefully when the Gemini client is unavailable.
        """
        if not self.gemini_client:
            return self._get_fallback_gemini_result(rule_score)

        # --- Sanitise / truncate inputs to prevent prompt injection ----------
        subject = (getattr(parsed_email, "subject", "") or "")[:200] if parsed_email else ""
        from_addr = (getattr(parsed_email, "from_addr", "") or "")[:100] if parsed_email else ""
        body = ""
        if parsed_email:
            raw_body = getattr(parsed_email, "body_text", "") or ""
            body = self._sanitize_for_llm(raw_body)[:3000]

        auth_summary = "Unknown"
        if auth_result:
            auth_summary = (
                f"SPF:{auth_result.spf_result} "
                f"DKIM:{auth_result.dkim_result} "
                f"DMARC:{auth_result.dmarc_result}"
            )

        anomalies_summary: list[str] = []
        if header_forensics:
            anomalies_summary = [
                a.description for a in (header_forensics.anomalies or [])[:5]
            ]

        ioc_summary = [
            f"{getattr(ioc, 'ioc_type', '')}:{str(getattr(ioc, 'ioc_value', ''))[:50]}"
            for ioc in (iocs or [])[:10]
        ]

        prompt = f"""You are a cybersecurity forensics analyst. Analyze this email for threats.

Email Data:
- From: {from_addr}
- Subject: {subject}
- Authentication: {auth_summary}
- Header Anomalies: {anomalies_summary}
- IOCs Found: {ioc_summary}
- Rule-Based Score: {rule_score}/100

Email Body (sanitized):
{body}

Respond ONLY with valid JSON matching this exact schema:
{{
  "threat_categories": ["one or more of: phishing, impersonation, bec, credential_theft, social_engineering, malware_delivery, financial_fraud, benign"],
  "gemini_score": <integer 0-100>,
  "urgency_indicators": ["list of urgency phrases found in the email"],
  "impersonation_analysis": {{
    "is_impersonating": <true/false>,
    "impersonated_entity": "<brand or person being impersonated, or null>",
    "technique": "<display name spoofing / domain lookalike / none>"
  }},
  "social_engineering_patterns": ["list of manipulation techniques detected"],
  "bec_indicators": ["business email compromise indicators if any"],
  "explanation": "<3-5 sentence forensic narrative explaining the threat assessment>",
  "recommended_actions": ["list of 4-5 specific security actions"],
  "confidence": "<high/medium/low>"
}}"""

        try:
            response = self.gemini_client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
            )

            # Strip potential markdown code fences around the JSON.
            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:]
            if text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]

            data = json.loads(text.strip())

            return GeminiAnalysisResult(
                threat_categories=data.get("threat_categories", ["benign"]),
                gemini_score=int(data.get("gemini_score", rule_score)),
                urgency_indicators=data.get("urgency_indicators", []),
                impersonation_analysis=data.get("impersonation_analysis", {}),
                social_engineering_patterns=data.get("social_engineering_patterns", []),
                bec_indicators=data.get("bec_indicators", []),
                explanation=data.get("explanation", ""),
                recommended_actions=data.get("recommended_actions", []),
                confidence=data.get("confidence", "medium"),
                raw_response=data,
            )

        except Exception as exc:
            return self._get_fallback_gemini_result(rule_score, str(exc))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_for_llm(text: str) -> str:
        """Strip HTML tags, collapse whitespace, return plain text."""
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    @staticmethod
    def _get_fallback_gemini_result(
        rule_score: int,
        error: str = "",
    ) -> GeminiAnalysisResult:
        """Return a rule-score-derived result when Gemini is unavailable."""
        if rule_score >= 60:
            categories = ["phishing", "social_engineering"]
            explanation = (
                "Rule-based analysis detected multiple threat indicators including "
                "authentication failures and suspicious content patterns. "
                "Gemini LLM analysis unavailable."
            )
        elif rule_score >= 40:
            categories = ["social_engineering"]
            explanation = (
                "Rule-based analysis detected moderate threat indicators. "
                "Manual review recommended."
            )
        else:
            categories = ["benign"]
            explanation = "No significant threat indicators detected by rule-based analysis."

        return GeminiAnalysisResult(
            threat_categories=categories,
            gemini_score=rule_score,
            urgency_indicators=[],
            impersonation_analysis={"is_impersonating": False},
            social_engineering_patterns=[],
            bec_indicators=[],
            explanation=explanation,
            recommended_actions=[
                "Review email carefully before clicking any links",
                "Verify sender identity through an alternative channel",
            ],
            confidence="low" if error else "medium",
            raw_response={"fallback": True, "error": error},
        )

    # ------------------------------------------------------------------
    # Main orchestrator
    # ------------------------------------------------------------------

    async def analyze(
        self,
        parsed_email,
        header_forensics,
        auth_result,
        iocs,
    ) -> ThreatAnalysisResult:
        """
        Run all three analysis layers and return a combined ThreatAnalysisResult.

        Weighting when Gemini is available:
          final = rule × 0.35 + ml × 0.35 + gemini × 0.30

        Weighting when Gemini is unavailable (confidence == 'low' and
        gemini_score falls back to rule_score):
          final = rule × 0.50 + ml × 0.50
        """
        # Layer 1 — Rules
        rule_score, triggered_rules = self.compute_rule_score(
            parsed_email, header_forensics, auth_result, iocs
        )

        # Layer 2 — ML
        ml_proba, shap_features = self.compute_ml_score(parsed_email)
        ml_score = int(ml_proba * 100)

        # Layer 3 — Gemini
        gemini_result = await self.analyze_with_gemini(
            parsed_email, header_forensics, auth_result, iocs, rule_score
        )

        # Weighted combination
        gemini_available = not (
            gemini_result.confidence == "low"
            and gemini_result.gemini_score == rule_score
        )
        if gemini_available:
            final_score = int(
                rule_score * 0.35 + ml_score * 0.35 + gemini_result.gemini_score * 0.30
            )
        else:
            final_score = int(rule_score * 0.50 + ml_score * 0.50)

        final_score = max(0, min(100, final_score))

        # Severity band
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MEDIUM"
        elif final_score >= 20:
            severity = "LOW"
        else:
            severity = "BENIGN"

        return ThreatAnalysisResult(
            threat_score=final_score,
            severity=severity,
            threat_categories=gemini_result.threat_categories,
            rule_score=rule_score,
            ml_score=ml_score,
            gemini_score=gemini_result.gemini_score,
            triggered_rules=triggered_rules,
            ai_explanation=gemini_result.explanation,
            urgency_indicators=gemini_result.urgency_indicators,
            impersonation_analysis=gemini_result.impersonation_analysis,
            social_engineering_patterns=gemini_result.social_engineering_patterns,
            bec_indicators=gemini_result.bec_indicators,
            shap_features=shap_features,
            recommended_actions=gemini_result.recommended_actions,
            confidence=gemini_result.confidence,
        )
