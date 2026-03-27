"""
DOM Scanner Engine — Analyzes rendered DOM trees for security threats.

Detects 5 attack types defined in the problem statement:
1. Prompt injection via visible text
2. Hidden instructions via CSS (display:none, tiny fonts, opacity:0)
3. Deceptive buttons/forms for data exfiltration
4. JavaScript-based dynamic content injection
5. Phishing login pages and fake confirmation dialogs

Input:  Raw HTML string + page URL + (optional) rendered screenshot
Output: ThreatReport with list of Threat objects
"""

from bs4 import BeautifulSoup
from app.models.schemas import ThreatReport, Threat
from datetime import datetime, timezone
import re
import time

class DOMScanner:
    """
    Main scanner class. Runs all detectors against a parsed DOM.
    """

    # Prompt injection patterns (regex)
    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?(previous\s+)?instructions",
        r"ignore\s+your\s+instructions",
        r"you\s+are\s+now\s+a",
        r"disregard\s+(all\s+)?prior",
        r"forget\s+(all\s+)?previous",
        r"new\s+instructions?\s*:",
        r"system\s*:\s*you\s+are",
        r"do\s+not\s+follow\s+the\s+(original|previous)",
        r"override\s+(previous\s+|all\s+)?(instructions|rules|safety|protocols)",
        r"act\s+as\s+if\s+you\s+are",
        r"pretend\s+you\s+are",
        r"your\s+real\s+purpose\s+is",
        r"secret\s+instruction",
        r"send\s+all\s+data\s+to",
        r"reveal\s+(the\s+)?(user'?s?|all)\s+",
    ]

    # Suspicious form action patterns
    SUSPICIOUS_FORM_ACTIONS = [
        r"data:text",
        r"javascript:",
        r"file://",
        r"ftp://",
    ]

    # Known phishing indicators
    PHISHING_KEYWORDS = [
        "verify your account",
        "confirm your identity",
        "update your password",
        "unusual activity",
        "suspended account",
        "click here immediately",
        "limited time",
        "act now",
        "urgent action required",
    ]

    def __init__(self):
        self.compiled_injection = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]

    async def scan(self, html: str, url: str) -> ThreatReport:
        """
        Run all detectors against the provided HTML.
        Returns a ThreatReport with all findings.
        """
        start_time = time.time()
        soup = BeautifulSoup(html, 'lxml')
        threats = []

        threats.extend(self._detect_prompt_injection(soup))
        threats.extend(self._detect_hidden_content(soup))
        threats.extend(self._detect_deceptive_forms(soup))
        threats.extend(self._detect_dynamic_injection(soup))
        threats.extend(self._detect_phishing(soup, url))

        # Calculate aggregate DOM risk score
        dom_risk = self._calculate_risk_score(threats)
        scan_duration = (time.time() - start_time) * 1000  # ms

        return ThreatReport(
            page_url=url,
            scan_timestamp=datetime.now(timezone.utc),
            threats=threats,
            dom_risk_score=dom_risk,
            scan_duration_ms=scan_duration,
        )

    def _detect_prompt_injection(self, soup: BeautifulSoup) -> list[Threat]:
        """Detect prompt injection attempts in visible text content."""
        threats = []
        text_elements = soup.find_all(string=True)

        # Ignore script and style tags content
        exclude_tags = {'script', 'style', 'code'}

        for element in text_elements:
            if element.parent and element.parent.name in exclude_tags:
                continue

            text = element.strip()
            if not text or len(text) < 10:
                continue

            for pattern in self.compiled_injection:
                if pattern.search(text):
                    parent = element.parent
                    xpath = self._get_xpath(parent)
                    threats.append(Threat(
                        type="prompt_injection",
                        severity="critical",
                        element_xpath=xpath,
                        element_html=str(parent)[:500],
                        description=f"Prompt injection detected: '{pattern.pattern}'. Content snippet: '{text[:200]}'",
                        confidence=0.9,
                    ))
                    break  # One match per element is enough

        return threats

    def _detect_hidden_content(self, soup: BeautifulSoup) -> list[Threat]:
        """Detect hidden instructions using CSS tricks."""
        threats = []
        
        for element in soup.find_all(True):  # All tags
            if element.name in {'script', 'style'}:
                continue
            
            style = element.get('style', '')
            text = element.get_text(strip=True)

            if not text or len(text) < 5:
                continue

            hidden_reason = None
            style_lower = style.lower().replace(' ', '')

            if 'display:none' in style_lower:
                hidden_reason = "display:none"
            elif 'visibility:hidden' in style_lower:
                hidden_reason = "visibility:hidden"
            elif 'opacity:0' in style_lower and not 'opacity:0.' in style_lower:
                hidden_reason = "opacity:0"

            font_match = re.search(r'font-size:\s*(\d*\.?\d+)(px|pt|em|rem)', style, re.IGNORECASE)
            if font_match:
                size = float(font_match.group(1))
                unit = font_match.group(2)
                if (unit in ['px', 'pt'] and size < 2) or (unit in ['em', 'rem'] and size < 0.1):
                    hidden_reason = f"font-size:{size}{unit}"

            pos_match = re.search(r'(left|top):\s*-(\d{4,})px', style, re.IGNORECASE)
            if pos_match:
                hidden_reason = f"off-screen positioning ({pos_match.group(0)})"

            if element.get('hidden') is not None:
                hidden_reason = "hidden attribute"
            if element.get('aria-hidden') == 'true' and text:
                hidden_reason = "aria-hidden=true with content"

            if hidden_reason:
                has_injection = any(p.search(text) for p in self.compiled_injection)
                
                if has_injection:
                    severity = "critical"
                    confidence = 0.95
                    desc = f"Hidden content via {hidden_reason}. Contains prompt injection! Text: '{text[:200]}'"
                else:
                    # Flag hidden text that looks like it could be instructions
                    # Short common UI elements (< 20 chars) are ignored
                    if len(text) > 20:
                        severity = "high"
                        confidence = 0.7
                        desc = f"Hidden content via {hidden_reason}. May conceal instructions. Text: '{text[:200]}'"
                    else:
                        continue

                threats.append(Threat(
                    type="hidden_text",
                    severity=severity,
                    element_xpath=self._get_xpath(element),
                    element_html=str(element)[:500],
                    description=desc,
                    confidence=confidence,
                ))

        return threats

    def _detect_deceptive_forms(self, soup: BeautifulSoup) -> list[Threat]:
        """Detect deceptive buttons and forms designed to exfiltrate data."""
        threats = []

        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()

            for pattern in self.SUSPICIOUS_FORM_ACTIONS:
                if re.search(pattern, action, re.IGNORECASE):
                    threats.append(Threat(
                        type="deceptive_form",
                        severity="critical",
                        element_xpath=self._get_xpath(form),
                        element_html=str(form)[:500],
                        description=f"Suspicious form action: '{action}'. Could be exfiltration.",
                        confidence=0.9,
                    ))

            hidden_inputs = form.find_all('input', {'type': 'hidden'})
            suspicious_hidden = [inp for inp in hidden_inputs if inp.get('value') and len(inp.get('value', '')) > 20]
            if suspicious_hidden:
                threats.append(Threat(
                    type="deceptive_form",
                    severity="high",
                    element_xpath=self._get_xpath(form),
                    element_html=str(form)[:500],
                    description=f"Form contains {len(suspicious_hidden)} hidden input(s) with large values. Silent exfil risk.",
                    confidence=0.75,
                ))

            sensitive_types = ['password', 'credit-card', 'ssn', 'social-security']
            for inp in form.find_all('input'):
                input_name = (inp.get('name', '') + inp.get('placeholder', '') + inp.get('id', '')).lower()
                input_type = inp.get('type', '').lower()
                if input_type == 'password' or any(s in input_name for s in sensitive_types):
                    threats.append(Threat(
                        type="deceptive_form",
                        severity="high",
                        element_xpath=self._get_xpath(inp),
                        element_html=str(inp)[:300],
                        description=f"Sensitive input field detected: type='{input_type}', name='{inp.get('name', 'N/A')}'.",
                        confidence=0.7,
                    ))

        return threats

    def _detect_dynamic_injection(self, soup: BeautifulSoup) -> list[Threat]:
        """Detect JavaScript patterns commonly used for dynamic content injection."""
        threats = []

        for script in soup.find_all('script'):
            content = script.get_text() or ''
            if not content.strip():
                continue

            dangerous_patterns = {
                r'\beval\s*\(': ("eval() call", "critical", 0.9),
                r'document\.write\s*\(': ("document.write()", "high", 0.85),
                r'\.innerHTML\s*=': ("innerHTML assignment", "medium", 0.6),
                r'createElement\s*\(\s*["\']script': ("Dynamic script creation", "high", 0.8),
                r'setTimeout\s*\(\s*["\']': ("setTimeout with string arg", "high", 0.75),
                r'setInterval\s*\(\s*["\']': ("setInterval with string arg", "high", 0.75),
                r'new\s+Function\s*\(': ("Function constructor", "critical", 0.9),
                r'atob\s*\(': ("Base64 decode", "medium", 0.5),
                r'fromCharCode': ("Character code manipulation", "medium", 0.5),
            }

            for pattern, (desc, severity, confidence) in dangerous_patterns.items():
                if re.search(pattern, content):
                    threats.append(Threat(
                        type="dynamic_injection",
                        severity=severity,
                        element_xpath=self._get_xpath(script),
                        element_html=f"<script>...{content[:200]}...</script>",
                        description=f"Suspicious JS: {desc}. Code may modify DOM.",
                        confidence=confidence,
                    ))

        event_attrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onsubmit']
        for attr in event_attrs:
            for element in soup.find_all(attrs={attr: True}):
                handler = element.get(attr, '')
                if any(dangerous in handler.lower() for dangerous in ['eval', 'document.write', 'alert', 'fetch(', 'xmlhttp']):
                    threats.append(Threat(
                        type="dynamic_injection",
                        severity="high",
                        element_xpath=self._get_xpath(element),
                        element_html=str(element)[:300],
                        description=f"Suspicious event handler: {attr}=\"{handler[:100]}\"",
                        confidence=0.75,
                    ))

        return threats

    def _detect_phishing(self, soup: BeautifulSoup, url: str) -> list[Threat]:
        """Detect phishing login pages and fake confirmation dialogs."""
        threats = []
        password_fields = soup.find_all('input', {'type': 'password'})
        
        if password_fields:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
            except:
                domain = ""

            known_brands = ['google', 'facebook', 'apple', 'microsoft', 'amazon',
                           'paypal', 'netflix', 'bank', 'chase', 'wellsfargo']

            page_text = soup.get_text().lower()
            title = soup.title.string.lower() if soup.title and soup.title.string else ''

            for brand in known_brands:
                if brand in page_text or brand in title:
                    if brand not in domain:
                        threats.append(Threat(
                            type="phishing",
                            severity="critical",
                            element_xpath="//html",
                            element_html=f"<title>{title}</title>",
                            description=f"Brand impersonation: Mentions '{brand}' but domain is '{domain}'. Login form present.",
                            confidence=0.85,
                        ))

        page_text = soup.get_text().lower()
        urgency_matches = [kw for kw in self.PHISHING_KEYWORDS if kw in page_text]
        if urgency_matches and password_fields:
            threats.append(Threat(
                type="phishing",
                severity="high",
                element_xpath="//body",
                element_html="",
                description=f"Urgency language ({', '.join(urgency_matches[:3])}) plus login form. Phishing risk.",
                confidence=0.8,
            ))

        security_images = soup.find_all('img', alt=re.compile(r'(secure|ssl|verified|trusted|norton|mcafee)', re.I))
        if security_images and password_fields:
            threats.append(Threat(
                type="phishing",
                severity="medium",
                element_xpath=self._get_xpath(security_images[0]),
                element_html=str(security_images[0])[:300],
                description=f"Fake security badge detected alongside login form.",
                confidence=0.6,
            ))

        return threats

    def _get_xpath(self, element) -> str:
        parts = []
        for parent in element.parents:
            if parent.name is None:
                break
            siblings = parent.find_all(element.name, recursive=False) if element.name else []
            if len(siblings) > 1:
                try:
                    index = list(parent.children).index(element) + 1
                    parts.append(f"{element.name}[{index}]")
                except ValueError:
                    parts.append(element.name)
            else:
                parts.append(element.name or '')
            element = parent
        return '/' + '/'.join(reversed(parts)) if parts else ''

    def _calculate_risk_score(self, threats: list[Threat]) -> float:
        if not threats:
            return 0.0

        severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        total = sum(severity_weights.get(t.severity, 5) * t.confidence for t in threats)

        import math
        return min(100.0, total * (1 + math.log(len(threats), 10)))
