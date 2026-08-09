import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

# Constants inlined from backend/backend/dast_constants.py to avoid cross-package import errors
# (deepagents/ lives in backend/, but dast_constants is in backend/backend/)
TECH_SIGNATURES = {
    "Express.js":  [r"X-Powered-By.*Express", r"express"],
    "Flask":       [r"Werkzeug", r"flask"],
    "Django":      [r"django", r"csrfmiddlewaretoken"],
    "Laravel":     [r"laravel", r"X-Powered-By.*PHP"],
    "Spring":      [r"spring", r"X-Application-Context"],
    "Rails":       [r"X-Powered-By.*Phusion", r"rails"],
    "FastAPI":     [r"fastapi", r"openapi.json"],
    "Next.js":     [r"__NEXT_DATA__", r"_next/static"],
    "React":       [r"__react", r"react-root"],
    "Vue.js":      [r"__vue", r"vue-router"],
    "WordPress":   [r"wp-content", r"wp-login.php"],
    "Node.js":     [r"X-Powered-By.*Node"],
    "ASP.NET":     [r"X-Powered-By.*ASP.NET", r"__VIEWSTATE"],
    "PHP":         [r"X-Powered-By.*PHP", r"\.php"],
    "MySQL":       [r"mysql", r"You have an error in your SQL syntax"],
    "PostgreSQL":  [r"PostgreSQL", r"pg_"],
    "MongoDB":     [r"mongodb", r"MongoError"],
    "SQLite":      [r"sqlite", r"SQLite error"],
}
SQL_ERROR_SIGS = [
    r"You have an error in your SQL syntax",
    r"Warning.*mysql_",
    r"Unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"ORA-[0-9]+",
    r"PG::SyntaxError",
    r"SQLite.*Error",
    r"SQLSTATE\[42",
    r"syntax error at or near",
    r"invalid input syntax for type",
]
FILE_PARAM_KEYWORDS = ["file", "path", "dir", "document", "img", "image", "template",
                        "include", "require", "page", "view", "load", "read", "fetch"]
FORMAT_PARAM_KEYWORDS = ["format", "type", "ext", "content_type", "mime", "output",
                           "export", "render", "style", "theme", "layout"]

@dataclass
class EndpointProfile:
    url: str
    methods: set = field(default_factory=set)
    status_codes: set = field(default_factory=set)
    response_lengths: list = field(default_factory=list)
    params: set = field(default_factory=set)
    has_numeric_params: bool = False
    has_string_params: bool = False
    has_file_param: bool = False
    has_format_param: bool = False
    leaks_token: bool = False
    leaks_sensitive: bool = False
    
    def interest_score(self) -> int:
        score = 0
        if self.leaks_token: score += 10
        if self.leaks_sensitive: score += 5
        if self.has_numeric_params or self.has_string_params: score += 2
        if self.has_file_param: score += 3
        if self.has_format_param: score += 2
        return score

class AttackSurfaceIndex:
    """
    Vectorless RAG over observed HTTP behaviour.
    No embeddings, no external APIs — pure keyword/pattern extraction.
    """
    
    def __init__(self):
        self.endpoints: dict[str, EndpointProfile] = {}
        self.tokens_seen: dict[str, str] = {}   # token -> endpoint that leaked it
        self.error_signatures: list[str] = []   # SQL errors, stack traces, etc.
        self.confirmed_creds: list[tuple] = []  # (user, pwd, endpoint)
        self.detected_technologies: set[str] = set()

    def ingest_response(self, url: str, method: str, body: str,
                        status: int, response_body: str, headers: dict = None):
        """
        Extract structured knowledge from a raw HTTP response.
        No embeddings — just keyword extraction.
        """
        # Normalise URL to path + query keys (ignore values for grouping)
        parsed = urlparse(url)
        base_path = parsed.path
        
        profile = self.endpoints.setdefault(base_path, EndpointProfile(base_path))
        profile.methods.add(method)
        profile.status_codes.add(status)
        profile.response_lengths.append(len(response_body))
        
        # Parse params
        if parsed.query:
            qs = parse_qs(parsed.query)
            for k, v_list in qs.items():
                profile.params.add(k)
                if any(v.isdigit() for v in v_list):
                    profile.has_numeric_params = True
                else:
                    profile.has_string_params = True
                
                k_lower = k.lower()
                if any(kw in k_lower for kw in FILE_PARAM_KEYWORDS):
                    profile.has_file_param = True
                if any(kw in k_lower for kw in FORMAT_PARAM_KEYWORDS):
                    profile.has_format_param = True

        # Check body params if form/json
        if body and isinstance(body, str):
            try:
                import json
                parsed_body = json.loads(body)
                if isinstance(parsed_body, dict):
                    for k, v in parsed_body.items():
                        profile.params.add(k)
                        if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
                            profile.has_numeric_params = True
                        elif isinstance(v, str):
                            profile.has_string_params = True
            except:
                if "=" in body and "&" in body: # likely form data
                    qs = parse_qs(body)
                    for k, v_list in qs.items():
                        profile.params.add(k)
                        if any(v.isdigit() for v in v_list):
                            profile.has_numeric_params = True
                        else:
                            profile.has_string_params = True

        # Detect tech from headers & body
        header_str = str(headers or {})
        for tech, sigs in TECH_SIGNATURES.items():
            for sig in sigs:
                if re.search(sig, response_body, re.I) or re.search(sig, header_str, re.I):
                    self.detected_technologies.add(tech)

        # Detect tokens
        if re.search(r'"token"|"jwt"|"Bearer"', response_body, re.I):
            profile.leaks_token = True
            match = re.search(r'"(?:token|jwt)"\s*:\s*"([^"]+)"', response_body, re.I)
            if match:
                self.tokens_seen[base_path] = match.group(1)
        
        # Detect sensitive data
        if re.search(r'"password"|"hash"|"secret"', response_body, re.I):
            profile.leaks_sensitive = True
            
        # Detect errors
        for sig in SQL_ERROR_SIGS:
            if re.search(sig, response_body, re.I):
                sig_text = f"{base_path}: SQL error signature '{sig}' found"
                if sig_text not in self.error_signatures:
                    self.error_signatures.append(sig_text)

    def _detected_tech(self) -> str:
        return ", ".join(self.detected_technologies) if self.detected_technologies else "Unknown"

    def summarise_for_prompt(self) -> str:
        """
        Generate a structured text summary of what we know about the target.
        This is the vectorless RAG context injected into every Oracle prompt.
        """
        lines = [
            f"Target technology stack: {self._detected_tech()}",
            f"Endpoints observed: {len(self.endpoints)}",
            "",
            "High-value endpoints:",
        ]
        for url, profile in sorted(
            self.endpoints.items(),
            key=lambda x: x[1].interest_score(),
            reverse=True,
        )[:10]:
            methods_str = ", ".join(profile.methods)
            lines.append(f"  [{methods_str}] {url}")
            if profile.params:
                lines.append(f"    params: {', '.join(profile.params)}")
            if profile.leaks_token:
                lines.append(f"    ⚠ leaks token/JWT")
            if profile.leaks_sensitive:
                lines.append(f"    ⚠ leaks sensitive data")
        
        if self.error_signatures:
            lines.append("")
            lines.append("Error signatures observed (high value):")
            for sig in self.error_signatures[:5]:
                lines.append(f"  {sig}")
                
        if self.confirmed_creds:
            lines.append("")
            lines.append(f"Credentials obtained: {len(self.confirmed_creds)}")
            
        return "\n".join(lines)
