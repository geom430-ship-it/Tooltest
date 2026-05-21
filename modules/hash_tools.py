"""
Hash Tools Module
Hash identification, generation, and cracking utilities
"""
import hashlib
import re
import hmac
import base64
import os

# Hash patterns for identification
HASH_PATTERNS = {
    "MD5": (r"^[a-f0-9]{32}$", 32),
    "SHA1": (r"^[a-f0-9]{40}$", 40),
    "SHA224": (r"^[a-f0-9]{56}$", 56),
    "SHA256": (r"^[a-f0-9]{64}$", 64),
    "SHA384": (r"^[a-f0-9]{96}$", 96),
    "SHA512": (r"^[a-f0-9]{128}$", 128),
    "SHA3-224": (r"^[a-f0-9]{56}$", 56),
    "SHA3-256": (r"^[a-f0-9]{64}$", 64),
    "SHA3-512": (r"^[a-f0-9]{128}$", 128),
    "RIPEMD160": (r"^[a-f0-9]{40}$", 40),
    "Whirlpool": (r"^[a-f0-9]{128}$", 128),
    "MySQL41": (r"^\*[A-F0-9]{40}$", 41),
    "MySQL3": (r"^[a-f0-9]{16}$", 16),
    "bcrypt": (r"^\$2[ayb]\$.{56}$", 60),
    "MD5-Crypt": (r"^\$1\$.{8}\$.{22}$", None),
    "SHA512-Crypt": (r"^\$6\$.{8,}\$.{86}$", None),
    "SHA256-Crypt": (r"^\$5\$.{8,}\$.{43}$", None),
    "Django-PBKDF2": (r"^pbkdf2_sha256\$", None),
    "Django-Bcrypt": (r"^bcrypt\$\$2", None),
    "WordPress": (r"^\$P\$.{31}$", 34),
    "Joomla": (r"^[a-f0-9]{32}:[a-zA-Z0-9]{32}$", None),
    "NTLM": (r"^[A-F0-9]{32}$", 32),
    "LM": (r"^[A-F0-9]{32}$", 32),
    "NTLMv2": (r"^[A-Fa-f0-9]{32}$", 32),
    "Base64": (r"^[A-Za-z0-9+/]+=*$", None),
    "MD4": (r"^[a-f0-9]{32}$", 32),
    "CRC32": (r"^[a-f0-9]{8}$", 8),
    "Adler32": (r"^[a-f0-9]{8}$", 8),
}

COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "admin123", "root",
    "toor", "pass", "letmein", "qwerty", "monkey", "1234567890",
    "abc123", "master", "superman", "dragon", "baseball", "football",
    "iloveyou", "shadow", "sunshine", "princess", "welcome",
    "login", "hello", "passw0rd", "test", "guest", "changeme",
    "secret", "666666", "111111", "654321", "7654321",
    "1234", "12345", "123456789", "1234567", "12345678",
    "password1", "Password1", "Password!", "P@ssword",
    "P@ssw0rd", "admin@123", "Admin@123", "administrator",
    "root123", "toor123", "mysql", "oracle", "postgres",
]


def identify_hash(hash_string):
    """Identify the type of hash"""
    hash_string = hash_string.strip()
    possible_types = []

    for hash_type, (pattern, length) in HASH_PATTERNS.items():
        if re.match(pattern, hash_string, re.IGNORECASE):
            if length is None or len(hash_string) == length:
                possible_types.append(hash_type)

    return possible_types


def generate_hash(text, algorithm="md5"):
    """Generate hash of text"""
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3_256": hashlib.sha3_256,
        "sha3_512": hashlib.sha3_512,
        "blake2b": hashlib.blake2b,
        "blake2s": hashlib.blake2s,
    }

    if algorithm.lower() not in algorithms:
        return None

    h = algorithms[algorithm.lower()](text.encode())
    return h.hexdigest()


def crack_hash(hash_string, wordlist=None, callback=None):
    """Try to crack a hash using wordlist"""
    hash_types = identify_hash(hash_string)

    if callback:
        callback({"type": "info", "message": f"🔓 Attempting to crack hash: {hash_string[:32]}..."})
        if hash_types:
            callback({"type": "info", "message": f"  Possible types: {', '.join(hash_types)}"})

    passwords = wordlist if wordlist else COMMON_PASSWORDS

    # Add variations
    extended = passwords.copy()
    for p in passwords[:20]:
        extended.extend([p + "!", p + "123", p + "1", p.capitalize(), p.upper()])

    for password in extended:
        # Try each hash type
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            try:
                h = generate_hash(password, algo)
                if h and h.lower() == hash_string.lower():
                    if callback:
                        callback({"type": "vuln", "message": f"🎉 CRACKED! {hash_string[:20]}... = '{password}' ({algo.upper()})"})
                    return {"cracked": True, "password": password, "algorithm": algo}
            except Exception:
                pass

        # Try MySQL hash
        if hash_string.startswith("*"):
            mysql_hash = "*" + hashlib.sha1(hashlib.sha1(password.encode()).digest()).hexdigest().upper()
            if mysql_hash == hash_string.upper():
                if callback:
                    callback({"type": "vuln", "message": f"🎉 CRACKED MySQL hash! = '{password}'"})
                return {"cracked": True, "password": password, "algorithm": "MySQL41"}

    if callback:
        callback({"type": "info", "message": f"❌ Hash not cracked with {len(extended)} passwords"})
        callback({"type": "info", "message": "  💡 Try a larger wordlist (rockyou.txt, etc.)"})

    return {"cracked": False}


def analyze_password_strength(password, callback=None):
    """Analyze password strength"""
    score = 0
    issues = []
    suggestions = []

    # Length check
    if len(password) < 8:
        issues.append("Too short (< 8 chars)")
    elif len(password) < 12:
        score += 1
        suggestions.append("Use 12+ characters for better security")
    elif len(password) < 16:
        score += 2
    else:
        score += 3

    # Character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>?/~`]', password))

    if has_lower: score += 1
    else: issues.append("No lowercase letters")

    if has_upper: score += 1
    else: suggestions.append("Add uppercase letters")

    if has_digit: score += 1
    else: suggestions.append("Add numbers")

    if has_special: score += 2
    else: suggestions.append("Add special characters (!@#$%)")

    # Common password check
    if password.lower() in [p.lower() for p in COMMON_PASSWORDS]:
        issues.append("Common password - easily guessable!")
        score = max(0, score - 5)

    # Sequential characters
    sequences = ['abcdef', 'qwerty', '123456', 'zxcvbn', 'password']
    for seq in sequences:
        if seq in password.lower():
            issues.append(f"Contains common sequence: '{seq}'")
            score = max(0, score - 2)

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters (e.g., 'aaa')")
        score = max(0, score - 1)

    # Entropy calculation
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 32

    import math
    entropy = len(password) * math.log2(max(charset_size, 1))

    # Final rating
    if score >= 7:
        rating = "Very Strong 💪"
        color = "success"
    elif score >= 5:
        rating = "Strong 👍"
        color = "primary"
    elif score >= 3:
        rating = "Medium ⚠️"
        color = "warning"
    elif score >= 1:
        rating = "Weak 😟"
        color = "danger"
    else:
        rating = "Very Weak 💀"
        color = "danger"

    result = {
        "password": password,
        "score": score,
        "max_score": 9,
        "rating": rating,
        "color": color,
        "length": len(password),
        "entropy_bits": round(entropy, 1),
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_special": has_special,
        "issues": issues,
        "suggestions": suggestions
    }

    if callback:
        callback({"type": "found", "message": f"Password: {password}"})
        callback({"type": "info", "message": f"Rating: {rating} | Score: {score}/9 | Entropy: {entropy:.1f} bits"})
        for issue in issues:
            callback({"type": "warn", "message": f"⚠️  {issue}"})
        for sug in suggestions:
            callback({"type": "info", "message": f"💡 {sug}"})

    return result


def generate_password(length=16, use_upper=True, use_digits=True, use_special=True):
    """Generate a secure random password"""
    import string as str_module

    chars = str_module.ascii_lowercase
    required = [str_module.ascii_lowercase[os.urandom(1)[0] % 26]]

    if use_upper:
        chars += str_module.ascii_uppercase
        required.append(str_module.ascii_uppercase[os.urandom(1)[0] % 26])
    if use_digits:
        chars += str_module.digits
        required.append(str_module.digits[os.urandom(1)[0] % 10])
    if use_special:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        chars += special_chars
        required.append(special_chars[os.urandom(1)[0] % len(special_chars)])

    remaining_length = length - len(required)
    password_chars = required + [chars[os.urandom(1)[0] % len(chars)] for _ in range(remaining_length)]

    # Shuffle
    for i in range(len(password_chars) - 1, 0, -1):
        j = os.urandom(1)[0] % (i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return ''.join(password_chars)


def hash_file(filepath, algorithm="sha256"):
    """Calculate hash of a file"""
    try:
        h = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"
