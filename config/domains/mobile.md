# Mobile Application Security Domain

> **ID:** mobile-security  
> **Version:** 1.0.0  
> **Last Updated:** 2026-01-21

## Overview

Security domain for mobile application development covering iOS and Android platforms.
Focuses on secure storage, communication, authentication, and platform-specific vulnerabilities.

## Metadata

| Property | Value |
|----------|-------|
| **Languages** | Swift, Kotlin, Java, Dart, React Native, Flutter |
| **Platforms** | iOS, Android, Cross-platform |
| **Compliance** | GDPR, HIPAA, PCI-DSS |
| **Reference** | OWASP Mobile Top 10 2024 |

---

## Threat Categories

### 1. Insecure Data Storage (M2)

**STRIDE Category:** Information Disclosure

#### Threat: Plaintext Sensitive Data

- **CWE IDs:** CWE-312, CWE-922
- **OWASP Categories:** A02:2021
- **Severity:** HIGH
- **Likelihood:** HIGH

**Detection Patterns:**

```regex
# iOS - NSUserDefaults for sensitive data
NSUserDefaults.*password|token|key

# Android - SharedPreferences without encryption
getSharedPreferences.*MODE_PRIVATE.*password

# React Native - AsyncStorage
AsyncStorage\.setItem.*(?:password|token|secret)
```

**Mitigations:**

| Phase | Description |
|-------|-------------|
| Implementation | Use iOS Keychain / Android Keystore for secrets |
| Implementation | Use encrypted SharedPreferences (EncryptedSharedPreferences) |
| Implementation | Enable file-level encryption |

**Code Example:**

❌ **Insecure (Android/Kotlin):**
```kotlin
val prefs = getSharedPreferences("app", MODE_PRIVATE)
prefs.edit().putString("auth_token", token).apply()
```

✅ **Secure:**
```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val securePrefs = EncryptedSharedPreferences.create(
    context, "secure_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
securePrefs.edit().putString("auth_token", token).apply()
```

---

### 2. Insecure Communication (M3)

**STRIDE Category:** Information Disclosure, Tampering

#### Threat: Cleartext Traffic

- **CWE IDs:** CWE-319
- **OWASP Categories:** A02:2021
- **Severity:** HIGH
- **Likelihood:** MEDIUM

**Detection Patterns:**

```regex
# iOS - Allow arbitrary loads
NSAllowsArbitraryLoads.*true

# Android - Cleartext traffic
android:usesCleartextTraffic="true"

# HTTP URLs in code
http://(?!localhost|127\.0\.0\.1)
```

**Mitigations:**

| Phase | Description |
|-------|-------------|
| Architecture | Enforce TLS 1.2+ for all connections |
| Implementation | Implement certificate pinning |
| Testing | Monitor network traffic for cleartext |

---

### 3. Insecure Authentication (M4)

**STRIDE Category:** Spoofing

#### Threat: Weak Local Authentication

- **CWE IDs:** CWE-287, CWE-308
- **OWASP Categories:** A07:2021
- **Severity:** HIGH
- **Likelihood:** MEDIUM

**Detection Patterns:**

```regex
# iOS - Weak biometric policy
LAPolicy\.deviceOwnerAuthentication(?!WithBiometrics)

# Simple PIN storage
pin.*[=:].*\d{4}
```

**Mitigations:**

| Phase | Description |
|-------|-------------|
| Design | Use platform-native biometric APIs |
| Implementation | Combine biometrics with device-bound keys |
| Implementation | Implement proper session management |

---

### 4. Insufficient Cryptography (M5)

**STRIDE Category:** Information Disclosure

#### Threat: Weak Encryption

- **CWE IDs:** CWE-327, CWE-328
- **OWASP Categories:** A02:2021
- **Severity:** CRITICAL
- **Likelihood:** MEDIUM

**Detection Patterns:**

```regex
# Weak algorithms
DES|3DES|RC4|MD5|SHA1(?!-256)

# ECB mode
AES.*ECB

# Hardcoded keys
secretKey\s*=\s*["'][A-Za-z0-9+/=]{16,}["']
```

**Mitigations:**

| Phase | Description |
|-------|-------------|
| Design | Use AES-256-GCM for encryption |
| Implementation | Use platform key management (Keychain/Keystore) |
| Implementation | Never hardcode cryptographic keys |

---

### 5. Client Code Quality (M7)

**STRIDE Category:** Tampering

#### Threat: Code Injection via WebViews

- **CWE IDs:** CWE-749, CWE-79
- **OWASP Categories:** A03:2021
- **Severity:** HIGH
- **Likelihood:** MEDIUM

**Detection Patterns:**

```regex
# Android - JavaScript enabled without restrictions
setJavaScriptEnabled\(true\)(?!.*addJavascriptInterface.*@JavascriptInterface)

# iOS - Insecure WKWebView
WKWebView.*evaluateJavaScript
```

**Mitigations:**

| Phase | Description |
|-------|-------------|
| Implementation | Disable JavaScript if not needed |
| Implementation | Use `@JavascriptInterface` annotation (Android) |
| Implementation | Validate all URLs before loading |

---

### 6. Reverse Engineering (M9)

**STRIDE Category:** Information Disclosure

#### Threat: Lack of Obfuscation

- **CWE IDs:** CWE-798, CWE-200
- **OWASP Categories:** A09:2021
- **Severity:** MEDIUM
- **Likelihood:** HIGH

**Mitigations:**

| Phase | Description |
|-------|-------------|
| Build | Enable ProGuard/R8 for Android |
| Build | Use code obfuscation tools |
| Design | Don't store secrets in client code |

---

## Security Controls

### Biometric Authentication

- **Category:** Preventive
- **Implementation:** Use platform-native biometric APIs with fallback

### Certificate Pinning

- **Category:** Preventive
- **Implementation:** Pin server certificates or public keys

### Root/Jailbreak Detection

- **Category:** Detective
- **Implementation:** Detect compromised devices, implement graceful degradation

### App Transport Security (iOS) / Network Security Config (Android)

- **Category:** Preventive
- **Implementation:** Enforce HTTPS, pin certificates

---

## Testing Guidelines

### Static Analysis

| Tool | Platform | Purpose |
|------|----------|---------|
| MobSF | Both | Automated security analysis |
| Hopper/Ghidra | iOS | Binary analysis |
| JADX | Android | Decompilation |

### Dynamic Analysis

| Tool | Platform | Purpose |
|------|----------|---------|
| Frida | Both | Runtime manipulation |
| Objection | Both | Runtime exploration |
| Burp Suite | Both | Traffic interception |

### Test Cases

1. [ ] Test data storage encryption
2. [ ] Test certificate pinning bypass
3. [ ] Test biometric authentication bypass
4. [ ] Test for sensitive data in logs
5. [ ] Test backup data encryption
6. [ ] Test for hardcoded secrets
7. [ ] Test deep link handling
8. [ ] Test WebView security

---

## References

- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)
- [OWASP MASTG](https://owasp.org/www-project-mobile-app-security/)
- [Apple Security Guide](https://support.apple.com/guide/security/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
