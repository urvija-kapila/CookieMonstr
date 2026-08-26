const OWASP_URLS = {
  A01: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  A02: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  A05: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  A07: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
};

const owasp = (id, name) => ({
  id,
  name,
  url: OWASP_URLS[id.slice(0, 3)]
});

const cwe = (id, name) => ({
  id,
  name,
  url: `https://cwe.mitre.org/data/definitions/${id.replace('CWE-', '')}.html`
});

export const FINDING_MAPPINGS = {
  missing_httponly: {
    owasp: owasp('A05:2021', 'Security Misconfiguration'),
    cwe: cwe('CWE-1004', "Sensitive Cookie Without 'HttpOnly' Flag"),
    attack_scenario: 'An XSS payload can read this cookie through document.cookie and send it to an attacker-controlled server.'
  },
  missing_secure: {
    owasp: owasp('A07:2021', 'Identification and Authentication Failures'),
    cwe: cwe('CWE-614', "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
    attack_scenario: 'If HTTP traffic is intercepted, this cookie can be captured and replayed by an attacker.'
  },
  samesite_missing: {
    owasp: owasp('A01:2021', 'Broken Access Control'),
    cwe: cwe('CWE-352', 'Cross-Site Request Forgery (CSRF)'),
    attack_scenario: 'A malicious site can cause the browser to send this cookie with a forged cross-site request.'
  },
  samesite_none_without_secure: {
    owasp: owasp('A05:2021', 'Security Misconfiguration'),
    cwe: cwe('CWE-352', 'Cross-Site Request Forgery (CSRF)'),
    attack_scenario: 'SameSite=None without Secure is an invalid security configuration and can weaken intended cross-site protections.'
  },
  sensitive_cookie_without_secure: {
    owasp: owasp('A07:2021', 'Identification and Authentication Failures'),
    cwe: cwe('CWE-614', "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
    attack_scenario: 'An attacker with network access can steal this session or authentication cookie and impersonate the user.'
  },
  broad_domain: {
    owasp: owasp('A05:2021', 'Security Misconfiguration'),
    cwe: cwe('CWE-732', 'Incorrect Permission Assignment for Critical Resource'),
    attack_scenario: 'A compromised subdomain may be able to read or overwrite this broadly scoped cookie.'
  },
  long_lived_session: {
    owasp: owasp('A07:2021', 'Identification and Authentication Failures'),
    cwe: cwe('CWE-613', 'Insufficient Session Expiration'),
    attack_scenario: 'A stolen session cookie remains useful for a longer window when its expiration is unnecessarily distant.'
  },
  api_key_exposed: {
    owasp: owasp('A02:2021', 'Cryptographic Failures'),
    cwe: cwe('CWE-922', 'Insecure Storage of Sensitive Information'),
    attack_scenario: 'Any script running on the origin can read this API key from browser storage and reuse it.'
  },
  jwt_token_exposed: {
    owasp: owasp('A07:2021', 'Identification and Authentication Failures'),
    cwe: cwe('CWE-922', 'Insecure Storage of Sensitive Information'),
    attack_scenario: 'An XSS payload can steal this browser-readable token and use it to impersonate the user.'
  },
  password_in_storage: {
    owasp: owasp('A02:2021', 'Cryptographic Failures'),
    cwe: cwe('CWE-256', 'Plaintext Storage of a Password'),
    attack_scenario: 'Any JavaScript with access to this origin can read the stored password directly.'
  },
  email_exposed: {
    owasp: owasp('A02:2021', 'Cryptographic Failures'),
    cwe: cwe('CWE-922', 'Insecure Storage of Sensitive Information'),
    attack_scenario: 'An XSS payload or other script on the origin can harvest this personal identifier.'
  },
  credit_card_exposed: {
    owasp: owasp('A02:2021', 'Cryptographic Failures'),
    cwe: cwe('CWE-922', 'Insecure Storage of Sensitive Information'),
    attack_scenario: 'A compromised page script can directly collect this payment data from browser storage.'
  },
  ssn_exposed: {
    owasp: owasp('A02:2021', 'Cryptographic Failures'),
    cwe: cwe('CWE-922', 'Insecure Storage of Sensitive Information'),
    attack_scenario: 'A compromised page script can collect this sensitive identity data from browser storage.'
  },
  session_id_exposed: {
    owasp: owasp('A07:2021', 'Identification and Authentication Failures'),
    cwe: cwe('CWE-922', 'Insecure Storage of Sensitive Information'),
    attack_scenario: 'An XSS payload can steal this session identifier and use it for session hijacking.'
  },
  private_key_exposed: {
    owasp: owasp('A02:2021', 'Cryptographic Failures'),
    cwe: cwe('CWE-922', 'Insecure Storage of Sensitive Information'),
    attack_scenario: 'Exposure of a private key can allow an attacker to decrypt data or impersonate its owner.'
  },
  oauth_token_exposed: {
    owasp: owasp('A07:2021', 'Identification and Authentication Failures'),
    cwe: cwe('CWE-922', 'Insecure Storage of Sensitive Information'),
    attack_scenario: 'A stolen OAuth token can be replayed to access the user account or connected service.'
  }
};

export function enrichFinding(finding) {
  const mapping = FINDING_MAPPINGS[finding.id];
  if (!mapping) {
    return finding;
  }

  return {
    ...finding,
    owasp: mapping.owasp,
    cwe: mapping.cwe,
    attack_scenario: mapping.attack_scenario
  };
}
