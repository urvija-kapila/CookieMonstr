function isLikelySessionCookie(cookie) {
  const sessionKeywords = [
    "session",
    "sess",
    "auth",
    "token",
    "jwt",
    "sid",
    "uid",
    "user",
    "login",
    "csrf"
  ];

  return sessionKeywords.some(keyword =>
    cookie.name.toLowerCase().includes(keyword)
  );
}

function isLongLived(cookie) {
  if (!cookie.expirationDate) return false;

  const now = Date.now() / 1000;

  const sixMonths = 180 * 24 * 60 * 60;

  return (cookie.expirationDate - now) > sixMonths;
}

export const COOKIE_RULES = [
  {
    id: "missing_httponly",
    severity: "HIGH",

    test: (cookie) => !cookie.httpOnly,

    title: "Missing HttpOnly flag",

    explanation:
      "This cookie can be accessed by JavaScript. An XSS attack could steal it.",

    fix:
      "Set the HttpOnly attribute when issuing this cookie."
  },

  {
    id: "missing_secure",
    severity: "HIGH",

    test: (cookie) =>
      !cookie.secure &&
      isLikelySessionCookie(cookie),

    title: "Missing Secure flag",

    explanation:
      "Sensitive cookies should only travel over HTTPS.",

    fix:
      "Set the Secure attribute."
  },

  {
    id: "samesite_missing",
    severity: "MEDIUM",

    test: (cookie) =>
      !cookie.sameSite ||
      cookie.sameSite === "unspecified",

    title: "SameSite attribute not explicitly set",

    explanation:
      "Explicit SameSite protection helps defend against CSRF.",

    fix:
      "Use SameSite=Lax or SameSite=Strict."
  },

  {
    id: "samesite_none_without_secure",
    severity: "HIGH",

    test: (cookie) =>
        cookie.sameSite === "no_restriction" && !cookie.secure,

    title: "SameSite=None without Secure",

    explanation:
        "Cookies using SameSite=None must also use the Secure flag.",

    fix:
        "Enable Secure whenever SameSite=None is used."
  },

  {
    id: "sensitive_cookie_without_secure",
    severity: "HIGH",

    test: (cookie) =>
        isLikelySessionCookie(cookie) &&
        !cookie.secure,

    title: "Sensitive cookie is not Secure",

    explanation:
        "Authentication and session cookies should always use the Secure flag.",

    fix:
        "Mark this cookie as Secure."
  },

  {
    id: "broad_domain",

    severity: "LOW",

    test: (cookie) =>
        cookie.domain.startsWith("."),

    title: "Broad domain scope",

    explanation:
        "This cookie is available to all subdomains.",

    fix:
        "Restrict the cookie domain when possible."
  },

  {
    id: "long_lived_session",

    severity: "MEDIUM",

    test: (cookie) =>
        isLikelySessionCookie(cookie) &&
        isLongLived(cookie),

    title: "Long-lived authentication cookie",

    explanation:
        "Authentication cookies should expire as soon as practical.",

    fix:
        "Reduce the cookie lifetime."
  }
];