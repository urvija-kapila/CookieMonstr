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
  }
];