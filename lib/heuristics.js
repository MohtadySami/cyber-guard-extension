// Local, deterministic download heuristics. This module intentionally has no
// chrome.* usage or mutable global state so it can run in both Chrome and Node.

export const HEURISTIC_CONSTANTS = Object.freeze({
  points: Object.freeze({
    SCRIPT_EXTENSION: 35,
    EXECUTABLE_EXTENSION: 25,
    CONTAINER_EXTENSION: 10,
    MACRO_DOCUMENT: 15,
    DOUBLE_EXTENSION: 40,
    RTLO_CHARACTER: 50,
    TRAILING_SPACES_OR_DOTS: 20,
    MIME_MISMATCH: 30,
    INSECURE_HTTP: 10,
    IP_HOST: 20,
    SUSPICIOUS_TLD: 10,
    PUNYCODE_HOST: 15,
    LONG_REDIRECT_CHAIN_SHORT: 10,
    LONG_REDIRECT_CHAIN_LONG: 20,
  }),
  scriptExtensions: Object.freeze([
    "ps1", "vbs", "vbe", "js", "jse", "hta", "wsf", "wsh", "bat", "cmd", "lnk", "reg", "scr", "pif", "msc",
  ]),
  executableExtensions: Object.freeze([
    "exe", "msi", "dll", "jar", "com", "cpl", "msp", "appx", "msix",
  ]),
  containerExtensions: Object.freeze([
    "iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "cab",
  ]),
  macroDocumentExtensions: Object.freeze([
    "docm", "xlsm", "pptm", "dotm", "xlam",
  ]),
  documentMediaExtensions: Object.freeze([
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "txt", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "zip",
  ]),
  executableMimeTypes: Object.freeze([
    "application/x-msdownload",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdos-program",
    "application/java-archive",
  ]),
  suspiciousTlds: Object.freeze([
    "zip", "mov", "xyz", "top", "click", "work", "rest", "country", "gq", "tk", "ml", "cf", "ga",
  ]),
});

const SCRIPT_EXTENSIONS = new Set(HEURISTIC_CONSTANTS.scriptExtensions);
const EXECUTABLE_EXTENSIONS = new Set(HEURISTIC_CONSTANTS.executableExtensions);
const CONTAINER_EXTENSIONS = new Set(HEURISTIC_CONSTANTS.containerExtensions);
const MACRO_DOCUMENT_EXTENSIONS = new Set(HEURISTIC_CONSTANTS.macroDocumentExtensions);
const DOCUMENT_MEDIA_EXTENSIONS = new Set(HEURISTIC_CONSTANTS.documentMediaExtensions);
const EXECUTABLE_MIME_TYPES = new Set(HEURISTIC_CONSTANTS.executableMimeTypes);
const SUSPICIOUS_TLDS = new Set(HEURISTIC_CONSTANTS.suspiciousTlds);
const BIDI_CONTROL_PATTERN = /[\u202A-\u202E\u2066-\u2069]/u;

function asContext(ctx) {
  return ctx && typeof ctx === "object" ? ctx : {};
}

function makeResult(code, points, text) {
  return { code, points, text };
}

function getLastExtension(ctx) {
  const extensions = getExtensions(resolveFilename(ctx));
  return extensions.at(-1) || "";
}

function getUrl(ctx) {
  const safeCtx = asContext(ctx);
  return typeof safeCtx.finalUrl === "string" && safeCtx.finalUrl
    ? safeCtx.finalUrl
    : typeof safeCtx.url === "string"
      ? safeCtx.url
      : "";
}

function decodePathSegment(segment) {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function isIpv4(hostname) {
  const parts = hostname.split(".");
  return parts.length === 4 && parts.every((part) => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function isIpLiteral(hostname) {
  const unbracketed = hostname.replace(/^\[|\]$/g, "");
  return isIpv4(unbracketed) || unbracketed.includes(":");
}

/** Returns the final path segment, recognizing both Windows and URL separators. */
export function getBaseName(path) {
  if (typeof path !== "string") {
    return "";
  }

  const segments = path.split(/[\\/]/);
  return segments.at(-1) || "";
}

/** Returns lowercase file extensions in order, excluding a trailing empty extension. */
export function getExtensions(filename) {
  const baseName = getBaseName(filename);
  if (!baseName) {
    return [];
  }

  return baseName
    .split(".")
    .slice(1)
    .filter(Boolean)
    .map((extension) => extension.toLowerCase().trim());
}

/** Safely extracts a URL hostname, returning an empty string for invalid input. */
export function getHostname(url) {
  if (typeof url !== "string" || !url) {
    return "";
  }

  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/** Resolves the available filename, including a decoded URL-path fallback. */
export function resolveFilename(ctx) {
  const safeCtx = asContext(ctx);
  const explicitName = getBaseName(safeCtx.filename);
  if (explicitName) {
    return explicitName;
  }

  for (const candidateUrl of [safeCtx.finalUrl, safeCtx.url]) {
    if (typeof candidateUrl !== "string" || !candidateUrl) {
      continue;
    }

    try {
      const pathName = new URL(candidateUrl).pathname;
      const candidateName = decodePathSegment(getBaseName(pathName));
      if (candidateName) {
        return candidateName;
      }
    } catch {
      // Invalid URLs are ignored; heuristics must remain best-effort.
    }
  }

  return "";
}

export function checkScriptExtension(ctx) {
  const filename = resolveFilename(ctx);
  const extension = getLastExtension(ctx);
  return SCRIPT_EXTENSIONS.has(extension)
    ? makeResult("SCRIPT_EXTENSION", HEURISTIC_CONSTANTS.points.SCRIPT_EXTENSION, `File name ${filename} uses script extension .${extension}`)
    : null;
}

export function checkExecutableExtension(ctx) {
  const filename = resolveFilename(ctx);
  const extension = getLastExtension(ctx);
  return EXECUTABLE_EXTENSIONS.has(extension)
    ? makeResult("EXECUTABLE_EXTENSION", HEURISTIC_CONSTANTS.points.EXECUTABLE_EXTENSION, `File name ${filename} uses executable extension .${extension}`)
    : null;
}

export function checkContainerExtension(ctx) {
  const filename = resolveFilename(ctx);
  const extension = getLastExtension(ctx);
  return CONTAINER_EXTENSIONS.has(extension)
    ? makeResult("CONTAINER_EXTENSION", HEURISTIC_CONSTANTS.points.CONTAINER_EXTENSION, `File name ${filename} uses container extension .${extension}`)
    : null;
}

export function checkMacroDocument(ctx) {
  const filename = resolveFilename(ctx);
  const extension = getLastExtension(ctx);
  return MACRO_DOCUMENT_EXTENSIONS.has(extension)
    ? makeResult("MACRO_DOCUMENT", HEURISTIC_CONSTANTS.points.MACRO_DOCUMENT, `File name ${filename} is a macro-enabled document (.${extension})`)
    : null;
}

export function checkDoubleExtension(ctx) {
  const filename = resolveFilename(ctx);
  const extensions = getExtensions(filename);
  const previousExtension = extensions.at(-2);
  const lastExtension = extensions.at(-1);
  const hasDangerousFinalExtension = SCRIPT_EXTENSIONS.has(lastExtension) || EXECUTABLE_EXTENSIONS.has(lastExtension);

  return extensions.length >= 2 && DOCUMENT_MEDIA_EXTENSIONS.has(previousExtension) && hasDangerousFinalExtension
    ? makeResult("DOUBLE_EXTENSION", HEURISTIC_CONSTANTS.points.DOUBLE_EXTENSION, `File name ${filename} uses a double extension (.${previousExtension}.${lastExtension})`)
    : null;
}

export function checkRtloCharacter(ctx) {
  const filename = resolveFilename(ctx);
  return BIDI_CONTROL_PATTERN.test(filename)
    ? makeResult("RTLO_CHARACTER", HEURISTIC_CONSTANTS.points.RTLO_CHARACTER, `File name ${filename} contains a bidirectional-control character`)
    : null;
}

export function checkTrailingSpacesOrDots(ctx) {
  const filename = resolveFilename(ctx);
  const hasSpaceBeforeExtension = /[ \t]+\.[^.]+$/u.test(filename);
  const hasExtraDotsBeforeExtension = /\.{2,}[^.]+$/u.test(filename);
  const hasManySpaces = /[ \t]{5,}/u.test(filename);

  return hasSpaceBeforeExtension || hasExtraDotsBeforeExtension || hasManySpaces
    ? makeResult("TRAILING_SPACES_OR_DOTS", HEURISTIC_CONSTANTS.points.TRAILING_SPACES_OR_DOTS, `File name ${filename} contains misleading spaces or dots before its extension`)
    : null;
}

export function checkMimeMismatch(ctx) {
  const safeCtx = asContext(ctx);
  const filename = resolveFilename(safeCtx);
  const extension = getLastExtension(safeCtx);
  const mime = typeof safeCtx.mime === "string" ? safeCtx.mime.toLowerCase().split(";")[0].trim() : "";

  return DOCUMENT_MEDIA_EXTENSIONS.has(extension) && EXECUTABLE_MIME_TYPES.has(mime)
    ? makeResult("MIME_MISMATCH", HEURISTIC_CONSTANTS.points.MIME_MISMATCH, `File name ${filename} uses document/media extension .${extension} but MIME type is ${mime}`)
    : null;
}

export function checkInsecureHttp(ctx) {
  const url = getUrl(ctx);
  try {
    return new URL(url).protocol === "http:"
      ? makeResult("INSECURE_HTTP", HEURISTIC_CONSTANTS.points.INSECURE_HTTP, `Download URL ${url} uses insecure HTTP`)
      : null;
  } catch {
    return null;
  }
}

export function checkIpHost(ctx) {
  const hostname = getHostname(getUrl(ctx));
  return hostname && isIpLiteral(hostname)
    ? makeResult("IP_HOST", HEURISTIC_CONSTANTS.points.IP_HOST, `Download host ${hostname} is an IP address`)
    : null;
}

export function checkSuspiciousTld(ctx) {
  const hostname = getHostname(getUrl(ctx));
  const tld = hostname.split(".").at(-1) || "";
  return SUSPICIOUS_TLDS.has(tld)
    ? makeResult("SUSPICIOUS_TLD", HEURISTIC_CONSTANTS.points.SUSPICIOUS_TLD, `Download host ${hostname} uses suspicious TLD .${tld}`)
    : null;
}

export function checkPunycodeHost(ctx) {
  const hostname = getHostname(getUrl(ctx));
  const punycodeLabel = hostname.split(".").find((label) => label.startsWith("xn--"));
  return punycodeLabel
    ? makeResult("PUNYCODE_HOST", HEURISTIC_CONSTANTS.points.PUNYCODE_HOST, `Download host ${hostname} contains punycode label ${punycodeLabel}`)
    : null;
}

export function checkLongRedirectChain(ctx) {
  const safeCtx = asContext(ctx);
  const hopCount = Array.isArray(safeCtx.redirectChain) ? safeCtx.redirectChain.length : 0;
  if (hopCount >= 5) {
    return makeResult("LONG_REDIRECT_CHAIN", HEURISTIC_CONSTANTS.points.LONG_REDIRECT_CHAIN_LONG, `Download followed a long redirect chain of ${hopCount} hops`);
  }
  if (hopCount >= 3) {
    return makeResult("LONG_REDIRECT_CHAIN", HEURISTIC_CONSTANTS.points.LONG_REDIRECT_CHAIN_SHORT, `Download followed a redirect chain of ${hopCount} hops`);
  }
  return null;
}

/** TODO(step 9): add a real lookalike-domain detector. */
export function checkLookalikeDomain(_hostname) {
  return null;
}

export function runAllHeuristics(ctx) {
  const safeCtx = asContext(ctx);
  const checks = [
    () => checkScriptExtension(safeCtx),
    () => checkExecutableExtension(safeCtx),
    () => checkContainerExtension(safeCtx),
    () => checkMacroDocument(safeCtx),
    () => checkDoubleExtension(safeCtx),
    () => checkRtloCharacter(safeCtx),
    () => checkTrailingSpacesOrDots(safeCtx),
    () => checkMimeMismatch(safeCtx),
    () => checkInsecureHttp(safeCtx),
    () => checkIpHost(safeCtx),
    () => checkSuspiciousTld(safeCtx),
    () => checkPunycodeHost(safeCtx),
    () => checkLongRedirectChain(safeCtx),
    () => checkLookalikeDomain(getHostname(getUrl(safeCtx))),
  ];

  const results = [];
  for (const check of checks) {
    try {
      const result = check();
      if (result) {
        results.push(result);
      }
    } catch {
      // A single heuristic must never interrupt download handling.
    }
  }
  return results;
}
