const VIRUSTOTAL_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/";
const VIRUSTOTAL_URL_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls";
const VIRUSTOTAL_URL_REPORT_URL = "https://www.virustotal.com/api/v3/urls/";

const REQUEST_TIMEOUT_MS = 10000;
const CACHE_TTL_MS = 10 * 60 * 1000;
const MIN_TIME_BETWEEN_REQUESTS_MS = 16000;

const resultCache = new Map();

let nextAllowedRequestTime = 0;

// Listen for messages from the popup or content script.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleIncomingMessage(message)
    .then((result) => {
      sendResponse({
        success: true,
        data: result
      });
    })
    .catch((error) => {
      sendResponse({
        success: false,
        error: buildSafeErrorMessage(error)
      });
    });

  return true;
});

// Route incoming messages to the correct function.
async function handleIncomingMessage(message) {
  validateMessageObject(message);

  if (message.type === "GET_API_KEY_STATUS") {
    return await getApiKeyStatus();
  }

  if (message.type === "SAVE_API_KEY") {
    return await saveApiKey(message.value);
  }

  if (message.type === "CLEAR_API_KEY") {
    return await clearApiKey();
  }

  if (message.type === "CHECK_HASH") {
    return await checkHashInVirusTotal(message.value);
  }

  if (message.type === "CHECK_URL") {
    return await checkUrlInVirusTotal(message.value);
  }

  throw new Error("Unsupported message type.");
}

// Return a simple status for the popup.
async function getApiKeyStatus() {
  const apiKey = await readApiKeyFromStorage();

  return {
    hasApiKey: Boolean(apiKey)
  };
}

// Save the API key after basic validation.
async function saveApiKey(apiKeyValue) {
  if (!isProbablyValidApiKey(apiKeyValue)) {
    throw new Error("The API key format looks invalid.");
  }

  await chrome.storage.local.set({
    virustotalApiKey: apiKeyValue.trim()
  });

  return {
    saved: true
  };
}

// Remove the saved API key.
async function clearApiKey() {
  await chrome.storage.local.remove("virustotalApiKey");

  return {
    cleared: true
  };
}

// Look up a hash in VirusTotal.
async function checkHashInVirusTotal(hashValue) {
  const hashType = getHashType(hashValue);

  if (!hashType) {
    throw new Error("Invalid hash format.");
  }

  const normalizedHash = hashValue.trim().toLowerCase();
  const cacheKey = "hash:" + normalizedHash;

  const cachedResult = getCachedResult(cacheKey);

  if (cachedResult) {
    return cachedResult;
  }

  const apiKey = await requireApiKey();
  await waitForRequestSlot();

  const requestUrl = VIRUSTOTAL_FILE_REPORT_URL + encodeURIComponent(normalizedHash);

  const response = await fetchWithTimeout(requestUrl, {
    method: "GET",
    headers: {
      "x-apikey": apiKey
    }
  });

  if (response.status === 404) {
    const result = {
      kind: "hash",
      query: normalizedHash,
      hashType: hashType,
      status: "not_found",
      stats: null,
      fromCache: false
    };

    saveCachedResult(cacheKey, result);
    return result;
  }

  if (!response.ok) {
    throw new Error(buildVirusTotalErrorMessage(response.status));
  }

  const responseData = await safeReadJson(response);
  const stats = safeExtractStats(responseData);

  const result = {
    kind: "hash",
    query: normalizedHash,
    hashType: hashType,
    status: "found",
    stats: stats,
    fromCache: false
  };

  saveCachedResult(cacheKey, result);
  return result;
}

// Submit a URL to VirusTotal and fetch the result.
async function checkUrlInVirusTotal(urlValue) {
  if (!isValidWebUrl(urlValue)) {
    throw new Error("Invalid URL.");
  }

  const normalizedUrl = normalizeUrl(urlValue);
  const cacheKey = "url:" + normalizedUrl;

  const cachedResult = getCachedResult(cacheKey);

  if (cachedResult) {
    return cachedResult;
  }

  const apiKey = await requireApiKey();

  await waitForRequestSlot();
  const urlId = await submitUrlForAnalysis(normalizedUrl, apiKey);

  await waitForRequestSlot();
  const reportData = await fetchUrlReportById(urlId, apiKey);

  const result = {
    kind: "url",
    query: normalizedUrl,
    status: reportData ? "found" : "not_found",
    stats: reportData ? safeExtractStats(reportData) : null,
    fromCache: false
  };

  saveCachedResult(cacheKey, result);
  return result;
}

// Submit a URL to VirusTotal.
async function submitUrlForAnalysis(urlValue, apiKey) {
  const requestBody = new URLSearchParams();
  requestBody.append("url", urlValue);

  const response = await fetchWithTimeout(VIRUSTOTAL_URL_SUBMIT_URL, {
    method: "POST",
    headers: {
      "x-apikey": apiKey,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: requestBody.toString()
  });

  if (!response.ok) {
    throw new Error(buildVirusTotalErrorMessage(response.status));
  }

  const responseData = await safeReadJson(response);
  const urlId = responseData?.data?.id;

  if (typeof urlId !== "string" || urlId.trim() === "") {
    throw new Error("VirusTotal did not return a valid URL ID.");
  }

  return urlId;
}

// Fetch a submitted URL report by its VirusTotal ID.
async function fetchUrlReportById(urlId, apiKey) {
  if (typeof urlId !== "string" || urlId.trim() === "") {
    throw new Error("Missing URL report ID.");
  }

  const requestUrl = VIRUSTOTAL_URL_REPORT_URL + encodeURIComponent(urlId);

  const response = await fetchWithTimeout(requestUrl, {
    method: "GET",
    headers: {
      "x-apikey": apiKey
    }
  });

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    throw new Error(buildVirusTotalErrorMessage(response.status));
  }

  return await safeReadJson(response);
}

// Return the saved API key or throw an error if it is missing.
async function requireApiKey() {
  const apiKey = await readApiKeyFromStorage();

  if (!apiKey) {
    throw new Error("No VirusTotal API key saved.");
  }

  return apiKey;
}

// Read the saved API key from extension storage.
async function readApiKeyFromStorage() {
  const storageData = await chrome.storage.local.get(["virustotalApiKey"]);
  const apiKey = storageData?.virustotalApiKey;

  if (typeof apiKey !== "string") {
    return "";
  }

  return apiKey.trim();
}

// Wait before sending the next request.
// This helps avoid public API rate limits.
async function waitForRequestSlot() {
  const now = Date.now();

  if (now < nextAllowedRequestTime) {
    const waitTime = nextAllowedRequestTime - now;
    await delay(waitTime);
  }

  nextAllowedRequestTime = Date.now() + MIN_TIME_BETWEEN_REQUESTS_MS;
}

// Small helper for waiting.
function delay(timeMs) {
  return new Promise((resolve) => {
    setTimeout(resolve, timeMs);
  });
}

// Return a cached result if it is still fresh.
function getCachedResult(cacheKey) {
  const cachedEntry = resultCache.get(cacheKey);

  if (!cachedEntry) {
    return null;
  }

  const isExpired = Date.now() - cachedEntry.savedAt > CACHE_TTL_MS;

  if (isExpired) {
    resultCache.delete(cacheKey);
    return null;
  }

  return {
    ...cachedEntry.value,
    fromCache: true
  };
}

// Save a result in the memory cache.
function saveCachedResult(cacheKey, value) {
  resultCache.set(cacheKey, {
    value,
    savedAt: Date.now()
  });
}

// Run fetch with a timeout to avoid hanging forever.
async function fetchWithTimeout(url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } catch (error) {
    if (error && error.name === "AbortError") {
      throw new Error("Request timed out.");
    }

    throw new Error("Network request failed.");
  } finally {
    clearTimeout(timeoutId);
  }
}

// Safely parse JSON from a response.
async function safeReadJson(response) {
  try {
    return await response.json();
  } catch {
    throw new Error("VirusTotal returned invalid JSON.");
  }
}

// Build a safe stats object from a VirusTotal response.
function safeExtractStats(responseData) {
  const rawStats = responseData?.data?.attributes?.last_analysis_stats;

  if (!rawStats || typeof rawStats !== "object") {
    return {
      harmless: 0,
      malicious: 0,
      suspicious: 0,
      undetected: 0,
      timeout: 0,
      unavailable: true
    };
  }

  return {
    harmless: toSafeNumber(rawStats.harmless),
    malicious: toSafeNumber(rawStats.malicious),
    suspicious: toSafeNumber(rawStats.suspicious),
    undetected: toSafeNumber(rawStats.undetected),
    timeout: toSafeNumber(rawStats.timeout),
    unavailable: false
  };
}

// Convert any value into a safe non-negative number.
function toSafeNumber(value) {
  const numberValue = Number(value);

  if (!Number.isFinite(numberValue) || numberValue < 0) {
    return 0;
  }

  return numberValue;
}

// Validate incoming message objects before using them.
function validateMessageObject(message) {
  if (!message || typeof message !== "object") {
    throw new Error("Invalid message object.");
  }

  if (typeof message.type !== "string" || message.type.trim() === "") {
    throw new Error("Missing message type.");
  }
}

// Basic validation for the VirusTotal API key.
function isProbablyValidApiKey(apiKeyValue) {
  if (typeof apiKeyValue !== "string") {
    return false;
  }

  const trimmedValue = apiKeyValue.trim();

  if (trimmedValue.length < 20 || trimmedValue.length > 128) {
    return false;
  }

  return /^[A-Za-z0-9_-]+$/.test(trimmedValue);
}

// Return the hash type if the hash looks valid.
function getHashType(hashValue) {
  if (typeof hashValue !== "string") {
    return null;
  }

  const trimmedHash = hashValue.trim();

  if (/^[a-fA-F0-9]{32}$/.test(trimmedHash)) {
    return "md5";
  }

  if (/^[a-fA-F0-9]{40}$/.test(trimmedHash)) {
    return "sha1";
  }

  if (/^[a-fA-F0-9]{64}$/.test(trimmedHash)) {
    return "sha256";
  }

  return null;
}

// Return true only for standard web URLs.
function isValidWebUrl(urlValue) {
  if (typeof urlValue !== "string") {
    return false;
  }

  const trimmedUrl = urlValue.trim();

  if (trimmedUrl === "" || trimmedUrl.length > 2048) {
    return false;
  }

  try {
    const parsedUrl = new URL(trimmedUrl);
    return parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:";
  } catch {
    return false;
  }
}

// Normalize a URL before using it as cache input or API input.
function normalizeUrl(urlValue) {
  return urlValue.trim();
}

// Convert HTTP errors into clear messages.
function buildVirusTotalErrorMessage(statusCode) {
  if (statusCode === 400) {
    return "Bad request sent to VirusTotal.";
  }

  if (statusCode === 401 || statusCode === 403) {
    return "Invalid or unauthorized API key.";
  }

  if (statusCode === 404) {
    return "No VirusTotal match found.";
  }

  if (statusCode === 429) {
    return "Rate limit reached. Please wait before checking again.";
  }

  if (statusCode >= 500) {
    return "VirusTotal is temporarily unavailable.";
  }

  return "Unexpected VirusTotal error.";
}

// Make sure only a safe message is shown to the user.
function buildSafeErrorMessage(error) {
  if (!error || typeof error.message !== "string") {
    return "Unknown error.";
  }

  return error.message;
}