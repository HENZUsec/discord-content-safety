const VIRUSTOTAL_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/";
const VIRUSTOTAL_URL_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls";
const VIRUSTOTAL_ANALYSIS_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/";

const REQUEST_TIMEOUT_MS = 10000;
const CACHE_TTL_MS = 10 * 60 * 1000;
const MIN_TIME_BETWEEN_REQUESTS_MS = 16000;

const URL_POLL_INTERVAL_MS = 4000;
const URL_POLL_MAX_ATTEMPTS = 4;

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

// Submit a URL to VirusTotal and poll until the analysis is ready.
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
  const analysisId = await submitUrlForAnalysis(normalizedUrl, apiKey);

  const analysisData = await pollUrlAnalysisUntilReady(analysisId, apiKey);
  const stats = safeExtractStatsFromAnalysis(analysisData);

  const result = {
    kind: "url",
    query: normalizedUrl,
    status: stats ? "found" : "not_found",
    stats: stats,
    fromCache: false
  };

  saveCachedResult(cacheKey, result);
  return result;
}

// Submit a URL to VirusTotal and get an analysis ID back.
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
  const analysisId = responseData?.data?.id;

  if (typeof analysisId !== "string" || analysisId.trim() === "") {
    throw new Error("VirusTotal did not return a valid analysis ID.");
  }

  return analysisId;
}

// Poll the VirusTotal analysis endpoint until the URL analysis is ready.
async function pollUrlAnalysisUntilReady(analysisId, apiKey) {
  if (typeof analysisId !== "string" || analysisId.trim() === "") {
    throw new Error("Missing analysis ID.");
  }

  for (let attempt = 1; attempt <= URL_POLL_MAX_ATTEMPTS; attempt += 1) {
    await waitForRequestSlot();

    const analysisData = await fetchAnalysisReportById(analysisId, apiKey);
    const analysisStatus = getAnalysisStatus(analysisData);

    if (analysisStatus === "completed") {
      return analysisData;
    }

    if (analysisStatus === "queued" || analysisStatus === "in-progress") {
      if (attempt < URL_POLL_MAX_ATTEMPTS) {
        await delay(URL_POLL_INTERVAL_MS);
        continue;
      }

      throw new Error("URL analysis is still pending. Please try again in a moment.");
    }

    if (analysisStatus === "not_found") {
      throw new Error("No VirusTotal match found.");
    }

    throw new Error("VirusTotal returned an unknown analysis status.");
  }

  throw new Error("URL analysis did not finish in time.");
}

// Fetch a VirusTotal analysis report by ID.
async function fetchAnalysisReportById(analysisId, apiKey) {
  const requestUrl = VIRUSTOTAL_ANALYSIS_REPORT_URL + encodeURIComponent(analysisId);

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

// Read the status from an analysis object.
function getAnalysisStatus(analysisData) {
  if (!analysisData || typeof analysisData !== "object") {
    return "not_found";
  }

  const statusValue = analysisData?.data?.attributes?.status;

  if (typeof statusValue !== "string" || statusValue.trim() === "") {
    return "unknown";
  }

  return statusValue.trim().toLowerCase();
}

// Extract analysis stats from a completed analysis object.
function safeExtractStatsFromAnalysis(analysisData) {
  const rawStats = analysisData?.data?.attributes?.stats;

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

// Build a safe stats object from a VirusTotal file response.
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