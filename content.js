const HASH_PATTERNS = {
  md5: /\b[a-fA-F0-9]{32}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g
};

const MAX_MESSAGE_TEXT_LENGTH = 5000;
const IGNORED_HOSTNAMES = new Set([
  "discord.com",
  "ptb.discord.com",
  "canary.discord.com"
]);

startExtension();

// Start the extension.
function startExtension() {
  try {
    scanEntirePage();
    observePageChanges();
  } catch (error) {
    console.error("Discord Content Safety failed to start:", error);
  }
}

// Scan all current Discord messages.
function scanEntirePage() {
  const messageElements = findAllMessageElements(document);

  for (const messageElement of messageElements) {
    safelyProcessMessage(messageElement);
  }
}

// Process a single message without crashing the whole script.
function safelyProcessMessage(messageElement) {
  try {
    processMessage(messageElement);
  } catch (error) {
    console.error("Failed to process message:", error);
  }
}

// Process one Discord message element.
function processMessage(messageElement) {
  if (!(messageElement instanceof HTMLElement)) {
    return;
  }

  addButtonsToLinks(messageElement);
  addButtonsToHashes(messageElement);
}

// Find possible Discord message containers.
function findAllMessageElements(rootElement) {
  if (!(rootElement instanceof Element) && rootElement !== document) {
    return [];
  }

  const selectors = [
    "article",
    "div[id^='chat-messages-']",
    "li [id^='chat-messages-']"
  ];

  const allElements = new Set();

  for (const selector of selectors) {
    const foundElements = rootElement.querySelectorAll(selector);

    for (const element of foundElements) {
      allElements.add(element);
    }
  }

  return Array.from(allElements);
}

// Add a check button next to each valid link.
function addButtonsToLinks(messageElement) {
  const linkElements = messageElement.querySelectorAll("a[href]");

  for (const linkElement of linkElements) {
    if (!(linkElement instanceof HTMLAnchorElement)) {
      continue;
    }

    if (linkAlreadyProcessed(linkElement)) {
      continue;
    }

    const urlValue = linkElement.href;

    if (!shouldHandleUrl(urlValue)) {
      markLinkAsProcessed(linkElement);
      continue;
    }

    const controlsElement = createControlsContainer();
    const checkButton = createCheckButton("Check link");

    checkButton.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();

      await runSafeCheck({
        buttonElement: checkButton,
        controlsElement,
        message: {
          type: "CHECK_URL",
          value: urlValue
        }
      });
    });

    controlsElement.appendChild(checkButton);
    linkElement.insertAdjacentElement("afterend", controlsElement);

    markLinkAsProcessed(linkElement);
  }
}

// Find hashes inside the message text and add a row for each one.
function addButtonsToHashes(messageElement) {
  if (messageAlreadyProcessedForHashes(messageElement)) {
    return;
  }

  const textContainer = findBestTextContainer(messageElement);
  const messageText = getSafeTextFromElement(textContainer);

  if (!messageText) {
    markMessageAsProcessedForHashes(messageElement);
    return;
  }

  const foundHashes = extractHashesFromText(messageText);

  if (foundHashes.length === 0) {
    markMessageAsProcessedForHashes(messageElement);
    return;
  }

  const hashSection = createOrGetHashSection(textContainer);

  for (const hashEntry of foundHashes) {
    if (hashAlreadyAdded(hashSection, hashEntry.value)) {
      continue;
    }

    const hashRow = createHashRow(hashEntry);

    if (hashRow) {
      hashSection.appendChild(hashRow);
    }
  }

  markMessageAsProcessedForHashes(messageElement);
}

// Create one UI row for one hash.
function createHashRow(hashEntry) {
  if (!hashEntry || typeof hashEntry.value !== "string") {
    return null;
  }

  const row = document.createElement("div");
  row.className = "dcs-hash-row";
  row.dataset.hashValue = hashEntry.value;

  const label = document.createElement("span");
  label.className = "dcs-hash-label";
  label.textContent = hashEntry.type + ": " + shortenLongValue(hashEntry.value);

  const controlsElement = createControlsContainer();
  const checkButton = createCheckButton("Check hash");

  checkButton.addEventListener("click", async () => {
    await runSafeCheck({
      buttonElement: checkButton,
      controlsElement,
      message: {
        type: "CHECK_HASH",
        value: hashEntry.value
      }
    });
  });

  controlsElement.appendChild(checkButton);

  row.appendChild(label);
  row.appendChild(controlsElement);

  return row;
}

// Run one check safely and show a clear result in the UI.
async function runSafeCheck({ buttonElement, controlsElement, message }) {
  setButtonBusy(buttonElement, true);
  setStatusText(controlsElement, "Checking...");

  try {
    const result = await sendMessageToBackground(message);
    updateControlsWithResult(controlsElement, result);
  } catch (error) {
    setStatusText(controlsElement, buildSafeUiError(error), true);
  } finally {
    setButtonBusy(buttonElement, false);
  }
}

// Create a small area for a button and result text.
function createControlsContainer() {
  const container = document.createElement("span");
  container.className = "dcs-controls";

  return container;
}

// Create one check button.
function createCheckButton(buttonText) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "dcs-button";
  button.textContent = buttonText;
  button.dataset.defaultText = buttonText;

  return button;
}

// Lock or unlock a button while a check is running.
function setButtonBusy(buttonElement, isBusy) {
  if (!(buttonElement instanceof HTMLButtonElement)) {
    return;
  }

  buttonElement.disabled = isBusy;
  buttonElement.textContent = isBusy
    ? "Checking..."
    : buttonElement.dataset.defaultText || "Check";
}

// Show status text such as "Checking..." or a result.
function setStatusText(container, text, isError = false) {
  removeOldStatus(container);

  const status = document.createElement("span");
  status.className = isError ? "dcs-status dcs-status-error" : "dcs-status";
  status.textContent = text;

  container.appendChild(status);
}

// Remove the current status text before showing a new one.
function removeOldStatus(container) {
  if (!(container instanceof HTMLElement)) {
    return;
  }

  const oldStatus = container.querySelector(".dcs-status");

  if (oldStatus) {
    oldStatus.remove();
  }
}

// Show a formatted VirusTotal result in the UI.
function updateControlsWithResult(container, result) {
  removeOldStatus(container);

  const resultText = buildReadableResultText(result);
  const statusClass = getStatusClassForResult(result);

  const status = document.createElement("span");
  status.className = "dcs-status " + statusClass;
  status.textContent = resultText;

  container.appendChild(status);
}

// Build a short readable result string.
function buildReadableResultText(result) {
  if (!result || typeof result !== "object") {
    return "No result";
  }

  if (result.status === "not_found") {
    return "No VT match";
  }

  if (!result.stats) {
    return "No VT data";
  }

  if (result.stats.unavailable) {
    return "No VT data";
  }

  const malicious = safeNumber(result.stats.malicious);
  const suspicious = safeNumber(result.stats.suspicious);

  if (malicious > 0 || suspicious > 0) {
    return "Flagged: " + malicious + " malicious, " + suspicious + " suspicious";
  }

  if (result.fromCache) {
    return "Clean or undetected (cached)";
  }

  return "Clean or undetected";
}

// Pick a CSS class based on the result severity.
function getStatusClassForResult(result) {
  if (!result || typeof result !== "object") {
    return "dcs-status-error";
  }

  if (result.status === "not_found") {
    return "dcs-status-neutral";
  }

  if (!result.stats) {
    return "dcs-status-neutral";
  }

  const malicious = safeNumber(result.stats.malicious);
  const suspicious = safeNumber(result.stats.suspicious);

  if (malicious > 0) {
    return "dcs-status-danger";
  }

  if (suspicious > 0) {
    return "dcs-status-warning";
  }

  return "dcs-status-ok";
}

// Send a message to the background script and wait for a safe response.
function sendMessageToBackground(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error("Extension communication failed."));
        return;
      }

      if (!response || typeof response !== "object") {
        reject(new Error("No response from background script."));
        return;
      }

      if (!response.success) {
        reject(new Error(response.error || "Unknown extension error."));
        return;
      }

      resolve(response.data);
    });
  });
}

// Find the best text container inside a Discord message.
function findBestTextContainer(messageElement) {
  if (!(messageElement instanceof HTMLElement)) {
    return null;
  }

  const possibleContainer =
    messageElement.querySelector("[id^='message-content-']") ||
    messageElement.querySelector("[class*='messageContent']");

  if (possibleContainer instanceof HTMLElement) {
    return possibleContainer;
  }

  return messageElement;
}

// Get safe text from an element.
// Limit size to reduce performance and parsing issues.
function getSafeTextFromElement(element) {
  if (!(element instanceof HTMLElement)) {
    return "";
  }

  const rawText = typeof element.innerText === "string" ? element.innerText : "";
  const trimmedText = rawText.trim();

  if (trimmedText === "") {
    return "";
  }

  return trimmedText.slice(0, MAX_MESSAGE_TEXT_LENGTH);
}

// Extract unique MD5, SHA1, and SHA256 hashes from plain text.
function extractHashesFromText(text) {
  if (typeof text !== "string" || text.trim() === "") {
    return [];
  }

  const results = [];
  const alreadyAdded = new Set();

  for (const [hashType, regexPattern] of Object.entries(HASH_PATTERNS)) {
    const matches = text.match(regexPattern) || [];

    for (const match of matches) {
      const normalizedMatch = match.trim().toLowerCase();

      if (!isValidHash(normalizedMatch)) {
        continue;
      }

      if (alreadyAdded.has(normalizedMatch)) {
        continue;
      }

      results.push({
        type: hashType,
        value: normalizedMatch
      });

      alreadyAdded.add(normalizedMatch);
    }
  }

  return results;
}

// Create a section for hashes or return the existing one.
function createOrGetHashSection(textContainer) {
  let section = textContainer.querySelector("[data-dcs-hash-section='true']");

  if (section instanceof HTMLElement) {
    return section;
  }

  section = document.createElement("div");
  section.className = "dcs-hash-section";
  section.dataset.dcsHashSection = "true";

  textContainer.appendChild(section);

  return section;
}

// Shorten long values to keep the UI readable.
function shortenLongValue(value) {
  if (typeof value !== "string") {
    return "";
  }

  const visibleLength = 14;

  if (value.length <= visibleLength) {
    return value;
  }

  return value.slice(0, visibleLength) + "...";
}

// Decide if a URL should be handled by the extension.
function shouldHandleUrl(urlValue) {
  if (!isValidWebUrl(urlValue)) {
    return false;
  }

  try {
    const parsedUrl = new URL(urlValue);

    if (IGNORED_HOSTNAMES.has(parsedUrl.hostname)) {
      return false;
    }
  } catch {
    return false;
  }

  return true;
}

// Validate a normal web URL.
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

// Validate a hash by length and allowed characters.
function isValidHash(hashValue) {
  if (typeof hashValue !== "string") {
    return false;
  }

  return (
    /^[a-f0-9]{32}$/.test(hashValue) ||
    /^[a-f0-9]{40}$/.test(hashValue) ||
    /^[a-f0-9]{64}$/.test(hashValue)
  );
}

// Return a safe number.
function safeNumber(value) {
  const numberValue = Number(value);

  if (!Number.isFinite(numberValue) || numberValue < 0) {
    return 0;
  }

  return numberValue;
}

// Return a safe error message for the UI.
function buildSafeUiError(error) {
  if (!error || typeof error.message !== "string") {
    return "Unknown error";
  }

  return error.message;
}

// Check if a link was already processed.
function linkAlreadyProcessed(linkElement) {
  return linkElement.dataset.dcsLinkProcessed === "true";
}

// Mark a link as processed.
function markLinkAsProcessed(linkElement) {
  linkElement.dataset.dcsLinkProcessed = "true";
}

// Check if hashes were already processed for this message.
function messageAlreadyProcessedForHashes(messageElement) {
  return messageElement.dataset.dcsHashProcessed === "true";
}

// Mark the message so it is not processed again for hashes.
function markMessageAsProcessedForHashes(messageElement) {
  messageElement.dataset.dcsHashProcessed = "true";
}

// Check if a hash already exists in the hash section.
function hashAlreadyAdded(hashSection, hashValue) {
  return hashSection.querySelector(`[data-hash-value="${hashValue}"]`) !== null;
}

// Watch for new messages added to the page.
function observePageChanges() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const addedNode of mutation.addedNodes) {
        if (!(addedNode instanceof HTMLElement)) {
          continue;
        }

        safelyProcessAddedNode(addedNode);
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

// Process a new DOM node without breaking the whole observer.
function safelyProcessAddedNode(addedNode) {
  try {
    processAddedNode(addedNode);
  } catch (error) {
    console.error("Failed to process added node:", error);
  }
}

// Process new nodes and search for message elements inside them.
function processAddedNode(addedNode) {
  if (looksLikeMessageElement(addedNode)) {
    safelyProcessMessage(addedNode);
  }

  const nestedMessages = findAllMessageElements(addedNode);

  for (const nestedMessage of nestedMessages) {
    safelyProcessMessage(nestedMessage);
  }
}

// Check if an element looks like a Discord message.
function looksLikeMessageElement(element) {
  return (
    element.matches("article") ||
    element.matches("div[id^='chat-messages-']") ||
    element.matches("li")
  );
}