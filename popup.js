document.addEventListener("DOMContentLoaded", startPopup);

// Start the popup UI.
function startPopup() {
  const apiKeyInput = document.getElementById("apiKeyInput");
  const saveButton = document.getElementById("saveButton");
  const clearButton = document.getElementById("clearButton");

  loadSavedApiKey(apiKeyInput);

  saveButton.addEventListener("click", async () => {
    const apiKeyValue = apiKeyInput.value.trim();

    if (!isProbablyValidApiKey(apiKeyValue)) {
      setPopupStatus("The API key format looks invalid.", true);
      return;
    }

    try {
      await sendMessageToBackground({
        type: "SAVE_API_KEY",
        value: apiKeyValue
      });

      setPopupStatus("API key saved.");
    } catch (error) {
      setPopupStatus(buildSafePopupError(error), true);
    }
  });

  clearButton.addEventListener("click", async () => {
    try {
      await sendMessageToBackground({
        type: "CLEAR_API_KEY"
      });

      apiKeyInput.value = "";
      setPopupStatus("API key removed.");
    } catch (error) {
      setPopupStatus(buildSafePopupError(error), true);
    }
  });
}

// Load the saved API key from local storage.
async function loadSavedApiKey(apiKeyInput) {
  try {
    const storageData = await chrome.storage.local.get(["virustotalApiKey"]);

    if (typeof storageData.virustotalApiKey === "string" && storageData.virustotalApiKey.trim() !== "") {
      apiKeyInput.value = storageData.virustotalApiKey;
      setPopupStatus("Saved API key found.");
      return;
    }

    setPopupStatus("No API key saved yet.");
  } catch {
    setPopupStatus("Failed to load saved API key.", true);
  }
}

// Show a short message in the popup.
function setPopupStatus(message, isError = false) {
  const statusMessage = document.getElementById("statusMessage");
  statusMessage.textContent = message;
  statusMessage.className = isError
    ? "popup-status popup-status-error"
    : "popup-status popup-status-ok";
}

// Send a message to the background script.
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

// Basic client-side validation for the API key.
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

// Return a safe popup error string.
function buildSafePopupError(error) {
  if (!error || typeof error.message !== "string") {
    return "Unknown error.";
  }

  return error.message;
}