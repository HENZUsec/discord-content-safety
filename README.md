# Discord Content Safety

A simple browser extension for Discord Web that helps inspect shared content such as links, hashes, and file attachments with VirusTotal.

## Features

- Detects links in Discord messages
- Detects MD5, SHA1, and SHA256 hashes in message text
- Lets the user save their own VirusTotal API key inside the extension popup
- Checks links and hashes with VirusTotal
- Adds heuristic attachment labels without downloading the file
- Lets the user manually check an attachment URL with VirusTotal
- Uses a manual scan model for all VirusTotal checks

## Browser support

This extension is built for Chromium-based desktop browsers such as Brave, Chrome, Edge, Opera, and similar browsers.

It is intended for Discord Web on desktop.

## Installation

### 1. Download or clone the repository

Download the project from GitHub or clone it locally.

### 2. Load the extension

Open your browser's extensions page.

For Chromium-based browsers, this is usually one of the following:

- `brave://extensions`
- `chrome://extensions`
- `edge://extensions`
- `opera://extensions`

Then:

- turn on **Developer mode**
- click **Load unpacked**
- select the project folder

### 3. Save your VirusTotal API key

Click the extension icon in your browser.

In the popup:

- paste your own VirusTotal API key
- click **Save**

The key is stored locally inside the extension.

## Usage

### 1. Open Discord Web

Go to:

`https://discord.com/app`

Log in as usual.

### 2. Use the check buttons

The extension looks for:

- links
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

When supported content is found, the extension adds:

- **Check link**
- **Check hash**

Click a button to send the item to VirusTotal and show the result directly in Discord.

## Attachment checks

This extension can also inspect Discord file attachments without downloading the file itself.

The current attachment check is heuristic-based and looks at:

- file name
- file extension
- double extensions
- macro-enabled document formats
- archive and script-like file types

Attachment labels may include:

- `High risk file type`
- `Macro-enabled document`
- `Potentially risky attachment`
- `No obvious filename risk`

For attachments, the extension shows:

- a compact risk label
- a **More** button
- **Why flagged**
- **Check attachment URL**

**Note:**  
This is **not a full file scan**. The extension does not download, hash, or upload the file in this mode.

## Current behavior

This extension uses a manual scan model.

It does not automatically send links, hashes, or attachment URLs to VirusTotal.

VirusTotal checks only happen when the user clicks:

- **Check link**
- **Check hash**
- **Check attachment URL**

Attachment risk labels are local heuristic checks based on visible filename patterns and do not download, hash, or upload the file.

## Example results

VirusTotal checks may return results such as:

- `No VT match`
- `Clean or undetected`
- `Clean or undetected (cached)`
- `Flagged: 1 malicious, 0 suspicious`
- `Rate limit reached. Please wait before checking again.`

## Notes

- This extension works on Discord Web, not the native desktop app
- Discord may change its page structure over time, so selectors may need updates
- VirusTotal public API has rate limits, so avoid checking too many items too quickly

## Future ideas

- persistent cache in extension storage
- improved attachment detection for more Discord layouts
- optional support for file hashing
- ignore more internal Discord links
- settings for behavior and filtering