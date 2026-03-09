# Discord Content Safety

A browser extension for Discord Web that lets you manually check links, hashes, and attachment URLs with VirusTotal.

## Features

- Check links with VirusTotal
- Check MD5, SHA1, and SHA256 hashes with VirusTotal
- Show simple risk labels for file attachments
- Check attachment URLs with VirusTotal
- Save your own VirusTotal API key in the extension popup

## Browser support

This extension is made for Chromium-based desktop browsers such as:

- Brave
- Chrome
- Edge
- Opera

It is intended for Discord Web on desktop.

## Installation

### 1. Download or clone the repository

Download the project from GitHub or clone it locally.

### 2. Load the extension

Open your browser's extensions page:

- `brave://extensions`
- `chrome://extensions`
- `edge://extensions`
- `opera://extensions`

Then:

- turn on **Developer mode**
- click **Load unpacked**
- select the project folder

### 3. Save your VirusTotal API key

Click the extension icon.

Then:

- paste your VirusTotal API key
- click **Save**

## Usage

Open Discord Web:

`https://discord.com/app`

The extension can detect:

- links
- MD5 hashes
- SHA1 hashes
- SHA256 hashes
- file attachments

Available actions:

- **Check link**
- **Check hash**
- **More** for attachment actions
- **Check attachment URL**

## Attachment checks

Attachments are checked locally by filename only.

The extension may show labels such as:

- `High risk file type`
- `Macro-enabled document`
- `Potentially risky attachment`
- `No obvious filename risk`

This is **not** a full file scan.

The extension does **not** download, hash, or upload the attachment in this mode.

## Current behavior

All VirusTotal checks are manual.

Nothing is sent to VirusTotal unless you click a button.

## Notes

- works on Discord Web, not the desktop app
- works best in Chromium-based desktop browsers
- VirusTotal public API has rate limits