# Discord Content Safety

A simple browser extension for Discord Web that checks shared content such as links and hashes with VirusTotal.

## Features

- Detects links in Discord messages
- Detects MD5, SHA1, and SHA256 hashes in message text
- Lets the user save their own VirusTotal API key inside the extension popup
- Checks URLs and hashes with VirusTotal
- Shows a simple result directly in Discord Web
- Uses cache to avoid repeated checks
- Uses cooldown and timeout to reduce API and network issues

## Code style

This project is written to be easy to read and easy to learn from.

The code uses:
- clear function names
- small functions
- simple English comments
- structure over cleverness

## Security and stability goals

This version focuses on safer behavior and fewer runtime errors.

It includes:
- input validation
- safer DOM handling
- request timeout
- clear error messages
- result caching
- simple API cooldown
- safe defaults for missing API data

## Project structure

- `manifest.json` defines the extension
- `background.js` handles VirusTotal API requests
- `content.js` scans Discord messages and injects UI
- `content.css` styles buttons and result labels inside Discord
- `popup.html` creates the extension popup
- `popup.js` saves and clears the user's API key
- `popup.css` styles the popup

## How to install in Brave

1. Open `brave://extensions`
2. Turn on **Developer mode**
3. Click **Load unpacked**
4. Select this project folder

## How to use

1. Click the extension icon
2. Paste your own VirusTotal API key
3. Save it
4. Open Discord Web
5. Click **Check link** or **Check hash** next to detected content

## Notes

- This extension works on Discord Web, not the native desktop app
- Discord may change its page structure over time, so selectors may need updates
- VirusTotal public API has rate limits, so avoid checking too many items too quickly

## Future ideas

- better URL handling for special cases
- support for attachments and file hashing
- ignore more internal Discord links
- better result severity labels
- persistent cache in extension storage
- settings page for behavior options