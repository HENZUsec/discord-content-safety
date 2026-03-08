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

## How to use

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

### Example results

- `No VT match`
- `Clean or undetected`
- `Flagged: 1 malicious, 0 suspicious`
- `Rate limit reached. Please wait before checking again.`
