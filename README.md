# BurpFuzzer

BurpFuzzer is a lightweight and stable **Burp Suite extension** written in **Jython**.  
It is designed for fast discovery of hidden directories, files, and endpoints using **path fuzzing** with real-time result visualization.

The extension focuses on simplicity, performance, and UI stability during long fuzzing sessions.

[![2d.png](https://i.postimg.cc/DzCH06h7/2d.png)](https://postimg.cc/Z9dVDr0Q)

---

## Features

### 🚀 Context Menu Integration
Send any request from **Proxy** or **Repeater** to BurpFuzzer with a single right-click.

### 🧠 Smart Path Handling
Automatically normalizes URL paths to prevent common issues such as:
- double slashes (`//admin`)
- missing separators
- malformed paths

### ⚙️ Multithreaded Execution
Fuzzing runs in background threads without blocking or freezing the Burp Suite UI.

### 📄 Flexible Wordlists
Load custom `.txt` wordlists directly through the graphical interface.

### 📊 Live Analytics
Each request displays:
- HTTP status code
- response body length
- request latency

Results are updated in real time during fuzzing.

---

## Status Indicators & Color Coding

BurpFuzzer uses a simple color-based classification to quickly filter results and highlight interesting endpoints.

| Color  | Status Codes       | Meaning |
|-------|--------------------|--------|
| Green | 200, 204           | Resource exists and is accessible |
| Yellow | 301, 302          | Redirected resource |
| Yellow | 401, 403          | Restricted access (possible 403 bypass targets) |
| Red   | 404                | Not found (usually noise) |
| White | 5xx and others     | Server errors or anomalies |

---

## Technical Details

- **Low-level request modification**  
  Requests are generated using `buildHttpMessage` with raw byte manipulation.  
  This ensures correctness even when working with non-standard headers.

- **Stable GUI updates**  
  Uses `ActionListener` and `SwingUtilities.invokeLater` to safely update tables without UI crashes.

- **Minimalistic design**  
  No unnecessary dependencies. Clean and extensible codebase.

---

## Installation

1. Configure **Jython Standalone** in Burp Suite  
   `Extender → Options → Python Environment`

2. Download `BurpFuzzer.py`

3. Go to  
   `Extender → Extensions → Add`

4. Select:
   - Extension type: **Python**
   - Extension file: `BurpFuzzer.py`

---

## Usage

1. Locate an interesting request in Burp history.
2. Right-click → **Send to BurpFuzzer**.
3. Open the **BurpFuzzer** tab.
4. Load a custom wordlist (optional).
5. Click **Start** and monitor results in real time.

---

## Disclaimer

This tool does **not** automatically exploit vulnerabilities.

BurpFuzzer is intended for **educational purposes** and **authorized security testing only**.  
Use it responsibly and only on systems you own or have permission to test.
