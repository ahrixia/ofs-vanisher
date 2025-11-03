# OFS Vanisher 
A Burp Suite extension to automatically hide / ignore out-of-scope hosts and URLs. Written by AI.   

---

## 🧩 Overview
OFS (Out of Scope) Vanisher helps you **keep your Burp Proxy HTTP history clean** by automatically excluding unwanted hosts and URLs from Burp’s scope and marking their responses so you can filter them out easily. OFS Vanisher does the boring part - so you can stop copy-pasting `^.*cdn.*$` at 3 a.m. and actually hack something.

Ideal for bug bounty testing or multi-target recon where you want to silence third-party noise (CDNs, analytics, etc.). 

---


## 🧠 How It Works
1. When you add a host or URL to the ignore list, the extension calls `excludeFromScope(URL)` for that entry (and both HTTP/HTTPS for hosts).
2. Burp treats those entries as **out of scope**.
3. With Burp’s option enabled (see below), **new out-of-scope requests** will not be logged in Proxy > HTTP History.
4. Any responses that still reach Burp are modified to appear as `text/css` with the extra header `X-OFS-Vanisher: ignored`, so you can hide them in your filter.

---

## 🧭 Usage
### Context Menu
- Right-click any request > Extension > choose **OFS Vanisher: Ignore Host (ANY)** or **Ignore Full URL (path only)**.  
- The host/URL is immediately added, saved, and excluded from scope.

### OFS Vanisher Tab
- **Add / Edit / Remove** entries.  
- **Exclude Selected** adds those to Burp’s scope exclude list.  
- **Save** persists the list between sessions.  
- **Clear All** wipes the list (does not modify Burp’s existing scope entries).

---

## ⚠️ Important Notes
- **Enable this Burp option** to stop new out-of-scope traffic from showing up:
> `Proxy > Options > Proxy history logging > Don't send items to Proxy history if out of scope`
- The Burp API **cannot**:
- delete existing Proxy history entries, or  
- toggle that Proxy setting programmatically.
- Already-recorded history entries must be cleared manually (`Proxy > HTTP history > Clear`).

---

## 🧩 Dependencies
OFS Vanisher is pure Jython (Python 2.7 syntax) and depends **only** on:
- **Jython standalone JAR** – required for running any Python-based Burp extension.

### 🔧 Setup inside Burp
1. Go to **Extender > Options > Python Environment**  
2. Under **Location of Jython standalone JAR**, click **Select file…**  
3. Choose your Jython file, and save.
---

## 📦 Installation
1. Open **Burp Suite > Extender > Extensions > Add**  
2. Select **Extension type:** Python  
3. Choose the file: **`ofs_vanisher.py`**  
4. Click **Next** > Burp will load the extension and create the **OFS Vanisher** tab.

## 🧾 Changelog
### v1.0
- Auto-exclusion on load, add, edit, and context actions.  
- Cleaner UI and summary output.  
- Added reminder banner on startup.
