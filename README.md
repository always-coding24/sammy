

## 🚀 How to Install and Run This Bot on Your Phone

**Follow these steps carefully. Copy and paste the commands into Termux.**

### 1. Install Termux

- Download and install the Termux app from [F-Droid](https://f-droid.org/en/packages/com.termux/).
- Open the Termux app.

### 2. Update Termux Packages

Copy-paste this command into Termux and press Enter:
```sh
pkg update && pkg upgrade -y
```

### 3. Install Python

```sh
pkg install python -y
```

### 4. Install Git

```sh
pkg install git -y
```

### 5. Download the Bot's Code

```sh
git clone https://github.com/always-coding24/sammy.git
cd sammy
```

### 6. Install Python Libraries Needed

This bot requires these Python libraries (used in the code):

- `requests`
- `beautifulsoup4`
- `colorama`

Install them by running:
```sh
pip install requests beautifulsoup4 colorama
```

### 8. Run the Bot

```sh
python "blackmen.py"
```

*(If the file has a different name, use that name instead.)*

---

