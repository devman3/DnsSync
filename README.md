# Windows DNS to Pi-hole Sync Script

This Python script fetches DNS records (A, AAAA, CNAME) for a specified zone from a Windows DNS server and exports them into a configuration file compatible with Pi-hole's underlying `dnsmasq` service. It then transfers this file to the Pi-hole server via SCP and triggers Pi-hole to reload the configuration, effectively adding the Windows DNS entries as local DNS records on the Pi-hole.

## Features

*   Fetches A, AAAA, and CNAME records from a specified Windows DNS zone.
*   Uses PowerShell Remoting (WinRM) via the `pypsrp` library to query the Windows DNS Server.
*   Formats fetched records into `dnsmasq` configuration syntax (`address=/...` and `cname=...`).
*   Uses SSH/SCP via the `paramiko` library to securely transfer the configuration file to the Pi-hole server.
*   Reloads the Pi-hole DNS service (`pihole-FTL`) via SSH to apply the new records immediately.
*   Uses a `.env` file for easy and secure configuration management (`python-dotenv`).
*   Provides interactive prompts for passwords/passphrases if not specified in the `.env` file or if SSH keys require them.
*   Includes basic logging for monitoring and troubleshooting.

## Prerequisites

### 1. Machine Running the Script
*   Python 3.6+
*   `pip` (Python package installer)
*   Network connectivity to both the Windows DNS Server and the Pi-hole Server.

### 2. Windows DNS Server (Source)
*   **IP Address/Hostname:** Known address (e.g., `10.2.3.5`).
*   **DNS Zone Name:** The zone to export (e.g., `kidz.ct.local`).
*   **WinRM Enabled & Configured:**
    *   Run `Enable-PSRemoting -Force` in an *elevated* PowerShell prompt on the server.
    *   Ensure firewall rules allow WinRM traffic (Default ports: HTTP=5985, HTTPS=5986) from the machine running the script.
    *   Configure `TrustedHosts` on the *client* machine (or the server, depending on auth) if not domain-joined or using Basic auth over HTTP. Example (run on client): `winrm set winrm/config/client '@{TrustedHosts="10.2.3.5"}'` (Use `*` with caution).
*   **User Account:** A Windows user account (domain or local) with permissions to query DNS records (e.g., member of `DNSAdmins` or potentially `Domain Users` with specific read permissions).
*   **Authentication:** The script supports standard WinRM authentication methods (`negotiate`, `ntlm`, `basic`, etc.). `negotiate` (Kerberos/NTLM fallback) is often the default. Basic requires HTTPS or TrustedHosts configuration.

### 3. Pi-hole Server (Destination)
*   **IP Address/Hostname:** Known address (e.g., `10.2.3.7`).
*   **SSH Enabled:** The SSH service must be running.
*   **SSH User Account:** An account that can log in via SSH (e.g., `pi`).
*   **Permissions:**
    *   Write permissions to the target directory (`/etc/dnsmasq.d/` by default).
    *   `sudo` privileges to run `pihole restartdns` and `chmod`. **Passwordless `sudo` for these specific commands is highly recommended for automation.** (See Setup below).
*   **Firewall:** Ensure firewall rules allow SSH traffic (Default port: 22) from the machine running the script.

## Setup & Configuration

1.  **Clone or Download:** Get the script files (`dns_sync.py`, `requirements.txt`, `.gitignore`, this `README.md`, and `LICENSE.md`).
2.  **Create `.env` File:** Create a file named `.env` in the same directory as the script. **Do NOT commit this file to Git.** Copy the following template and fill in your details:

    ```dotenv
    # .env - Configuration for Windows DNS to Pi-hole Sync Script

    # --- Windows DNS Server Details ---
    WINDOWS_DNS_SERVER="10.2.3.5"
    WINDOWS_ZONE_NAME="kidz.ct.local"
    WINDOWS_USERNAME="YOUR_WINDOWS_DOMAIN\\YourUsername" # Or just "YourUsername" for local accounts

    # --- Windows Authentication ---
    # Option 1: Set password here (less secure, ensure file permissions are strict)
    # WINDOWS_PASSWORD="YourWindowsPassword"
    # Option 2: Leave empty/commented to be prompted interactively when the script runs
    WINDOWS_PASSWORD=""

    # --- WinRM Configuration ---
    # Authentication mechanism: 'negotiate', 'ntlm', 'basic', 'credssp', 'kerberos'
    WINRM_AUTH="negotiate"
    # Use SSL for WinRM connection (requires port 5986 and proper cert setup on server)
    WINRM_SSL="False" # Use True or False

    # --- Pi-hole Server Details ---
    PIHOLE_SERVER="10.2.3.7"
    PIHOLE_USERNAME="your_pihole_ssh_user" # e.g., 'pi'

    # --- Pi-hole Authentication ---
    # Option 1: Provide path to your private SSH key (Recommended)
    # Ensure the key file is readable only by your user (chmod 600)
    PIHOLE_SSH_KEY_PATH="/path/to/your/private/id_rsa" # e.g., "/home/user/.ssh/id_rsa" or "C:/Users/User/.ssh/id_rsa"
    # Option 2: Set SSH password here (less secure) - Leave empty if using key or want interactive prompt
    # PIHOLE_PASSWORD="YourPiholeSSHPassword"
    PIHOLE_PASSWORD=""
    # Option 3: Leave both KEY_PATH and PASSWORD empty/commented to be prompted for password interactively

    # --- Pi-hole Configuration ---
    # Path on the Pi-hole server where the dnsmasq config file will be written
    PIHOLE_OUTPUT_FILE="/etc/dnsmasq.d/05-windows-dns-import.conf"
    ```

3.  **Set Permissions:** Secure your `.env` file and SSH key:
    ```bash
    # On Linux/macOS
    chmod 600 .env
    chmod 600 /path/to/your/private/id_rsa # If using SSH key
    ```
    On Windows, use file properties to restrict access to your user account.

4.  **Configure Passwordless Sudo on Pi-hole (Recommended):**
    *   SSH into your Pi-hole server.
    *   Edit the sudoers file safely: `sudo visudo`
    *   Add the following lines at the end, replacing `your_pihole_ssh_user` with the actual username you configured in `.env`:
        ```sudoers
        # Allow your_pihole_ssh_user to restart DNS and chmod the config file without password
        your_pihole_ssh_user ALL=(ALL) NOPASSWD: /usr/local/bin/pihole restartdns
        your_pihole_ssh_user ALL=(ALL) NOPASSWD: /bin/chmod 644 /etc/dnsmasq.d/05-windows-dns-import.conf
        ```
        *Note: Verify the paths to `pihole` and `chmod` if they differ on your system (use `which pihole` and `which chmod`).*
    *   Save and exit the editor (Ctrl+X, then Y, then Enter in `nano`).

## Installation

1.  **Navigate:** Open your terminal or command prompt and navigate to the directory containing the script files.
2.  **(Optional but Recommended) Create Virtual Environment:**
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Linux/macOS
    # .\.venv\Scripts\activate # Windows PowerShell
    # .venv\Scripts\activate.bat # Windows CMD
    ```
3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Run the Script:**
    ```bash
    python dns_sync.py
    ```
2.  **Enter Credentials (if prompted):** If you did not provide passwords in the `.env` file, or if your SSH key is passphrase-protected, the script will prompt you securely in the terminal.
3.  **Check Output:** The script will log its progress to the console. Upon successful completion, the file specified by `PIHOLE_OUTPUT_FILE` (e.g., `/etc/dnsmasq.d/05-windows-dns-import.conf`) will be created/updated on the Pi-hole, and the Pi-hole DNS service will be reloaded.
4.  **Verify:** You can check the file content on the Pi-hole and test DNS resolution for one of the synced hostnames using `dig` or `nslookup` against the Pi-hole's IP address.

## Security Considerations

*   **`.env` File:** Keep this file secure and **never** commit it to version control. Use file permissions (`chmod 600`) to restrict access.
*   **Passwords:** Avoid storing passwords directly in `.env` if possible. Prefer interactive prompts or, even better, SSH keys for Pi-hole access.
*   **SSH Keys:** Using SSH keys (`PIHOLE_SSH_KEY_PATH`) is more secure than passwords. Protect your private key with a strong passphrase and secure file permissions (`chmod 600`).
*   **WinRM Security:** Configure WinRM securely on the Windows server. Use HTTPS (SSL) if possible, and restrict `TrustedHosts` appropriately if not using Kerberos/domain authentication.
*   **Passwordless Sudo:** Limiting passwordless `sudo` to only the necessary commands (`pihole restartdns`, `chmod` on the specific file) reduces risk compared to granting full passwordless sudo access.
*   **Firewalls:** Ensure firewalls on all involved machines are configured with the principle of least privilege, only allowing necessary ports (SSH: 22, WinRM: 5985/5986) from trusted sources.

## Automation (Optional)

You can automate the script using task schedulers:

*   **Linux/macOS:** Use `cron`. Edit the crontab with `crontab -e` and add an entry like:
    ```cron
    # Run DNS sync every hour
    0 * * * * /path/to/.venv/bin/python /path/to/your/project/dns_sync.py >> /path/to/your/project/dns_sync.log 2>&1
    ```
    *(Ensure you use the full path to the python executable *within your virtual environment* and the script. Using SSH keys is essential for non-interactive cron jobs).*
*   **Windows:** Use Task Scheduler. Create a task to run `python.exe` (preferably from your virtual environment) with the script path as an argument. Ensure the task runs as a user with appropriate permissions and secure credential handling.

## Troubleshooting

*   **WinRM Connection Errors:** Check WinRM service status (`Get-Service WinRM`), firewall rules, `TrustedHosts` configuration, username/password, and specified `WINRM_AUTH` method. Review `pypsrp` documentation for error details.
*   **SSH Connection Errors:** Verify Pi-hole IP, SSH service status (`sudo systemctl status ssh`), firewall rules, username, `PIHOLE_SSH_KEY_PATH` correctness and permissions, SSH key passphrase (if any), or `PIHOLE_PASSWORD`. Check `paramiko` error messages.
*   **Permission Denied (Pi-hole):** Check SSH user permissions on `/etc/dnsmasq.d/`, verify the passwordless `sudo` configuration is correct and active for the specific user and commands.
*   **Script Errors:** Check the console output and any generated log files for Python tracebacks or error messages from the script's logging. Ensure all prerequisites and dependencies are met.
*   **No Records Found:** Verify the `WINDOWS_ZONE_NAME` is correct and exists on the `WINDOWS_DNS_SERVER`. Check the permissions of the `WINDOWS_USERNAME`. Ensure the zone actually contains A, AAAA, or CNAME records (excluding the '@' record).

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
---