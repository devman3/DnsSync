import getpass
import io
import logging
import os
import sys
from dotenv import load_dotenv
from pypsrp.client import Client
from paramiko import SSHClient, AutoAddPolicy, RSAKey, Ed25519Key, ECDSAKey, DSSKey
from paramiko.ssh_exception import AuthenticationException, SSHException

# --- Load Configuration from .env file ---
load_dotenv() # Load variables from .env file in the current directory

# Get variables from environment, providing None as default if not found
WINDOWS_DNS_SERVER = os.getenv("WINDOWS_DNS_SERVER")
WINDOWS_ZONE_NAME = os.getenv("WINDOWS_ZONE_NAME")
WINDOWS_USERNAME = os.getenv("WINDOWS_USERNAME")
WINDOWS_PASSWORD = os.getenv("WINDOWS_PASSWORD") # Will be empty string if set to "" in .env

PIHOLE_SERVER = os.getenv("PIHOLE_SERVER")
PIHOLE_USERNAME = os.getenv("PIHOLE_USERNAME")
PIHOLE_SSH_KEY_PATH = os.getenv("PIHOLE_SSH_KEY_PATH") # Path to private key
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD") # Will be empty string if set to "" in .env
PIHOLE_OUTPUT_FILE = os.getenv("PIHOLE_OUTPUT_FILE", "/etc/dnsmasq.d/05-windows-dns-import.conf") # Default if not in .env

WINRM_AUTH = os.getenv("WINRM_AUTH", "negotiate") # Default to negotiate
# Handle boolean conversion carefully for WINRM_SSL
winrm_ssl_str = os.getenv("WINRM_SSL", "False").lower()
WINRM_SSL = winrm_ssl_str == 'true'

# --- Basic Configuration Validation ---
required_vars = {
    "WINDOWS_DNS_SERVER": WINDOWS_DNS_SERVER,
    "WINDOWS_ZONE_NAME": WINDOWS_ZONE_NAME,
    "WINDOWS_USERNAME": WINDOWS_USERNAME,
    "PIHOLE_SERVER": PIHOLE_SERVER,
    "PIHOLE_USERNAME": PIHOLE_USERNAME,
}

missing_vars = [k for k, v in required_vars.items() if not v]
if missing_vars:
    logging.error(f"Missing required configuration variables in .env file: {', '.join(missing_vars)}")
    sys.exit(1)

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions --- (Identical to the previous version)

def get_private_key(key_path):
    """Attempts to load a private key from a given path."""
    if not key_path or not os.path.exists(key_path):
        logging.debug(f"SSH key path '{key_path}' not provided or does not exist.")
        return None

    key_types = [Ed25519Key, ECDSAKey, RSAKey, DSSKey] # Prioritize modern keys
    key_password = None
    key = None

    # Try loading without password first
    for key_type in key_types:
        try:
            key = key_type.from_private_key_file(key_path, password=None)
            logging.info(f"Loaded SSH key type {key_type.__name__} from {key_path} (no password needed).")
            return key
        except AuthenticationException:
             logging.debug(f"Password likely required for SSH key {key_path} (type {key_type.__name__}). Will prompt if needed.")
             # Don't prompt here, prompt only if connection fails later
             continue # Try next key type in case one doesn't need a password
        except Exception as e:
            logging.debug(f"Could not load key type {key_type.__name__} from {key_path} without password: {e}")
            continue # Try next key type

    # If we reach here, all types failed without a password OR need a password
    # We will attempt connection using the key path, and Paramiko/SSH will handle prompting if needed OR
    # it will prompt within the transfer function if AuthenticationException occurs during connect.
    # For now, just indicate a key path exists but might need a password later.
    logging.info(f"SSH key found at {key_path}. Password may be required during connection.")
    # Return the path itself, the connect logic will handle the actual key object loading with potential password
    # Correction: Let's try loading *with* password prompt *here* if the initial load failed due to AuthenticationException
    for key_type in key_types:
        try:
            # Try again, potentially prompting for password only if AuthenticationException occurred before
            key = key_type.from_private_key_file(key_path, password=None) # Check again first
            return key # Should not happen if already failed, but safety check
        except AuthenticationException:
             while key is None: # Loop for password retry
                try:
                    key_password = getpass.getpass(f"Enter passphrase for private key {key_path}: ")
                    key = key_type.from_private_key_file(key_path, password=key_password)
                    logging.info(f"Loaded SSH key type {key_type.__name__} from {key_path} with provided password.")
                    return key
                except AuthenticationException:
                    logging.warning("Incorrect passphrase entered.")
                    retry = input("Try entering passphrase again? (y/n): ").lower()
                    if retry != 'y':
                        break # Break inner loop, try next key type or fail
                except Exception as e:
                    logging.debug(f"Failed to load key type {key_type.__name__} with password: {e}")
                    break # Break inner loop, try next key type
        except Exception:
            continue # Try next key type if other error occurred

    # If key is still None after all attempts
    if key is None:
         logging.error(f"Failed to load SSH key from {key_path} after attempting password prompt.")
         return None

    return key # Should technically return the loaded key obj now

def fetch_dns_records_psrp(server, username, password, zone_name, auth, use_ssl):
    """Fetches DNS records from Windows DNS using PowerShell Remoting."""
    logging.info(f"Connecting to Windows DNS Server {server} via WinRM...")
    try:
        # Prompt for password if not provided in .env
        if not password:
            password = getpass.getpass(f"Enter password for Windows user {username} on {server}: ")

        client = Client(server,
                        username=username,
                        password=password,
                        auth=auth,
                        ssl=use_ssl,
                        cert_validation=False) # Set True in production if using a trusted cert

        # Use ConvertTo-Json for easier parsing in Python
        script_json = f"""
        Get-DnsServerResourceRecord -ZoneName "{zone_name}" -ComputerName "{server}" -RRType A, AAAA, CNAME |
        Where-Object {{ $_.HostName -ne '@' }} |
        Select-Object HostName, RecordType, @{{Name='RecordDataString'; Expression={{$_.RecordData | ConvertTo-Json -Depth 2 -Compress}}}} | ConvertTo-Json -Depth 5 -Compress
        """
        # Notes on JSON: Select converts RecordData object to JSON string first, then the whole result is JSON array.

        logging.info("Executing PowerShell command to fetch DNS records...")
        output_json, streams, had_errors = client.execute_ps(script_json)

        if had_errors:
            logging.error("PowerShell errors encountered:")
            # Try to decode stderr for better error messages
            error_messages = []
            for error_record in streams.error:
                try:
                    error_messages.append(error_record.get('Exception', {}).get('Message', str(error_record)))
                except Exception:
                    error_messages.append(str(error_record)) # Fallback
            logging.error("\n".join(error_messages))
            return None

        if not output_json or not output_json.strip():
             logging.warning("No records found or command returned empty output.")
             return []

        import json
        try:
            records_data = json.loads(output_json)
            # Ensure it's a list
            if not isinstance(records_data, list):
                records_data = [records_data] # Handle case where only one record is returned

            # Now parse the inner JSON string for RecordData
            parsed_records = []
            for record in records_data:
                try:
                    record_data_obj = json.loads(record['RecordDataString'])
                    record['RecordData'] = record_data_obj # Replace string with object
                    del record['RecordDataString'] # Clean up
                    parsed_records.append(record)
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                     logging.warning(f"Could not parse inner RecordData for record '{record}': {e}")

            return parsed_records
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse main JSON output: {e}")
            logging.error(f"Raw JSON output received:\n{output_json}")
            return None
        except Exception as e:
             logging.error(f"Unexpected error processing PowerShell output: {e}")
             return None


    except Exception as e:
        logging.error(f"Failed to connect or execute command on Windows server {server}: {e}")
        # Add more specific error handling if possible, e.g., for WinRM connection errors
        return None

def format_for_pihole(records, zone_name):
    """Formats DNS records for Pi-hole dnsmasq."""
    if not records:
        return ""

    output_lines = []
    output_lines.append(f"# Auto-generated DNS entries from Windows DNS Zone: {zone_name}")
    output_lines.append(f"# Source: {WINDOWS_DNS_SERVER}")
    output_lines.append(f"# Generated: {logging.Formatter().formatTime(logging.LogRecord(None, None, '', 0, '', (), None, None))}") # Add timestamp
    output_lines.append("# ---- Start of Records ----")

    count = 0
    for record in records:
        try:
            # PowerShell output usually gives relative hostname
            hostname = record.get('HostName')
            record_type = record.get('RecordType')
            record_data = record.get('RecordData') # This should be a dict

            if not all([hostname, record_type, record_data]):
                logging.warning(f"Skipping record due to missing data: {record}")
                continue

            # Construct FQDN
            fqdn = f"{hostname}.{zone_name}"

            if record_type == 'A' and 'IPv4Address' in record_data:
                ip = record_data['IPv4Address']
                # Add both FQDN and short name resolution
                output_lines.append(f"address=/{fqdn}/{ip}")
                # Optionally add short name if desired, might conflict if multiple zones exist in Pi-hole
                # output_lines.append(f"address=/{hostname}/{ip}") # Uncomment carefully
                count += 1
            elif record_type == 'AAAA' and 'IPv6Address' in record_data:
                 ip = record_data['IPv6Address']
                 output_lines.append(f"address=/{fqdn}/{ip}")
                 # output_lines.append(f"address=/{hostname}/{ip}") # Uncomment carefully
                 count += 1
            elif record_type == 'CNAME' and 'HostNameAlias' in record_data:
                # Ensure alias target is fully qualified if necessary
                alias_target = record_data['HostNameAlias']
                # Assume PowerShell gives FQDN for CNAME target, remove trailing dot if present
                alias_target_clean = alias_target.rstrip('.')

                output_lines.append(f"cname={fqdn},{alias_target_clean}")
                # Also allow CNAME resolution via short name? Risky if target is external.
                # output_lines.append(f"cname={hostname},{alias_target_clean}") # Uncomment carefully
                count += 1
            else:
                logging.debug(f"Skipping unsupported record type or missing data: Type={record_type}, Data={record_data}")

        except Exception as e:
            logging.warning(f"Skipping record due to formatting error: {record} - Error: {e}")
            continue

    logging.info(f"Formatted {count} records for Pi-hole (using address=/ and cname= syntax).")
    output_lines.append("# ---- End of Records ----")
    return "\n".join(output_lines) + "\n"


def transfer_and_reload_pihole(server, username, password, key_path, local_data, remote_path):
    """Transfers data to Pi-hole via SCP and reloads dnsmasq via SSH."""
    ssh = None
    try:
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy()) # Warning: Less secure. Use known_hosts in prod.

        pkey_obj = None
        use_password_auth = False

        # 1. Try loading the key if path is provided
        if key_path:
            logging.info(f"Attempting to load SSH key from: {key_path}")
            pkey_obj = get_private_key(key_path) # This helper now handles interactive password prompt for the key
            if pkey_obj:
                 logging.info(f"SSH Key loaded successfully. Will attempt key-based auth.")
            else:
                 logging.warning(f"Failed to load SSH key from {key_path}. Will try password auth if password is available.")
                 if not password: # No key, no password from .env -> need to prompt
                     password = getpass.getpass(f"Enter SSH password for Pi-hole user {username}@{server}: ")
                 use_password_auth = True # Mark to use password auth
        # 2. If no key path, check if password was provided in .env
        elif password:
            logging.info("Using password from .env for Pi-hole SSH connection.")
            use_password_auth = True
        # 3. No key path, no password in .env -> prompt interactively
        else:
            logging.info("No SSH key path or password in .env. Prompting for Pi-hole SSH password.")
            password = getpass.getpass(f"Enter SSH password for Pi-hole user {username}@{server}: ")
            use_password_auth = True

        # Connect
        logging.info(f"Connecting to Pi-hole {server} via SSH...")
        auth_kwargs = {'hostname': server, 'username': username, 'timeout': 15}
        if use_password_auth:
            auth_kwargs['password'] = password
            auth_kwargs['look_for_keys'] = False # Don't accidentally use default keys if password fails
        else: # Use key
            auth_kwargs['pkey'] = pkey_obj
            # Password might still be needed for sudo later, but not for connection itself

        ssh.connect(**auth_kwargs)
        logging.info(f"SSH connection established to {server}.")

        # Transfer file using SCP
        logging.info(f"Uploading formatted records to {server}:{remote_path}")
        sftp = ssh.open_sftp()
        try:
            # Use BytesIO to upload string data directly
            with io.BytesIO(local_data.encode('utf-8')) as data_stream:
                sftp.putfo(data_stream, remote_path)
            sftp.close()
            logging.info("File uploaded successfully.")

            # Set permissions (using sudo) - more robust if user doesn't own /etc/dnsmasq.d
            # Need to handle potential sudo password prompt if NOPASSWD isn't set
            chmod_command = f"sudo chmod 644 {remote_path}"
            logging.info(f"Executing: {chmod_command}")
            stdin, stdout, stderr = ssh.exec_command(chmod_command, get_pty=True) # get_pty helps with sudo prompts sometimes

            # Note: Handling sudo password prompts programmatically is complex and insecure.
            # It's highly recommended to configure passwordless sudo for the specific command (`pihole restartdns` and `chmod`)
            # for the SSH user on the Pi-hole. Assuming passwordless sudo here.

            exit_status = stdout.channel.recv_exit_status()
            stderr_output = stderr.read().decode()
            if exit_status != 0:
                logging.warning(f"Could not set permissions on {remote_path}. Exit Status: {exit_status}. Error: {stderr_output}")
            else:
                logging.info(f"Set permissions on {remote_path} to 644.")

        except Exception as e:
            logging.error(f"SFTP/SCP or chmod failed: {e}")
            try:
                sftp.close()
            except: pass
            return False

        # Reload Pi-hole FTL (dnsmasq) using sudo
        reload_command = "sudo pihole restartdns"
        logging.info(f"Executing command on Pi-hole: '{reload_command}'")
        stdin, stdout, stderr = ssh.exec_command(reload_command, get_pty=True) # get_pty may help sudo

        # Again, assuming passwordless sudo is configured.
        exit_status = stdout.channel.recv_exit_status()
        stdout_output = stdout.read().decode()
        stderr_output = stderr.read().decode()

        if exit_status == 0:
            logging.info("Pi-hole DNS reloaded successfully.")
            if stdout_output: logging.info(f"Pi-hole stdout:\n{stdout_output}")
            if stderr_output: logging.warning(f"Pi-hole stderr output:\n{stderr_output}") # May contain non-fatal warnings
            return True
        else:
            logging.error(f"Failed to reload Pi-hole DNS. Exit status: {exit_status}")
            if stdout_output: logging.error(f"Pi-hole stdout:\n{stdout_output}")
            if stderr_output: logging.error(f"Pi-hole stderr:\n{stderr_output}")
            return False

    except AuthenticationException as ae:
        logging.error(f"Authentication failed for user {username} on Pi-hole {server}.")
        logging.error(f"Error detail: {ae}")
        logging.error("Check SSH username, password, key path, key passphrase, and SSH server configuration.")
        return False
    except SSHException as e:
        logging.error(f"SSH connection error to Pi-hole {server}: {e}")
        logging.error("Check Pi-hole IP/hostname, SSH service status, and firewall rules.")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during Pi-hole operations: {e}")
        return False
    finally:
        if ssh and ssh.get_transport() and ssh.get_transport().is_active():
            ssh.close()
            logging.info("SSH connection closed.")


# --- Main Execution ---
if __name__ == "__main__":

    # Passwords are now handled within the functions if not provided in .env
    # We pass the values read from .env (which might be None or empty string)

    # 1. Fetch records from Windows DNS
    windows_records = fetch_dns_records_psrp(
        WINDOWS_DNS_SERVER,
        WINDOWS_USERNAME,
        WINDOWS_PASSWORD, # Pass password from .env (or None/empty)
        WINDOWS_ZONE_NAME,
        WINRM_AUTH,
        WINRM_SSL
    )

    if windows_records is None:
        logging.error("Failed to fetch DNS records from Windows. Exiting.")
        sys.exit(1)

    if not windows_records:
        logging.warning("No DNS records found or returned for the specified zone. Nothing to transfer.")
        sys.exit(0) # Exit cleanly, nothing to do

    # 2. Format records for Pi-hole
    pihole_formatted_data = format_for_pihole(windows_records, WINDOWS_ZONE_NAME)

    if not pihole_formatted_data or not pihole_formatted_data.strip():
        logging.error("Failed to format records for Pi-hole or no valid records found. Exiting.")
        sys.exit(1)

    # 3. Transfer to Pi-hole and reload
    success = transfer_and_reload_pihole(
        PIHOLE_SERVER,
        PIHOLE_USERNAME,
        PIHOLE_PASSWORD, # Pass password from .env (or None/empty)
        PIHOLE_SSH_KEY_PATH, # Pass key path from .env (or None/empty)
        pihole_formatted_data,
        PIHOLE_OUTPUT_FILE
    )

    if success:
        logging.info("DNS records successfully exported from Windows DNS and imported into Pi-hole.")
        sys.exit(0)
    else:
        logging.error("Failed to transfer records to Pi-hole or reload the service.")
        sys.exit(1)