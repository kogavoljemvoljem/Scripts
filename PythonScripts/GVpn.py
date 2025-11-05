import os
import subprocess
import requests
import time
import threading
import importlib.util
import logging
import platform

# Configure logging
logging.basicConfig(filename="vpn.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def install_missing_packages():
    """Ensure required Python packages are installed."""
    required_packages = ["requests"]
    for package in required_packages:
        if importlib.util.find_spec(package) is None:
            try:
                subprocess.run(["pip", "install", package], check=True)
                logging.info(f"Successfully installed {package}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to install {package}: {str(e)}")

def get_public_vpn():
    """Fetch a list of public VPN servers and return the closest one based on ping."""
    try:
        response = requests.get("https://www.vpngate.net/api/iphone/", timeout=5)
        response.raise_for_status()
        lines = response.text.split('\n')
        servers = [line.split(',') for line in lines if ',' in line and len(line.split(',')) > 6]
        if servers:
            sorted_servers = sorted(servers[1:], key=lambda x: int(x[6]) if x[6].isdigit() else float('inf'))
            host, country = sorted_servers[0][1], sorted_servers[0][2]
            logging.info(f"Selected closest VPN server: {host} ({country}, ping: {sorted_servers[0][6]}ms)")
            return host, country
        logging.warning("No valid VPN servers available.")
        return None, None
    except requests.RequestException as e:
        logging.error(f"VPN fetch failed: {str(e)}")
        return None, None

def connect_vpn(host):
    """Connect to a VPN using Windows built-in tools."""
    if not host:
        logging.error("No VPN host provided.")
        return False
    logging.info(f"Connecting to VPN: {host}")
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["rasdial", "MyVPN", host, "vpn", "vpn"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logging.error(f"VPN connection failed: {result.stderr}")
                return False
            logging.info(f"VPN connected to {host}")
            return True
        except subprocess.TimeoutExpired:
            logging.error("VPN connection timed out")
            return False
    else:
        logging.warning(f"Unsupported OS: {platform.system()}")
        return False

def disconnect_vpn():
    """Disconnect the active VPN."""
    if platform.system() == "Windows":
        try:
            result = subprocess.run(["rasdial", "MyVPN", "disconnect"], capture_output=True, text=True)
            if result.returncode == 0:
                logging.info("VPN disconnected")
                return True
            else:
                logging.error(f"Disconnect failed: {result.stderr}")
                return False
        except subprocess.CalledProcessError as e:
            logging.error(f"Disconnect error: {str(e)}")
            return False
    return False

def check_vpn():
    """Check if a VPN connection is active."""
    if platform.system() == "Windows":
        try:
            result = subprocess.check_output("rasdial", shell=True, text=True)
            is_connected = "Connected" in result
            logging.debug(f"VPN status check: {'Connected' if is_connected else 'Disconnected'}")
            return is_connected
        except subprocess.CalledProcessError as e:
            logging.error(f"VPN status check failed: {str(e)}")
            return False
    else:
        logging.warning("VPN status check not supported on non-Windows OS.")
        return False

def vpn_monitor(stop_event):
    """Continuously monitor and auto-reconnect to the closest VPN."""
    while not stop_event.is_set():
        if not check_vpn():
            host, country = get_public_vpn()
            if host:
                connect_vpn(host)
        time.sleep(30)

def main():
    """Main entry point for the VPN application."""
    if platform.system() != "Windows":
        logging.error("Non-Windows OS detected")
        return

    install_missing_packages()
    logging.info("Application started")

    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=vpn_monitor, args=(stop_event,), daemon=True)
    monitor_thread.start()

    # Keep the script running until interrupted (e.g., Ctrl+C)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("User interrupted the application")
        if check_vpn():
            disconnect_vpn()
        stop_event.set()
        logging.info("Application terminated")

if __name__ == "__main__":
    main()
