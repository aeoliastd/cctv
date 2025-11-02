#!/usr/bin/env python3
"""
Network scanner and setup tool for Tapo C211 camera.
Automatically scans the network to find ONVIF cameras with confirmation prompts.
"""

import socket
import ipaddress
import json
import sys
import os
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from onvif import ONVIFCamera


def get_local_network():
    """Get the local network IP range."""
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Get network address
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network.network_address), str(network.broadcast_address)
    except Exception as e:
        print(f"Error determining local network: {e}")
        return None, None


def check_port(ip, port, timeout=1):
    """Check if a port is open on the given IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def check_onvif_service(ip, port, username="admin", password="", verbose=False):
    """Check if an ONVIF service is available at the given IP and port."""
    try:
        if verbose:
            print(f"  Trying port {port}...", end=' ', flush=True)
        camera = ONVIFCamera(ip, port, username, password)
        device_service = camera.create_devicemgmt_service()
        device_info = device_service.GetDeviceInformation()
        if verbose:
            print("✓")
        return {
            'ip': ip,
            'port': port,
            'manufacturer': device_info.Manufacturer,
            'model': device_info.Model,
            'firmware': device_info.FirmwareVersion,
            'serial': device_info.SerialNumber,
            'hardware_id': device_info.HardwareId
        }
    except Exception as e:
        if verbose:
            print("✗")
        return None


def scan_network_for_cameras(network_start, network_end, ports=[2020, 80, 8080], username="admin", password=""):
    """Scan network for ONVIF cameras."""
    print("=" * 60)
    print("NETWORK SCAN FOR ONVIF CAMERAS")
    print("=" * 60)
    print()
    
    # Parse IP range
    try:
        start_ip = ipaddress.IPv4Address(network_start)
        end_ip = ipaddress.IPv4Address(network_end)
    except:
        print(f"Invalid IP range: {network_start} - {network_end}")
        return []
    
    # Generate IP list
    ip_list = []
    current = int(start_ip)
    end = int(end_ip)
    while current <= end:
        ip_list.append(str(ipaddress.IPv4Address(current)))
        current += 1
    
    print(f"Scanning {len(ip_list)} IP addresses on ports {ports}...")
    print("This may take a few minutes. Please wait...")
    print()
    
    found_cameras = []
    
    # First, scan for open ports
    print("Step 1: Scanning for open ports...")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for ip in ip_list:
            for port in ports:
                futures.append(executor.submit(check_port, ip, port))
        
        completed = 0
        total = len(futures)
        for future in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                print(f"  Progress: {completed}/{total} ({completed*100//total}%)", end='\r')
        
        # Collect results (we'll re-scan for ports that are open)
        print(f"\n  Port scanning complete. Checking ONVIF services...")
    
    # Now check ONVIF services on detected ports
    print("\nStep 2: Checking ONVIF services on open ports...")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for ip in ip_list:
            for port in ports:
                if check_port(ip, port, timeout=0.5):
                    futures.append(executor.submit(check_onvif_service, ip, port, username, password))
        
        completed = 0
        total = len(futures)
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            if result:
                found_cameras.append(result)
                print(f"  ✓ Found camera at {result['ip']}:{result['port']}")
                print(f"    Model: {result['manufacturer']} {result['model']}")
            if completed % 10 == 0:
                print(f"  Progress: {completed}/{total} ONVIF checks completed", end='\r')
    
    print()
    return found_cameras


def manual_ip_scan(username="admin", password=""):
    """Allow user to manually enter IP address to scan."""
    print("\n" + "=" * 60)
    print("MANUAL IP SCAN")
    print("=" * 60)
    print()
    
    ip = input("Enter camera IP address: ").strip()
    if not ip:
        return None
    
    # Validate IP
    try:
        ipaddress.IPv4Address(ip)
    except:
        print("Invalid IP address")
        return None
    
    ports = [2020, 80, 8080]
    print(f"\nScanning {ip} on ports {ports}...")
    print(f"Using username: '{username}'")
    print()
    
    # Try ONVIF on all ports, even if port scan doesn't detect them as open
    # Some cameras may not respond to port scans but still have ONVIF
    found_ports = []
    for port in ports:
        port_open = check_port(ip, port)
        if port_open:
            print(f"  Port {port} is open, checking ONVIF service...")
            found_ports.append(port)
        else:
            print(f"  Port {port} appears closed, but trying ONVIF anyway...")
    
    print()
    print("Checking ONVIF service on all ports...")
    for port in ports:
        camera_info = check_onvif_service(ip, port, username, password, verbose=True)
        if camera_info:
            print(f"  ✓ Found ONVIF camera on port {port}!")
            return camera_info
    
    print(f"\n✗ No ONVIF service found at {ip} on ports {ports}.")
    print("Possible reasons:")
    print("  - Wrong IP address")
    print("  - Incorrect username/password")
    print("  - ONVIF not enabled on camera")
    print("  - Camera uses a different port")
    return None


def confirm_camera(camera_info):
    """Ask user to confirm if this is the correct camera."""
    print("\n" + "=" * 60)
    print("CAMERA FOUND")
    print("=" * 60)
    print()
    print(f"IP Address:     {camera_info['ip']}")
    print(f"Port:           {camera_info['port']}")
    print(f"Manufacturer:   {camera_info['manufacturer']}")
    print(f"Model:          {camera_info['model']}")
    print(f"Firmware:       {camera_info['firmware']}")
    print(f"Serial Number:  {camera_info.get('serial', 'N/A')}")
    print()
    
    response = input("Is this your Tapo C211 camera? (y/n): ").strip().lower()
    return response == 'y' or response == 'yes'


def load_config():
    """Load existing config.json if it exists."""
    config_path = "config.json"
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load existing config.json: {e}")
            return None
    return None


def update_config(camera_ip=None, camera_port=None, username=None, password=None):
    """Update config.json with camera settings."""
    config_path = "config.json"
    
    try:
        # Load existing config or create default
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            config = {
                "camera": {},
                "display": {"window_name": "Tapo Camera Feed"}
            }
        
        # Update camera settings only if provided
        if camera_ip is not None:
            config["camera"]["host"] = camera_ip
        if camera_port is not None:
            config["camera"]["port"] = camera_port
        if username is not None:
            config["camera"]["username"] = username
        if password is not None:
            config["camera"]["password"] = password
        
        # Ensure camera section exists
        if "camera" not in config:
            config["camera"] = {}
        if "display" not in config:
            config["display"] = {"window_name": "Tapo Camera Feed"}
        
        # Save config
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"\n✓ Configuration saved to {config_path}")
        return True
    except Exception as e:
        print(f"\n✗ Error saving config: {e}")
        return False


def main():
    """Main function to run camera discovery."""
    import os
    
    print("=" * 60)
    print("TAPO C211 CAMERA DISCOVERY TOOL")
    print("=" * 60)
    print()
    
    # Check for existing config
    existing_config = load_config()
    if existing_config and existing_config.get("camera") and existing_config["camera"].get("host"):
        print("📋 Existing configuration detected in config.json:")
        print()
        camera_config = existing_config["camera"]
        print(f"  Host:      {camera_config.get('host', 'N/A')}")
        print(f"  Port:      {camera_config.get('port', 'N/A')}")
        print(f"  Username:  {camera_config.get('username', 'N/A')}")
        print(f"  Password:  {'*' * len(camera_config.get('password', '')) if camera_config.get('password') else 'N/A'}")
        print()
        print("Reusing existing configuration.")
        print("If you want to reset, delete config.json and run this script again.")
        print()
        
        reuse = input("Use existing configuration? (y/n): ").strip().lower()
        if reuse == 'y' or reuse == 'yes':
            print("\n✓ Using existing configuration from config.json")
            print("You can run: python tapo_camera.py")
            return
        else:
            print("\nStarting new setup...")
            print()
    
    # Show instructions first
    print("📋 SETUP INSTRUCTIONS:")
    print()
    print("Before running the scan, you need to set up a Camera Account in the Tapo app:")
    print()
    print("  HOW TO SET CAMERA USERNAME/PASSWORD:")
    print("  1. Open Tapo app on your mobile device")
    print("  2. Tap on your camera to enter Live View")
    print("  3. Tap the gear icon (⚙️) at top right → Device Settings")
    print("  4. Tap 'Advanced Settings'")
    print("  5. Tap 'Camera Account'")
    print("  6. Create or view your username and password")
    print()
    print("  HOW TO FIND CAMERA IP ADDRESS:")
    print("  1. In Tapo app, go to camera Live View")
    print("  2. Tap the gear icon (⚙️) at top right → Device Settings")
    print("  3. Tap 'Device Info' to see the IP address")
    print()
    print("-" * 60)
    print()
    
    # Get username and password first
    print("First, we need your camera credentials:")
    username = input("Camera username [admin]: ").strip() or "admin"
    password = getpass.getpass("Camera password: ")
    
    if not password:
        print("\n⚠ Warning: No password entered. Some cameras may require a password.")
        proceed = input("Continue anyway? (y/n): ").strip().lower()
        if proceed != 'y' and proceed != 'yes':
            print("Cancelled.")
            return
    
    # Save credentials immediately to config.json (before any scanning)
    print("\n💾 Saving credentials to config.json...")
    update_config(username=username, password=password)
    print("Credentials saved. You won't need to enter them again if you run this script later.\n")
    
    print("\nChoose scanning method:")
    print("1. Automatic network scan (scans entire local network)")
    print("2. Manual IP address entry")
    print("3. Skip scanning, just show instructions")
    print()
    
    choice = input("Enter choice [1]: ").strip() or "1"
    
    found_camera = None
    
    if choice == "1":
        # Automatic network scan
        network_start, network_end = get_local_network()
        
        if not network_start:
            print("Could not determine local network. Using common default: 192.168.1.0/24")
            network_start = "192.168.1.0"
            network_end = "192.168.1.255"
        else:
            print(f"Detected network: {network_start} - {network_end}")
            confirm = input("Use this network range? (y/n): ").strip().lower()
            if confirm != 'y' and confirm != 'yes':
                network_start = input("Enter network start IP (e.g., 192.168.1.0): ").strip() or network_start
                network_end = input("Enter network end IP (e.g., 192.168.1.255): ").strip() or network_end
        
        found_cameras = scan_network_for_cameras(network_start, network_end, username=username, password=password)
        
        if not found_cameras:
            print("\n✗ No ONVIF cameras found on the network.")
            print("\nTrying manual scan...")
            found_camera = manual_ip_scan(username=username, password=password)
        else:
            print(f"\n✓ Found {len(found_cameras)} ONVIF camera(s):")
            print()
            for i, cam in enumerate(found_cameras, 1):
                print(f"{i}. {cam['manufacturer']} {cam['model']} at {cam['ip']}:{cam['port']}")
            
            if len(found_cameras) == 1:
                if confirm_camera(found_cameras[0]):
                    found_camera = found_cameras[0]
            else:
                selection = input(f"\nSelect camera (1-{len(found_cameras)}): ").strip()
                try:
                    idx = int(selection) - 1
                    if 0 <= idx < len(found_cameras):
                        if confirm_camera(found_cameras[idx]):
                            found_camera = found_cameras[idx]
                except:
                    print("Invalid selection")
    
    elif choice == "2":
        # Manual IP entry
        found_camera = manual_ip_scan(username=username, password=password)
    
    else:
        # Show instructions
        print("\n" + "=" * 60)
        print("MANUAL SETUP INSTRUCTIONS")
        print("=" * 60)
        print()
        print("HOW TO FIND CAMERA SETTINGS IN TAPO APP:")
        print()
        print("  📍 FIND IP ADDRESS:")
        print("  1. Open Tapo app → Tap on your camera (Live View)")
        print("  2. Tap gear icon (⚙️) at top right → Device Settings")
        print("  3. Tap 'Device Info' → View IP address")
        print()
        print("  🔐 SET USERNAME/PASSWORD (Camera Account):")
        print("  1. Open Tapo app → Tap on your camera (Live View)")
        print("  2. Tap gear icon (⚙️) at top right → Device Settings")
        print("  3. Tap 'Advanced Settings' → 'Camera Account'")
        print("  4. Create or view username and password")
        print("     (This is DIFFERENT from your Tapo account login!)")
        print()
        print("-" * 60)
        print()
        print("MANUAL CONFIGURATION:")
        print("1. Use the steps above to find IP address and set Camera Account")
        print("2. Edit config.json with your camera details:")
        print("   {")
        print('     "camera": {')
        print('       "host": "YOUR_CAMERA_IP",')
        print('       "port": 2020,')
        print('       "username": "YOUR_CAMERA_ACCOUNT_USERNAME",')
        print('       "password": "YOUR_CAMERA_ACCOUNT_PASSWORD"')
        print("     }")
        print("   }")
        print()
        print("3. Or run: python tapo_camera.py <IP> <PORT> <USERNAME> <PASSWORD>")
        print()
        return
    
    # Process found camera
    if found_camera:
        if confirm_camera(found_camera):
            update = input("\nUpdate config.json with these settings? (y/n): ").strip().lower()
            if update == 'y' or update == 'yes':
                update_config(found_camera['ip'], found_camera['port'], username, password)
                print("\n✓ Setup complete! You can now run: python tapo_camera.py")
            else:
                print("\nConfiguration not saved. You can manually edit config.json")
        else:
            print("\nCamera not confirmed. Please try scanning again or set up manually.")
    else:
        print("\nNo camera found. Please check:")
        print("  - Camera is powered on and connected to WiFi")
        print("  - Camera and computer are on the same network")
        print("  - ONVIF is enabled on the camera")
        print("  - Camera credentials are correct")
        print()
        
        # Offer to save manually entered details
        manual_save = input("Would you like to manually enter camera IP and save configuration? (y/n): ").strip().lower()
        if manual_save == 'y' or manual_save == 'yes':
            print()
            manual_ip = input("Enter camera IP address: ").strip()
            if manual_ip:
                try:
                    ipaddress.IPv4Address(manual_ip)
                    manual_port = input("Enter camera port [2020]: ").strip() or "2020"
                    try:
                        manual_port = int(manual_port)
                        update_config(manual_ip, manual_port, username, password)
                        print("\n✓ Configuration saved with manually entered details!")
                        print("You can now run: python tapo_camera.py")
                    except ValueError:
                        print("Invalid port number. Configuration not saved.")
                except:
                    print("Invalid IP address. Configuration not saved.")
            else:
                print("No IP entered. Configuration not saved.")
        else:
            # Still save credentials even if user doesn't want to enter IP
            print("\nSaving credentials to config.json (you can add IP manually later)...")
            update_config(username=username, password=password)
            print("You can manually edit config.json to add the camera IP address.")


if __name__ == "__main__":
    main()
