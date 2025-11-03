"""
Test script to verify packet capture is working
Run this to diagnose packet capture issues
"""

from scapy.all import sniff, get_if_list
import sys

def test_interfaces():
    """List available interfaces"""
    print("Available network interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"  {i+1}. {iface}")
    return interfaces

def test_capture(interface=None, count=5):
    """Test capturing a few packets"""
    print(f"\nTesting packet capture...")
    print(f"Interface: {interface or 'auto-detect'}")
    print(f"Capturing {count} packets...")
    print("(Try browsing the web or pinging something to generate traffic)")
    print("-" * 50)
    
    try:
        packets = sniff(iface=interface, count=count, timeout=10)
        print(f"\n✓ Successfully captured {len(packets)} packets!")
        
        for i, packet in enumerate(packets, 1):
            if packet.haslayer('IP'):
                src = packet['IP'].src
                dst = packet['IP'].dst
                proto = packet['IP'].proto
                print(f"  Packet {i}: {src} -> {dst} (proto: {proto})")
            else:
                print(f"  Packet {i}: {packet.summary()}")
        
        return True
    except PermissionError:
        print("\n✗ Permission denied!")
        print("   ERROR: You need root/administrator privileges to capture packets.")
        print("   Try running with: sudo python test_capture.py")
        return False
    except OSError as e:
        print(f"\n✗ OS Error: {e}")
        print("   This might be a permission issue or interface problem.")
        return False
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False

if __name__ == '__main__':
    print("=" * 50)
    print("Packet Capture Test Script")
    print("=" * 50)
    
    interfaces = test_interfaces()
    
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = None
        print("\nNo interface specified, using auto-detect")
    
    success = test_capture(interface, count=5)
    
    if success:
        print("\n" + "=" * 50)
        print("✓ Packet capture is working!")
        print("=" * 50)
    else:
        print("\n" + "=" * 50)
        print("✗ Packet capture failed. Check the errors above.")
        print("=" * 50)
        print("\nTroubleshooting:")
        print("1. Make sure you're running with sudo: sudo python test_capture.py")
        print("2. Try specifying an interface: sudo python test_capture.py en0")
        print("3. On macOS, you might need to grant network permissions")
        print("4. Check if the interface exists and is active")

