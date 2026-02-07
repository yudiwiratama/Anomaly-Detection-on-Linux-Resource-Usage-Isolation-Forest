#!/usr/bin/env python3
"""
Script untuk test parser conntrack
"""

from conntrack_parser import ConntrackParser
import sys

def test_parser():
    print("🔍 Testing Conntrack Parser...")
    print("=" * 50)
    
    parser = ConntrackParser()
    
    print("\n1. Mengambil data conntrack...")
    try:
        connections = parser.get_conntrack_data()
        print(f"   ✓ Ditemukan {len(connections)} koneksi")
        
        if connections:
            print("\n2. Sample koneksi pertama:")
            sample = connections[0]
            for key, value in sample.items():
                print(f"   {key}: {value}")
            
            print("\n3. Testing agregasi...")
            summary = parser.get_connection_summary(connections)
            print(f"   Total: {summary['total_connections']}")
            print(f"   Protocol: {summary['by_protocol']}")
            print(f"   State: {summary['by_state']}")
            print("\n✅ Parser bekerja dengan baik!")
            return True
        else:
            print("\n⚠️  Tidak ada data yang ditemukan")
            print("   Kemungkinan penyebab:")
            print("   - Tidak ada koneksi aktif")
            print("   - Permission denied (jalankan dengan sudo)")
            print("   - conntrack module tidak loaded")
            return False
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_parser()
    sys.exit(0 if success else 1)

