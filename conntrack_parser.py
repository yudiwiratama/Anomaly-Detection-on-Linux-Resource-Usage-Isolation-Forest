#!/usr/bin/env python3
"""
Parser untuk data conntrack dari Linux
Mengambil data dari /proc/net/nf_conntrack atau menggunakan conntrack command
"""

import subprocess
import re
from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime
import asyncio


class ConntrackParser:
    """Parser untuk data conntrack"""
    
    def __init__(self):
        self.conntrack_data = []
    
    async def get_conntrack_data_async(self) -> List[Dict[str, Any]]:
        """Mengambil data conntrack secara async (non-blocking)"""
        # Coba dengan format extended terlebih dahulu
        try:
            process = await asyncio.create_subprocess_exec(
                'conntrack', '-L', '-o', 'extended',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5.0)
            
            if process.returncode == 0 and stdout:
                output = stdout.decode('utf-8', errors='ignore')
                if output.strip():
                    connections = self._parse_conntrack_output(output)
                    if connections:
                        return connections
        except (asyncio.TimeoutError, FileNotFoundError, PermissionError):
            pass
        
        # Try with explicit extended format
        try:
            process = await asyncio.create_subprocess_exec(
                'conntrack', '-L', '-o', 'extended', '-n',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5.0)
            
            if process.returncode == 0 and stdout:
                output = stdout.decode('utf-8', errors='ignore')
                if output.strip():
                    return self._parse_conntrack_output(output)
        except (asyncio.TimeoutError, FileNotFoundError, PermissionError):
            pass
        
        # Fallback ke sync method untuk compatibility
        return self.get_conntrack_data()
    
    def get_conntrack_data(self) -> List[Dict[str, Any]]:
        """Mengambil data conntrack dari sistem"""
        # Coba dengan format extended terlebih dahulu (untuk mendapatkan bytes)
        try:
            result = subprocess.run(
                ['conntrack', '-L', '-o', 'extended'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                connections = self._parse_conntrack_output(result.stdout)
                if connections:
                    return connections
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            pass
        
        # Try with explicit extended format
        try:
            result = subprocess.run(
                ['conntrack', '-L', '-o', 'extended', '-n'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                connections = self._parse_conntrack_output(result.stdout)
                return connections
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass
        
        # Fallback ke format default jika extended tidak tersedia
        try:
            result = subprocess.run(
                ['conntrack', '-L'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_conntrack_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass
        
        # Fallback ke /proc/net/nf_conntrack
        try:
            with open('/proc/net/nf_conntrack', 'r') as f:
                content = f.read()
                if content.strip():
                    return self._parse_proc_conntrack(content)
        except (FileNotFoundError, PermissionError):
            pass
        
        # Fallback ke /proc/net/ip_conntrack (untuk kernel lama)
        try:
            with open('/proc/net/ip_conntrack', 'r') as f:
                content = f.read()
                if content.strip():
                    return self._parse_proc_conntrack(content)
        except (FileNotFoundError, PermissionError):
            pass
        
        return []
    
    def _parse_conntrack_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse output dari conntrack command (optimized)"""
        connections = []
        # Pre-compile known states set untuk faster lookup
        known_states_set = {'TIME_WAIT', 'ESTABLISHED', 'CLOSE', 'CLOSE_WAIT', 'SYN_SENT', 
                           'SYN_RECV', 'FIN_WAIT', 'LAST_ACK', 'LISTEN', 'NEW', 'RELATED', 'NONE'}
        
        # Split lines lebih efisien (skip empty lines early)
        lines = [line for line in output.split('\n') if line.strip()]
        
        for line in lines:
            if not line.strip():
                continue
            
            conn = {}
            # Format:
            # UDP: udp      17 3 src=10.233.102.187 dst=172.18.101.57 sport=48106 dport=53 ...
            # TCP: tcp      6 94 TIME_WAIT src=10.233.102.187 dst=44.193.130.88 sport=43022 dport=443 ...
            # Format: <protocol> <protocol_num> <timeout> [<STATE>] <key=value> ...
            # Index:     0            1            2         3         4+
            parts = line.split()
            if len(parts) < 4:
                continue
            
            # Protocol parsing - handle both formats:
            # Extended: ipv4 <layer> <protocol> <timeout> [<STATE>] ...
            # Default: <protocol> <protocol_num> <timeout> [<STATE>] ...
            if parts[0] in ['ipv4', 'ipv6']:
                # Extended format: protocol is at index 2
                if len(parts) > 2:
                    conn['protocol'] = parts[2].lower()
                else:
                    conn['protocol'] = parts[0]
            else:
                # Default format: protocol is at index 0
                conn['protocol'] = parts[0].lower()
            
            # State parsing - handle both formats
            # Extended: ipv4 <layer> <protocol> <timeout> [<STATE>] ...
            # Default: <protocol> <protocol_num> <timeout> [<STATE>] ...
            if parts[0] in ['ipv4', 'ipv6']:
                # Extended format: ipv4 <layer> <protocol> <protocol_num> <timeout> [<STATE>] ...
                # State is at index 5 (after ipv4, layer, protocol, protocol_num, timeout)
                state_idx = 5
                if len(parts) > 5:
                    if parts[5] in known_states_set or ('=' not in parts[5] and not parts[5].isdigit() and not parts[5].startswith('[')):
                        conn['state'] = parts[5]
                        state_idx = 6
                    else:
                        conn['state'] = 'NONE'
                        state_idx = 5
                else:
                    conn['state'] = 'NONE'
                    state_idx = 5
            else:
                # Default format: state is at index 3 (after protocol, protocol_num, timeout)
                state_idx = 3
                if len(parts) > 3:
                    if parts[3] in known_states_set or ('=' not in parts[3] and not parts[3].isdigit() and not parts[3].startswith('[')):
                        conn['state'] = parts[3]
                        state_idx = 4
                    else:
                        conn['state'] = 'NONE'
                        state_idx = 3
                else:
                    conn['state'] = 'NONE'
                    state_idx = 3
            
            # Parse key-value pairs (mulai dari setelah state atau langsung setelah timeout)
            # Track bytes untuk kedua direction (original dan reply)
            bytes_sent = 0
            bytes_recv = 0
            first_bytes_seen = False
            
            for part in parts[state_idx:]:
                if '=' in part:
                    key, value = part.split('=', 1)
                    # Hanya ambil yang pertama untuk src/dst/sport/dport (karena ada duplicate untuk reply)
                    if key in ['src', 'dst', 'sport', 'dport'] and key not in conn:
                        conn[key] = value
                    # Ambil mark dan use (bisa muncul kapan saja, ambil yang terakhir jika ada duplikat)
                    elif key in ['mark', 'use']:
                        conn[key] = value
                    # Parse bytes - ada dua bytes field (satu untuk original, satu untuk reply)
                    elif key == 'bytes':
                        try:
                            bytes_val = int(value)
                            if not first_bytes_seen:
                                # Bytes pertama adalah untuk original direction (sent)
                                bytes_sent = bytes_val
                                first_bytes_seen = True
                            else:
                                # Bytes kedua adalah untuk reply direction (received)
                                bytes_recv = bytes_val
                        except ValueError:
                            pass
                elif part.startswith('[') and part.endswith(']'):
                    # Handle flags seperti [ASSURED], [UNREPLIED]
                    flags = part.strip('[]')
                    conn['flags'] = flags
                    # Parse individual flags
                    if 'ASSURED' in flags:
                        conn['assured'] = True
                    if 'UNREPLIED' in flags:
                        conn['unreplied'] = True
            
            # Set bytes (selalu set, meskipun 0)
            conn['bytes_sent'] = bytes_sent
            conn['bytes_recv'] = bytes_recv
            conn['total_bytes'] = bytes_sent + bytes_recv
            
            if 'src' in conn and 'dst' in conn:
                connections.append(conn)
        
        return connections
    
    def _parse_proc_conntrack(self, content: str) -> List[Dict[str, Any]]:
        """Parse /proc/net/nf_conntrack format"""
        connections = []
        lines = content.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            
            conn = {}
            # Format: ipv4     2 tcp      6 119 TIME_WAIT src=192.168.1.100 dst=10.0.0.1 sport=54321 dport=80 ...
            parts = line.split()
            if len(parts) < 4:
                continue
            
            conn['protocol'] = parts[2] if len(parts) > 2 else 'unknown'
            conn['state'] = parts[3] if len(parts) > 3 else 'UNKNOWN'
            
            # Parse key-value pairs
            for part in parts[4:]:
                if '=' in part:
                    key, value = part.split('=', 1)
                    conn[key] = value
            
            if 'src' in conn and 'dst' in conn:
                connections.append(conn)
        
        return connections
    
    def aggregate_by_protocol(self, connections: List[Dict[str, Any]]) -> Dict[str, int]:
        """Agregasi berdasarkan protocol"""
        result = defaultdict(int)
        for conn in connections:
            protocol = conn.get('protocol', 'unknown').upper()
            result[protocol] += 1
        return dict(result)
    
    def aggregate_by_state(self, connections: List[Dict[str, Any]]) -> Dict[str, int]:
        """Agregasi berdasarkan state"""
        result = defaultdict(int)
        for conn in connections:
            state = conn.get('state', 'UNKNOWN')
            result[state] += 1
        return dict(result)
    
    def aggregate_by_source_ip(self, connections: List[Dict[str, Any]], top_n: int = 20) -> List[Dict[str, Any]]:
        """Agregasi berdasarkan source IP (top N)"""
        result = defaultdict(int)
        for conn in connections:
            src = conn.get('src', 'unknown')
            result[src] += 1
        
        sorted_result = sorted(result.items(), key=lambda x: x[1], reverse=True)
        return [{'ip': ip, 'count': count} for ip, count in sorted_result[:top_n]]
    
    def aggregate_by_destination_ip(self, connections: List[Dict[str, Any]], top_n: int = 20) -> List[Dict[str, Any]]:
        """Agregasi berdasarkan destination IP (top N)"""
        result = defaultdict(int)
        for conn in connections:
            dst = conn.get('dst', 'unknown')
            result[dst] += 1
        
        sorted_result = sorted(result.items(), key=lambda x: x[1], reverse=True)
        return [{'ip': ip, 'count': count} for ip, count in sorted_result[:top_n]]
    
    def aggregate_by_port(self, connections: List[Dict[str, Any]], port_type: str = 'dport', top_n: int = 20) -> List[Dict[str, Any]]:
        """Agregasi berdasarkan port (source atau destination)"""
        result = defaultdict(int)
        for conn in connections:
            port = conn.get(port_type, 'unknown')
            if port != 'unknown':
                result[port] += 1
        
        sorted_result = sorted(result.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0, reverse=True)
        return [{'port': port, 'count': count} for port, count in sorted_result[:top_n]]
    
    def group_by_protocol_state(self, connections: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
        """Grouping berdasarkan protocol dan state"""
        result = defaultdict(lambda: defaultdict(int))
        for conn in connections:
            protocol = conn.get('protocol', 'unknown').upper()
            state = conn.get('state', 'UNKNOWN')
            result[protocol][state] += 1
        
        return {k: dict(v) for k, v in result.items()}
    
    def get_connection_summary(self, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ringkasan lengkap koneksi"""
        return {
            'total_connections': len(connections),
            'by_protocol': self.aggregate_by_protocol(connections),
            'by_state': self.aggregate_by_state(connections),
            'top_source_ips': self.aggregate_by_source_ip(connections),
            'top_destination_ips': self.aggregate_by_destination_ip(connections),
            'top_destination_ports': self.aggregate_by_port(connections, 'dport'),
            'top_source_ports': self.aggregate_by_port(connections, 'sport'),
            'protocol_state_matrix': self.group_by_protocol_state(connections),
            'timestamp': datetime.now().isoformat()
        }
    
    def get_grouping_stats(self, connections: List[Dict[str, Any]], group_by: str) -> Dict[str, Dict[str, Any]]:
        """Get grouping statistics dengan count dan bytes untuk semua values (bukan hanya top N)"""
        stats = defaultdict(lambda: {'count': 0, 'bytes_sent': 0, 'bytes_recv': 0, 'total_bytes': 0})
        
        for conn in connections:
            key = None
            
            if group_by == 'protocol':
                key = conn.get('protocol', 'unknown').upper()
            elif group_by == 'state':
                key = conn.get('state', 'UNKNOWN')
            elif group_by == 'src_ip':
                key = conn.get('src', 'unknown')
            elif group_by == 'dst_ip':
                key = conn.get('dst', 'unknown')
            elif group_by == 'sport':
                key = conn.get('sport', 'unknown')
            elif group_by == 'dport':
                key = conn.get('dport', 'unknown')
            elif group_by == 'port':
                # Combine source and destination ports
                sport = conn.get('sport', 'unknown')
                dport = conn.get('dport', 'unknown')
                key = f"{sport}:{dport}"
            
            if key and key != 'unknown':
                stats[key]['count'] += 1
                # Bytes tracking (jika tersedia di future)
                stats[key]['bytes_sent'] += int(conn.get('bytes_sent', 0))
                stats[key]['bytes_recv'] += int(conn.get('bytes_recv', 0))
                stats[key]['total_bytes'] = stats[key]['bytes_sent'] + stats[key]['bytes_recv']
        
        return dict(stats)
    
    def get_all_groupings(self, connections: List[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Get semua grouping statistics sekaligus"""
        return {
            'by_protocol': self.get_grouping_stats(connections, 'protocol'),
            'by_state': self.get_grouping_stats(connections, 'state'),
            'by_src_ip': self.get_grouping_stats(connections, 'src_ip'),
            'by_dst_ip': self.get_grouping_stats(connections, 'dst_ip'),
            'by_sport': self.get_grouping_stats(connections, 'sport'),
            'by_dport': self.get_grouping_stats(connections, 'dport'),
            'by_port': self.get_grouping_stats(connections, 'port')
        }

