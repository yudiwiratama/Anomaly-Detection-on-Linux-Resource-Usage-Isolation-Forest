#!/usr/bin/env python3
"""
Anomaly Detection menggunakan Isolation Forest untuk mendeteksi koneksi yang tidak biasa
"""

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
from typing import List, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detector untuk anomaly connections menggunakan Isolation Forest"""
    
    def __init__(self, contamination=0.1, random_state=42):
        """
        Initialize anomaly detector
        
        Args:
            contamination: Expected proportion of anomalies (0.0 to 0.5)
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        self._n_estimators = 100  # Default n_estimators
    
    def _extract_features(self, connections: List[Dict[str, Any]]) -> np.ndarray:
        """
        Extract features dari connections untuk anomaly detection
        
        Features:
        - Protocol (encoded)
        - State (encoded)
        - Bytes sent (normalized)
        - Bytes received (normalized)
        - Total bytes (normalized)
        - Port number (normalized)
        - IP uniqueness score
        """
        if not connections:
            return np.array([])
        
        features = []
        protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2, 'icmpv6': 3, 'gre': 4, 'esp': 5, 'ah': 6}
        state_map = {
            'ESTABLISHED': 0, 'TIME_WAIT': 1, 'CLOSE': 2, 'CLOSE_WAIT': 3,
            'SYN_SENT': 4, 'SYN_RECV': 5, 'FIN_WAIT': 6, 'LAST_ACK': 7,
            'LISTEN': 8, 'NEW': 9, 'RELATED': 10, 'NONE': 11
        }
        
        # Collect statistics untuk normalization
        bytes_sent_list = [c.get('bytes_sent', 0) or 0 for c in connections]
        bytes_recv_list = [c.get('bytes_recv', 0) or 0 for c in connections]
        total_bytes_list = [c.get('total_bytes', 0) or 0 for c in connections]
        ports = []
        for c in connections:
            sport = c.get('sport', '0')
            dport = c.get('dport', '0')
            try:
                ports.append(int(sport) if sport.isdigit() else 0)
                ports.append(int(dport) if dport.isdigit() else 0)
            except:
                ports.append(0)
        
        # Calculate IP frequency untuk uniqueness score
        src_ips = [c.get('src', '') for c in connections]
        dst_ips = [c.get('dst', '') for c in connections]
        all_ips = src_ips + dst_ips
        ip_freq = {}
        for ip in all_ips:
            ip_freq[ip] = ip_freq.get(ip, 0) + 1
        
        max_bytes_sent = max(bytes_sent_list) if bytes_sent_list else 1
        max_bytes_recv = max(bytes_recv_list) if bytes_recv_list else 1
        max_total_bytes = max(total_bytes_list) if total_bytes_list else 1
        max_port = max(ports) if ports else 1
        max_ip_freq = max(ip_freq.values()) if ip_freq else 1
        
        for conn in connections:
            protocol = conn.get('protocol', 'unknown').lower()
            state = conn.get('state', 'NONE')
            bytes_sent = conn.get('bytes_sent', 0) or 0
            bytes_recv = conn.get('bytes_recv', 0) or 0
            total_bytes = conn.get('total_bytes', 0) or 0
            
            # Protocol encoding
            protocol_encoded = protocol_map.get(protocol, 7)  # 7 = other
            
            # State encoding
            state_encoded = state_map.get(state, 11)  # 11 = NONE
            
            # Normalized bytes (0-1 range)
            bytes_sent_norm = bytes_sent / max_bytes_sent if max_bytes_sent > 0 else 0
            bytes_recv_norm = bytes_recv / max_bytes_recv if max_bytes_recv > 0 else 0
            total_bytes_norm = total_bytes / max_total_bytes if max_total_bytes > 0 else 0
            
            # Port encoding (use destination port, normalized)
            dport = conn.get('dport', '0')
            try:
                port_num = int(dport) if dport.isdigit() else 0
                port_norm = port_num / max_port if max_port > 0 else 0
            except:
                port_norm = 0
            
            # IP uniqueness score (inverse frequency, normalized)
            src_ip = conn.get('src', '')
            dst_ip = conn.get('dst', '')
            src_freq = ip_freq.get(src_ip, 1)
            dst_freq = ip_freq.get(dst_ip, 1)
            avg_freq = (src_freq + dst_freq) / 2
            uniqueness = 1.0 - (avg_freq / max_ip_freq) if max_ip_freq > 0 else 0.5
            
            # Feature vector: [protocol, state, bytes_sent_norm, bytes_recv_norm, total_bytes_norm, port_norm, uniqueness]
            feature_vector = [
                protocol_encoded,
                state_encoded,
                bytes_sent_norm,
                bytes_recv_norm,
                total_bytes_norm,
                port_norm,
                uniqueness
            ]
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def detect_anomalies(self, connections: List[Dict[str, Any]]) -> Tuple[List[int], List[float]]:
        """
        Detect anomalies dalam connections
        
        Returns:
            Tuple of (anomaly_indices, anomaly_scores)
            - anomaly_indices: List of indices yang terdeteksi sebagai anomaly
            - anomaly_scores: List of anomaly scores (lower = more anomalous)
        """
        if not connections or len(connections) < 10:
            # Need at least 10 connections untuk meaningful detection
            return [], []
        
        try:
            # Extract features
            features = self._extract_features(connections)
            
            if len(features) == 0:
                return [], []
            
            # Fit model jika belum fitted atau data berubah
            if not self.is_fitted or self.model is None:
                n_est = getattr(self, '_n_estimators', 100)  # Use custom n_estimators if set
                self.model = IsolationForest(
                    contamination=self.contamination,
                    random_state=self.random_state,
                    n_estimators=n_est
                )
                # Fit scaler
                features_scaled = self.scaler.fit_transform(features)
                # Fit model
                self.model.fit(features_scaled)
                self.is_fitted = True
            else:
                # Just transform dengan scaler yang sudah fitted
                features_scaled = self.scaler.transform(features)
            
            # Predict anomalies
            predictions = self.model.predict(features_scaled)
            anomaly_scores = self.model.score_samples(features_scaled)
            
            # Get anomaly indices (predictions == -1 means anomaly)
            anomaly_indices = [i for i, pred in enumerate(predictions) if pred == -1]
            
            # Sort by anomaly score (most anomalous first - lower score = more anomalous)
            if anomaly_indices:
                anomaly_indices.sort(key=lambda i: anomaly_scores[i])
            
            logger.info(f"Detected {len(anomaly_indices)} anomalies out of {len(connections)} connections")
            
            return anomaly_indices, anomaly_scores.tolist()
        
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            import traceback
            traceback.print_exc()
            return [], []
    
    def get_anomaly_details(self, connections: List[Dict[str, Any]], 
                          anomaly_indices: List[int], 
                          anomaly_scores: List[float]) -> List[Dict[str, Any]]:
        """
        Get detailed information tentang anomalies
        
        Returns:
            List of anomaly details dengan connection info dan score
        """
        anomalies = []
        for idx in anomaly_indices:
            if 0 <= idx < len(connections):
                conn = connections[idx].copy()
                score = anomaly_scores[idx] if idx < len(anomaly_scores) else 0.0
                conn['anomaly_score'] = float(score)
                conn['anomaly_index'] = idx
                # Ensure total_bytes is calculated
                bytes_sent = conn.get('bytes_sent', 0) or 0
                bytes_recv = conn.get('bytes_recv', 0) or 0
                conn['total_bytes'] = bytes_sent + bytes_recv
                anomalies.append(conn)
        
        return anomalies

