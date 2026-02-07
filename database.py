#!/usr/bin/env python3
"""
Database models dan operations untuk time series data
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
import json

Base = declarative_base()


class ConnectionSnapshot(Base):
    """Snapshot koneksi pada waktu tertentu"""
    __tablename__ = 'connection_snapshots'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    protocol = Column(String(10))
    state = Column(String(20))
    src = Column(String(45))  # IPv6 support
    dst = Column(String(45))
    sport = Column(String(10))
    dport = Column(String(10))
    flags = Column(String(50))
    mark = Column(String(10))
    use = Column(String(10))
    # Bytes tracking (jika tersedia)
    bytes_sent = Column(Integer, default=0)
    bytes_recv = Column(Integer, default=0)


class MetricSnapshot(Base):
    """Snapshot metrics agregasi pada waktu tertentu"""
    __tablename__ = 'metric_snapshots'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    metric_type = Column(String(50), index=True)  # 'protocol', 'state', 'src_ip', 'dst_ip', 'port', etc.
    metric_key = Column(String(255), index=True)  # Value dari metric (e.g., 'TCP', '192.168.1.1', '80')
    count = Column(Integer, default=0)
    bytes_sent = Column(Integer, default=0)
    bytes_recv = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)


class DatabaseManager:
    """Manager untuk database operations"""
    
    def __init__(self, db_path: str = "conntrack.db"):
        self.db_path = db_path
        self.engine = create_engine(f'sqlite:///{db_path}', echo=False, connect_args={"check_same_thread": False})
        self.SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        Base.metadata.create_all(self.engine)
        
        # Enable WAL mode for better concurrency
        try:
            with self.engine.connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                conn.execute("PRAGMA cache_size=10000;")
        except:
            pass
        
        # Create indexes for better performance
        try:
            Index('idx_metric_timestamp', MetricSnapshot.timestamp).create(self.engine, checkfirst=True)
            Index('idx_metric_type_key', MetricSnapshot.metric_type, MetricSnapshot.metric_key).create(self.engine, checkfirst=True)
            Index('idx_conn_timestamp', ConnectionSnapshot.timestamp).create(self.engine, checkfirst=True)
        except:
            pass  # Indexes might already exist
    
    def get_session(self):
        """Get database session"""
        return self.SessionLocal()
    
    def save_snapshot(self, connections: List[Dict[str, Any]], metrics: Dict[str, Any] = None):
        """Simpan snapshot koneksi dan metrics dengan batch insert untuk performa"""
        session = self.get_session()
        try:
            timestamp = datetime.now(timezone.utc)
            
            # Batch insert connections untuk performa yang lebih baik
            # Process in chunks of 500 untuk large datasets (130k+)
            batch_size = 500 if len(connections) > 100000 else 1000
            total_connections = len(connections)
            
            # Progress tracking untuk large datasets
            if total_connections > 50000:
                print(f"Saving {total_connections} connections in batches of {batch_size}...")
            
            for i in range(0, total_connections, batch_size):
                batch = connections[i:i + batch_size]
                snapshots = []
                for conn in batch:
                    snapshot = ConnectionSnapshot(
                        timestamp=timestamp,
                        protocol=conn.get('protocol'),
                        state=conn.get('state'),
                        src=conn.get('src'),
                        dst=conn.get('dst'),
                        sport=conn.get('sport'),
                        dport=conn.get('dport'),
                        flags=conn.get('flags'),
                        mark=conn.get('mark'),
                        use=conn.get('use'),
                        bytes_sent=conn.get('bytes_sent', 0),
                        bytes_recv=conn.get('bytes_recv', 0)
                    )
                    snapshots.append(snapshot)
                
                # Bulk insert batch
                session.bulk_save_objects(snapshots)
                session.flush()  # Flush untuk memastikan data tersimpan tapi belum commit
                
                # Progress update untuk large datasets
                if total_connections > 50000 and (i + batch_size) % 10000 == 0:
                    print(f"Progress: {min(i + batch_size, total_connections)}/{total_connections} connections saved")
            
            # Save aggregated metrics
            if metrics:
                # Map metric type names (by_protocol -> protocol, etc.)
                metric_type_map = {
                    'by_protocol': 'protocol',
                    'by_state': 'state',
                    'by_src_ip': 'src_ip',
                    'by_dst_ip': 'dst_ip',
                    'by_sport': 'sport',
                    'by_dport': 'dport',
                    'by_port': 'port'
                }
                
                for metric_type_key, data in metrics.items():
                    # Map to database metric_type
                    metric_type = metric_type_map.get(metric_type_key, metric_type_key)
                    
                    if isinstance(data, dict):
                        for key, value in data.items():
                            if isinstance(value, dict):
                                # Handle nested dict (e.g., {'count': 10, 'bytes_sent': 1000, 'bytes_recv': 500})
                                count = value.get('count', 0)
                                bytes_sent = value.get('bytes_sent', 0)
                                bytes_recv = value.get('bytes_recv', 0)
                                total_bytes = bytes_sent + bytes_recv
                            else:
                                # Simple count value
                                count = value if isinstance(value, int) else 0
                                bytes_sent = 0
                                bytes_recv = 0
                                total_bytes = 0
                            
                            metric = MetricSnapshot(
                                timestamp=timestamp,
                                metric_type=metric_type,
                                metric_key=str(key),
                                count=count,
                                bytes_sent=bytes_sent,
                                bytes_recv=bytes_recv,
                                total_bytes=total_bytes
                            )
                            session.add(metric)
            
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_time_series(self, metric_type: str, metric_key: str = None, 
                       start_time: datetime = None, end_time: datetime = None,
                       interval_minutes: int = 1) -> List[Dict[str, Any]]:
        """Get time series data untuk metric tertentu"""
        session = self.get_session()
        try:
            query = session.query(MetricSnapshot).filter(
                MetricSnapshot.metric_type == metric_type
            )
            
            if metric_key:
                query = query.filter(MetricSnapshot.metric_key == metric_key)
            
            if start_time:
                query = query.filter(MetricSnapshot.timestamp >= start_time)
            
            if end_time:
                query = query.filter(MetricSnapshot.timestamp <= end_time)
            
            query = query.order_by(MetricSnapshot.timestamp)
            
            results = query.all()
            
            # Group by interval
            grouped = {}
            for result in results:
                # Round timestamp to interval
                rounded_time = self._round_time(result.timestamp, interval_minutes)
                key = f"{rounded_time.isoformat()}"
                
                if key not in grouped:
                    grouped[key] = {
                        'timestamp': rounded_time.isoformat(),
                        'count': 0,
                        'bytes_sent': 0,
                        'bytes_recv': 0,
                        'total_bytes': 0
                    }
                
                grouped[key]['count'] += result.count
                grouped[key]['bytes_sent'] += result.bytes_sent
                grouped[key]['bytes_recv'] += result.bytes_recv
                grouped[key]['total_bytes'] += result.total_bytes
            
            return sorted(grouped.values(), key=lambda x: x['timestamp'])
        finally:
            session.close()
    
    def get_all_metrics_at_time(self, timestamp: datetime = None) -> Dict[str, Any]:
        """Get semua metrics pada waktu tertentu (latest jika None)"""
        session = self.get_session()
        try:
            if timestamp is None:
                # Get latest timestamp
                latest = session.query(MetricSnapshot).order_by(
                    MetricSnapshot.timestamp.desc()
                ).first()
                if not latest:
                    return {}
                timestamp = latest.timestamp
            
            query = session.query(MetricSnapshot).filter(
                MetricSnapshot.timestamp == timestamp
            )
            
            results = query.all()
            
            metrics = {}
            for result in results:
                if result.metric_type not in metrics:
                    metrics[result.metric_type] = {}
                
                metrics[result.metric_type][result.metric_key] = {
                    'count': result.count,
                    'bytes_sent': result.bytes_sent,
                    'bytes_recv': result.bytes_recv,
                    'total_bytes': result.total_bytes
                }
            
            return metrics
        finally:
            session.close()
    
    def get_grouping_stats(self, group_by: str, include_bytes: bool = True) -> Dict[str, Any]:
        """Get grouping statistics dari latest snapshot"""
        session = self.get_session()
        try:
            # Get latest timestamp
            latest = session.query(MetricSnapshot).order_by(
                MetricSnapshot.timestamp.desc()
            ).first()
            
            if not latest:
                return {}
            
            timestamp = latest.timestamp
            
            # Map group_by to metric_type
            metric_type_map = {
                'protocol': 'protocol',
                'state': 'state',
                'src_ip': 'src_ip',
                'dst_ip': 'dst_ip',
                'port': 'port',
                'sport': 'sport',
                'dport': 'dport'
            }
            
            metric_type = metric_type_map.get(group_by)
            if not metric_type:
                return {}
            
            query = session.query(MetricSnapshot).filter(
                MetricSnapshot.timestamp == timestamp,
                MetricSnapshot.metric_type == metric_type
            )
            
            results = query.all()
            
            stats = {}
            for result in results:
                stats[result.metric_key] = {
                    'count': result.count,
                    'bytes_sent': result.bytes_sent if include_bytes else 0,
                    'bytes_recv': result.bytes_recv if include_bytes else 0,
                    'total_bytes': result.total_bytes if include_bytes else 0
                }
            
            return stats
        finally:
            session.close()
    
    def get_connection_count_timeseries(self, start_time: datetime = None, 
                                       end_time: datetime = None,
                                       interval_minutes: int = 1) -> List[Dict[str, Any]]:
        """Get total connection count time series"""
        session = self.get_session()
        try:
            # Get distinct timestamps first (each snapshot has same timestamp for all connections at that time)
            from sqlalchemy import func, distinct
            
            # Query untuk mendapatkan distinct timestamps dan count per timestamp
            subquery = session.query(
                ConnectionSnapshot.timestamp,
                func.count(ConnectionSnapshot.id).label('count')
            )
            
            if start_time:
                subquery = subquery.filter(ConnectionSnapshot.timestamp >= start_time)
            
            if end_time:
                subquery = subquery.filter(ConnectionSnapshot.timestamp <= end_time)
            
            subquery = subquery.group_by(ConnectionSnapshot.timestamp).order_by(ConnectionSnapshot.timestamp)
            
            results = subquery.all()
            
            # Group by rounded interval
            grouped = {}
            for timestamp, count in results:
                rounded_time = self._round_time(timestamp, interval_minutes)
                key = f"{rounded_time.isoformat()}"
                
                if key not in grouped:
                    grouped[key] = {
                        'timestamp': rounded_time.isoformat(),
                        'count': 0
                    }
                
                grouped[key]['count'] += count
            
            return sorted(grouped.values(), key=lambda x: x['timestamp'])
        finally:
            session.close()
    
    def _round_time(self, dt: datetime, interval_minutes: int) -> datetime:
        """Round datetime to nearest interval"""
        minutes = (dt.minute // interval_minutes) * interval_minutes
        return dt.replace(minute=minutes, second=0, microsecond=0)
    
    def cleanup_old_data(self, days_to_keep: int = 7):
        """Hapus data lebih lama dari days_to_keep"""
        session = self.get_session()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            
            # Delete old snapshots
            session.query(ConnectionSnapshot).filter(
                ConnectionSnapshot.timestamp < cutoff
            ).delete()
            
            session.query(MetricSnapshot).filter(
                MetricSnapshot.timestamp < cutoff
            ).delete()
            
            session.commit()
        finally:
            session.close()

