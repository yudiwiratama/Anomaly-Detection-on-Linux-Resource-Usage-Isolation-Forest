#!/usr/bin/env python3
"""
FastAPI Backend untuk Conntrack Dashboard
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from conntrack_parser import ConntrackParser
from database import DatabaseManager
from anomaly_detector import AnomalyDetector
import atexit
import orjson
from functools import lru_cache
import time

app = FastAPI(title="Conntrack Dashboard API")

# Override JSON encoder untuk menggunakan orjson (2-3x faster)
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

class ORJSONResponse(JSONResponse):
    media_type = "application/json"
    
    def render(self, content: Any) -> bytes:
        return orjson.dumps(
            content,
            option=orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_NON_STR_KEYS
        )

# Use orjson response by default
app.default_response_class = ORJSONResponse

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

parser = ConntrackParser()
db_manager = DatabaseManager()
anomaly_detector = AnomalyDetector(contamination=0.1)  # 10% expected anomalies

# Cache untuk summary data (5 detik TTL)
_summary_cache = {
    'data': None,
    'timestamp': 0,
    'ttl': 5  # 5 detik
}

async def get_cached_summary_async():
    """Get cached summary atau refresh jika expired (async)"""
    current_time = time.time()
    if (_summary_cache['data'] is None or 
        (current_time - _summary_cache['timestamp']) > _summary_cache['ttl']):
        try:
            connections = await parser.get_conntrack_data_async()
        except:
            connections = parser.get_conntrack_data()
        if connections:
            summary = parser.get_connection_summary(connections)
            _summary_cache['data'] = summary
            _summary_cache['timestamp'] = current_time
        else:
            _summary_cache['data'] = None
    return _summary_cache['data']

def get_cached_summary():
    """Get cached summary atau refresh jika expired (sync fallback)"""
    current_time = time.time()
    if (_summary_cache['data'] is None or 
        (current_time - _summary_cache['timestamp']) > _summary_cache['ttl']):
        connections = parser.get_conntrack_data()
        if connections:
            summary = parser.get_connection_summary(connections)
            _summary_cache['data'] = summary
            _summary_cache['timestamp'] = current_time
        else:
            _summary_cache['data'] = None
    return _summary_cache['data']

# Background scheduler untuk collect data
scheduler = BackgroundScheduler()
scheduler.start()

def collect_snapshot():
    """Collect dan simpan snapshot data ke database dengan optimasi untuk large datasets"""
    try:
        connections = parser.get_conntrack_data()
        if connections:
            connection_count = len(connections)
            
            # Untuk large datasets (>50k), skip detailed metrics untuk mempercepat
            if connection_count > 50000:
                print(f"Large dataset detected ({connection_count} connections). Skipping detailed metrics for performance.")
                # Hanya simpan connections, skip detailed metrics
                try:
                    db_manager.save_snapshot(connections, None)
                    print(f"Successfully saved {connection_count} connections to database")
                except Exception as db_error:
                    print(f"Error saving to database: {db_error}")
                    import traceback
                    traceback.print_exc()
            else:
                # Get all groupings
                groupings = parser.get_all_groupings(connections)
                
                # Prepare metrics untuk database
                metrics = {}
                for group_type, group_data in groupings.items():
                    metrics[group_type] = group_data
                
                # Save to database
                db_manager.save_snapshot(connections, metrics)
    except Exception as e:
        print(f"Error collecting snapshot: {e}")
        import traceback
        traceback.print_exc()

# Schedule snapshot collection setiap 30 detik
# max_instances=1 untuk mencegah overlap jobs
scheduler.add_job(
    collect_snapshot,
    trigger=IntervalTrigger(seconds=30),
    id='collect_snapshot',
    name='Collect conntrack snapshot',
    replace_existing=True,
    max_instances=1,  # Hanya 1 instance yang bisa berjalan bersamaan
    coalesce=True,    # Jika job terlewat, jalankan sekali saja
    misfire_grace_time=60  # Grace time 60 detik sebelum dianggap misfire
)

# Collect initial snapshot
collect_snapshot()

# Cleanup on shutdown
atexit.register(lambda: scheduler.shutdown())


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve dashboard HTML"""
    try:
        return FileResponse("static/index.html")
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
            <body>
                <h1>Dashboard tidak ditemukan</h1>
                <p>Pastikan file static/index.html ada</p>
            </body>
        </html>
        """)


@app.get("/api/connections")
async def get_connections(
    limit: Optional[int] = Query(None, description="Limit jumlah koneksi yang dikembalikan (default: 10000 untuk performa)"),
    offset: Optional[int] = Query(0, description="Offset untuk pagination")
) -> Dict[str, Any]:
    """Mendapatkan koneksi conntrack dengan pagination support"""
    try:
        # Try async first, fallback to sync
        try:
            import asyncio
            connections = await parser.get_conntrack_data_async()
        except:
            connections = parser.get_conntrack_data()
        total_count = len(connections) if connections else 0
        
        # Default limit untuk large datasets
        if limit is None and total_count > 10000:
            limit = 10000  # Default limit untuk mencegah memory issues
        
        if not connections:
            # Cek apakah ada masalah permission
            import os
            import subprocess
            try:
                test_result = subprocess.run(['conntrack', '-L'], capture_output=True, timeout=2, stderr=subprocess.PIPE)
                if test_result.returncode != 0 and 'root' in test_result.stderr.decode('utf-8', errors='ignore').lower():
                    return {
                        "success": False,
                        "data": [],
                        "count": 0,
                        "total_count": 0,
                        "limit": limit,
                        "offset": offset,
                        "has_more": False,
                        "error": "Permission denied: conntrack memerlukan root access. Jalankan dengan sudo atau berikan CAP_NET_ADMIN capability."
                    }
            except:
                pass
            return {
                "success": True,
                "data": [],
                "count": 0,
                "total_count": 0,
                "limit": limit,
                "offset": offset,
                "has_more": False,
                "message": "Tidak ada data conntrack yang ditemukan. Pastikan ada koneksi aktif atau jalankan dengan sudo."
            }
        
        # Apply pagination/limit
        if limit is not None and limit > 0:
            # Limit maximum to prevent memory issues
            max_limit = 50000  # Reduced hard limit untuk 130k+ connections
            effective_limit = min(limit, max_limit)
            connections = connections[offset:offset + effective_limit]
        elif offset > 0:
            connections = connections[offset:]
        
        return {
            "success": True,
            "data": connections,
            "count": len(connections),
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(connections)) < total_count if limit else False
        }
    except Exception as e:
        import traceback
        error_detail = str(e)
        print(f"Error in get_connections: {error_detail}")
        traceback.print_exc()
        return {
            "success": False,
            "data": [],
            "count": 0,
            "total_count": 0,
            "limit": limit,
            "offset": offset,
            "has_more": False,
            "error": error_detail
        }


@app.get("/api/summary")
async def get_summary() -> Dict[str, Any]:
    """Mendapatkan ringkasan agregasi data conntrack (dengan caching dan async)"""
    try:
        # Use cached summary jika available (async)
        summary = await get_cached_summary_async()
        if summary is None:
            # Cek apakah ada masalah permission
            import subprocess
            error_msg = "Tidak ada data conntrack yang ditemukan."
            try:
                test_result = subprocess.run(['conntrack', '-L'], capture_output=True, timeout=2, stderr=subprocess.PIPE)
                if test_result.returncode != 0 and 'root' in test_result.stderr.decode('utf-8', errors='ignore').lower():
                    error_msg = "Permission denied: conntrack memerlukan root access. Jalankan server dengan sudo atau berikan CAP_NET_ADMIN capability."
            except:
                pass
            
            return {
                "success": False,
                "data": {
                    "total_connections": 0,
                    "by_protocol": {},
                    "by_state": {},
                    "top_source_ips": [],
                    "top_destination_ips": [],
                    "top_destination_ports": [],
                    "top_source_ports": [],
                    "protocol_state_matrix": {},
                    "timestamp": datetime.now().isoformat(),
                    "error": error_msg
                }
            }
        # Use cached summary jika available
        summary = get_cached_summary()
        if summary is None:
            summary = parser.get_connection_summary(connections)
        
        return {
            "success": True,
            "data": summary
        }
    except Exception as e:
        return {
            "success": False,
            "data": {
                "total_connections": 0,
                "error": f"Error memproses summary: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        }


@app.get("/api/aggregate/protocol")
async def aggregate_by_protocol() -> Dict[str, Any]:
    """Agregasi berdasarkan protocol"""
    try:
        connections = parser.get_conntrack_data()
        result = parser.aggregate_by_protocol(connections)
        return {
            "success": True,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/aggregate/state")
async def aggregate_by_state() -> Dict[str, Any]:
    """Agregasi berdasarkan state"""
    try:
        connections = parser.get_conntrack_data()
        result = parser.aggregate_by_state(connections)
        return {
            "success": True,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/aggregate/source-ip")
async def aggregate_by_source_ip(top_n: int = 10) -> Dict[str, Any]:
    """Agregasi berdasarkan source IP"""
    try:
        connections = parser.get_conntrack_data()
        result = parser.aggregate_by_source_ip(connections, top_n)
        return {
            "success": True,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/aggregate/destination-ip")
async def aggregate_by_destination_ip(top_n: int = 10) -> Dict[str, Any]:
    """Agregasi berdasarkan destination IP"""
    try:
        connections = parser.get_conntrack_data()
        result = parser.aggregate_by_destination_ip(connections, top_n)
        return {
            "success": True,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/aggregate/ports")
async def aggregate_by_ports(port_type: str = "dport", top_n: int = 10) -> Dict[str, Any]:
    """Agregasi berdasarkan port"""
    try:
        connections = parser.get_conntrack_data()
        result = parser.aggregate_by_port(connections, port_type, top_n)
        return {
            "success": True,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/group/protocol-state")
async def group_by_protocol_state() -> Dict[str, Any]:
    """Grouping berdasarkan protocol dan state"""
    try:
        connections = parser.get_conntrack_data()
        result = parser.group_by_protocol_state(connections)
        return {
            "success": True,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/groupings/all")
async def get_all_groupings() -> Dict[str, Any]:
    """Get semua grouping statistics dengan count dan bytes"""
    try:
        connections = parser.get_conntrack_data()
        groupings = parser.get_all_groupings(connections)
        return {
            "success": True,
            "data": groupings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/groupings/{group_by}")
async def get_grouping(group_by: str) -> Dict[str, Any]:
    """Get grouping statistics untuk group_by tertentu"""
    try:
        connections = parser.get_conntrack_data()
        valid_groups = ['protocol', 'state', 'src_ip', 'dst_ip', 'sport', 'dport', 'port']
        
        if group_by not in valid_groups:
            raise HTTPException(status_code=400, detail=f"Invalid group_by. Must be one of: {valid_groups}")
        
        result = parser.get_grouping_stats(connections, group_by)
        return {
            "success": True,
            "data": result
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/timeseries/{metric_type}")
async def get_timeseries(
    metric_type: str,
    metric_key: Optional[str] = Query(None, description="Specific metric key (e.g., 'TCP', '192.168.1.1')"),
    hours: Optional[int] = Query(1, description="Number of hours of data to retrieve"),
    interval_minutes: Optional[int] = Query(1, description="Interval in minutes")
) -> Dict[str, Any]:
    """Get time series data untuk metric tertentu"""
    try:
        # Map metric_type from frontend format (by_protocol) to database format (protocol)
        metric_type_map = {
            'by_protocol': 'protocol',
            'by_state': 'state',
            'by_src_ip': 'src_ip',
            'by_dst_ip': 'dst_ip',
            'by_sport': 'sport',
            'by_dport': 'dport',
            'by_port': 'port'
        }
        
        db_metric_type = metric_type_map.get(metric_type, metric_type)
        
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        
        result = db_manager.get_time_series(
            metric_type=db_metric_type,
            metric_key=metric_key,
            start_time=start_time,
            end_time=end_time,
            interval_minutes=interval_minutes
        )
        
        return {
            "success": True,
            "data": result,
            "metric_type": metric_type,
            "metric_key": metric_key,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/timeseries/metrics/list")
async def get_available_metrics() -> Dict[str, Any]:
    """Get list of available metric types dan keys"""
    try:
        # Get latest metrics to show available keys
        latest_metrics = db_manager.get_all_metrics_at_time()
        
        available = {}
        for metric_type, keys in latest_metrics.items():
            available[metric_type] = list(keys.keys())
        
        return {
            "success": True,
            "data": available
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/timeseries/connection-count")
async def get_connection_count_timeseries(
    hours: Optional[int] = Query(1, description="Number of hours of data to retrieve"),
    interval_minutes: Optional[int] = Query(1, description="Interval in minutes")
) -> Dict[str, Any]:
    """Get total connection count time series"""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        
        result = db_manager.get_connection_count_timeseries(
            start_time=start_time,
            end_time=end_time,
            interval_minutes=interval_minutes
        )
        
        # Jika tidak ada data di database, return current connection count sebagai single point
        if not result or len(result) == 0:
            connections = parser.get_conntrack_data()
            current_count = len(connections) if connections else 0
            # Return beberapa data points untuk membuat chart lebih informatif
            # Create data points untuk last hour dengan interval yang diminta
            result = []
            for i in range(max(1, (hours * 60) // interval_minutes)):
                point_time = end_time - timedelta(minutes=interval_minutes * i)
                result.insert(0, {
                    'timestamp': point_time.isoformat(),
                    'count': current_count
                })
        
        return {
            "success": True,
            "data": result,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.post("/api/database/cleanup")
async def cleanup_database(days_to_keep: int = Query(7, description="Days of data to keep")) -> Dict[str, Any]:
    """Cleanup old data from database"""
    try:
        db_manager.cleanup_old_data(days_to_keep=days_to_keep)
        return {
            "success": True,
            "message": f"Cleaned up data older than {days_to_keep} days"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/api/anomalies")
async def get_anomalies(
    limit: Optional[int] = Query(None, description="Limit jumlah anomalies yang dikembalikan (default: None = semua anomalies)"),
    min_score: Optional[float] = Query(None, description="Minimum anomaly score threshold"),
    contamination: Optional[float] = Query(None, description="Expected proportion of anomalies (0.0 to 0.5, default: 0.1)"),
    n_estimators: Optional[int] = Query(None, description="Number of trees in Isolation Forest (default: 100)")
) -> Dict[str, Any]:
    """Detect anomalies dalam connections menggunakan Isolation Forest"""
    try:
        print(f"[Anomaly Detection] Starting detection with limit={limit}, min_score={min_score}")
        
        # Get connections
        try:
            connections = await parser.get_conntrack_data_async()
        except Exception as e:
            print(f"[Anomaly Detection] Async failed, trying sync: {e}")
            connections = parser.get_conntrack_data()
        
        if not connections:
            print("[Anomaly Detection] No connections found")
            return {
                "success": False,
                "data": [],
                "count": 0,
                "total_connections": 0,
                "error": "Tidak ada koneksi yang ditemukan"
            }
        
        print(f"[Anomaly Detection] Found {len(connections)} connections")
        
        if len(connections) < 10:
            return {
                "success": True,
                "data": [],
                "count": 0,
                "total_connections": len(connections),
                "message": f"Perlu minimal 10 koneksi untuk anomaly detection (saat ini: {len(connections)})"
            }
        
        # Update detector parameters jika di-override
        if contamination is not None:
            if 0.0 <= contamination <= 0.5:
                anomaly_detector.contamination = contamination
                anomaly_detector.is_fitted = False  # Reset model untuk refit dengan parameter baru
                print(f"[Anomaly Detection] Contamination updated to {contamination}")
            else:
                print(f"[Anomaly Detection] Invalid contamination {contamination}, using default 0.1")
        
        if n_estimators is not None:
            if n_estimators > 0:
                # Create new model dengan n_estimators baru
                anomaly_detector.model = None
                anomaly_detector.is_fitted = False
                # Store n_estimators untuk digunakan saat create model
                anomaly_detector._n_estimators = n_estimators
                print(f"[Anomaly Detection] n_estimators updated to {n_estimators}")
            else:
                print(f"[Anomaly Detection] Invalid n_estimators {n_estimators}, using default 100")
        
        # Detect anomalies
        print("[Anomaly Detection] Running Isolation Forest...")
        anomaly_indices, anomaly_scores = anomaly_detector.detect_anomalies(connections)
        print(f"[Anomaly Detection] Detected {len(anomaly_indices)} anomalies")
        
        if not anomaly_indices:
            return {
                "success": True,
                "data": [],
                "count": 0,
                "total_connections": len(connections),
                "message": "Tidak ada anomaly yang terdeteksi"
            }
        
        # Get anomaly details
        anomalies = anomaly_detector.get_anomaly_details(connections, anomaly_indices, anomaly_scores)
        print(f"[Anomaly Detection] Got {len(anomalies)} anomaly details")
        
        # Filter by min_score jika provided
        if min_score is not None:
            original_count = len(anomalies)
            anomalies = [a for a in anomalies if a.get('anomaly_score', 0) <= min_score]
            print(f"[Anomaly Detection] Filtered by min_score {min_score}: {original_count} -> {len(anomalies)}")
        
        # Sort by anomaly score (most anomalous first - lower score = more anomalous)
        anomalies.sort(key=lambda x: x.get('anomaly_score', 0))
        
        # Apply limit (jika limit tidak disediakan atau None, return semua)
        original_count = len(anomalies)
        if limit is not None and limit > 0:
            # Hard limit untuk mencegah memory issues (max 10000)
            max_limit = 10000
            effective_limit = min(limit, max_limit)
            anomalies = anomalies[:effective_limit]
            print(f"[Anomaly Detection] Applied limit {effective_limit}: {len(anomalies)}/{original_count} anomalies")
        else:
            print(f"[Anomaly Detection] No limit applied: returning all {len(anomalies)} anomalies")
        
        return {
            "success": True,
            "data": anomalies,
            "count": len(anomalies),
            "total_connections": len(connections),
            "anomaly_rate": len(anomaly_indices) / len(connections) if connections else 0
        }
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[Anomaly Detection] Error: {e}")
        print(error_trace)
        return {
            "success": False,
            "data": [],
            "count": 0,
            "error": f"{str(e)}"
        }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

