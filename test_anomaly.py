#!/usr/bin/env python3
"""
Test script untuk anomaly detection
Menjalankan berbagai test cases untuk memverifikasi fitur anomaly detection
"""

import requests
import json
import time
import sys

API_BASE = "http://localhost:8000"

def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def print_test(name):
    print(f"\n🧪 Test: {name}")

def print_success(msg=""):
    print(f"   ✅ PASSED {msg}")

def print_fail(msg):
    print(f"   ❌ FAILED: {msg}")

def test_basic_detection():
    """Test basic anomaly detection"""
    print_test("Basic Detection")
    try:
        response = requests.get(f"{API_BASE}/api/anomalies?limit=10", timeout=30)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert data.get('success') == True, "Response should have success=True"
        assert 'data' in data, "Response should have 'data' field"
        assert 'count' in data, "Response should have 'count' field"
        assert 'total_connections' in data, "Response should have 'total_connections' field"
        print_success(f"- Found {data.get('count', 0)} anomalies from {data.get('total_connections', 0)} connections")
        return True
    except Exception as e:
        print_fail(str(e))
        return False

def test_parameters():
    """Test parameter override"""
    print_test("Parameter Override")
    try:
        response = requests.get(
            f"{API_BASE}/api/anomalies",
            params={
                'limit': 20,
                'contamination': 0.15,
                'n_estimators': 150
            },
            timeout=30
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get('success') == True
        print_success("- Parameters can be overridden")
        print(f"   - Contamination: 0.15, N Estimators: 150")
        print(f"   - Found {data.get('count', 0)} anomalies")
        return True
    except Exception as e:
        print_fail(str(e))
        return False

def test_min_score():
    """Test min_score filter"""
    print_test("Min Score Filter")
    try:
        response = requests.get(
            f"{API_BASE}/api/anomalies",
            params={'min_score': -0.3, 'limit': 10},
            timeout=30
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get('success') == True
        
        if data.get('data') and len(data['data']) > 0:
            scores = [a.get('anomaly_score', 0) for a in data['data']]
            all_valid = all(s <= -0.3 for s in scores)
            assert all_valid, f"All scores should be <= -0.3, got: {scores}"
            print_success(f"- All {len(scores)} anomalies have score <= -0.3")
        else:
            print_success("- Filter works (no anomalies with score <= -0.3)")
        return True
    except Exception as e:
        print_fail(str(e))
        return False

def test_edge_cases():
    """Test edge cases"""
    print_test("Edge Cases")
    results = []
    
    # Test invalid contamination
    try:
        response = requests.get(
            f"{API_BASE}/api/anomalies",
            params={'contamination': 0.6},  # Invalid (> 0.5)
            timeout=30
        )
        assert response.status_code == 200
        data = response.json()
        # Should still work, but use default contamination
        print_success("- Invalid contamination handled gracefully")
        results.append(True)
    except Exception as e:
        print_fail(f"Invalid contamination: {e}")
        results.append(False)
    
    # Test very low contamination
    try:
        response = requests.get(
            f"{API_BASE}/api/anomalies",
            params={'contamination': 0.01, 'limit': 10},
            timeout=30
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get('success') == True
        print_success("- Low contamination (0.01) works")
        results.append(True)
    except Exception as e:
        print_fail(f"Low contamination: {e}")
        results.append(False)
    
    # Test invalid n_estimators
    try:
        response = requests.get(
            f"{API_BASE}/api/anomalies",
            params={'n_estimators': 5},  # Invalid (< 10)
            timeout=30
        )
        assert response.status_code == 200
        print_success("- Invalid n_estimators handled gracefully")
        results.append(True)
    except Exception as e:
        print_fail(f"Invalid n_estimators: {e}")
        results.append(False)
    
    return all(results)

def test_performance():
    """Test performance with different configurations"""
    print_test("Performance")
    results = []
    
    # Test with default parameters
    try:
        start = time.time()
        response = requests.get(
            f"{API_BASE}/api/anomalies",
            params={'limit': 100, 'n_estimators': 100},
            timeout=60
        )
        elapsed = time.time() - start
        assert response.status_code == 200
        assert elapsed < 30, f"Detection took {elapsed:.2f}s, should be < 30s"
        print_success(f"- Default config: {elapsed:.2f}s")
        results.append(True)
    except Exception as e:
        print_fail(f"Performance test: {e}")
        results.append(False)
    
    # Test with lower n_estimators (should be faster)
    try:
        start = time.time()
        response = requests.get(
            f"{API_BASE}/api/anomalies",
            params={'limit': 100, 'n_estimators': 50},
            timeout=60
        )
        elapsed = time.time() - start
        assert response.status_code == 200
        print_success(f"- Lower n_estimators (50): {elapsed:.2f}s")
        results.append(True)
    except Exception as e:
        print_fail(f"Performance test (low n_estimators): {e}")
        results.append(False)
    
    return all(results)

def test_anomaly_scores():
    """Test anomaly score validity"""
    print_test("Anomaly Score Validity")
    try:
        response = requests.get(
            f"{API_BASE}/api/anomalies",
            params={'limit': 50},
            timeout=30
        )
        assert response.status_code == 200
        data = response.json()
        
        if data.get('data') and len(data['data']) > 0:
            anomalies = data['data']
            scores = [a.get('anomaly_score', 0) for a in anomalies]
            
            # Check all scores are present
            assert all(s is not None for s in scores), "All anomalies should have scores"
            
            # Check scores are sorted (most anomalous first)
            sorted_scores = sorted(scores)
            assert scores == sorted_scores, "Anomalies should be sorted by score (lowest first)"
            
            # Check scores are negative (anomalies)
            all_negative = all(s <= 0 for s in scores)
            if not all_negative:
                print(f"   ⚠️  Warning: Some scores are positive: {[s for s in scores if s > 0]}")
            
            print_success(f"- {len(scores)} anomalies have valid scores")
            print(f"   - Score range: {min(scores):.4f} to {max(scores):.4f}")
            return True
        else:
            print_success("- No anomalies to validate (this is OK)")
            return True
    except Exception as e:
        print_fail(str(e))
        return False

def test_data_completeness():
    """Test that anomaly data is complete"""
    print_test("Data Completeness")
    try:
        response = requests.get(
            f"{API_BASE}/api/anomalies",
            params={'limit': 10},
            timeout=30
        )
        assert response.status_code == 200
        data = response.json()
        
        if data.get('data') and len(data['data']) > 0:
            anomalies = data['data']
            required_fields = ['anomaly_score', 'protocol', 'state', 'src', 'dst', 'sport', 'dport']
            
            for i, anomaly in enumerate(anomalies):
                missing = [f for f in required_fields if f not in anomaly]
                if missing:
                    print_fail(f"Anomaly {i} missing fields: {missing}")
                    return False
            
            print_success(f"- All {len(anomalies)} anomalies have required fields")
            return True
        else:
            print_success("- No anomalies to validate (this is OK)")
            return True
    except Exception as e:
        print_fail(str(e))
        return False

def main():
    print_header("Anomaly Detection Test Suite")
    print("\n📋 Running tests against:", API_BASE)
    print("   Make sure the server is running!")
    
    # Check if server is accessible
    try:
        response = requests.get(f"{API_BASE}/api/summary", timeout=5)
        if response.status_code != 200:
            print_fail(f"Server returned status {response.status_code}")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print_fail("Cannot connect to server. Is it running?")
        print(f"   Expected: {API_BASE}")
        sys.exit(1)
    except Exception as e:
        print_fail(f"Error connecting to server: {e}")
        sys.exit(1)
    
    print_success("Server is accessible")
    
    # Run tests
    tests = [
        ("Basic Detection", test_basic_detection),
        ("Parameter Override", test_parameters),
        ("Min Score Filter", test_min_score),
        ("Edge Cases", test_edge_cases),
        ("Performance", test_performance),
        ("Anomaly Score Validity", test_anomaly_scores),
        ("Data Completeness", test_data_completeness),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print_fail(f"Test '{name}' crashed: {e}")
            results.append((name, False))
    
    # Summary
    print_header("Test Summary")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {status}: {name}")
    
    print(f"\n📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())

