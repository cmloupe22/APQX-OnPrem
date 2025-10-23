"""
Test suite for APQX Sample Application
"""

import pytest
import json
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from app import app as flask_app

@pytest.fixture
def app():
    """Create application fixture."""
    flask_app.config['TESTING'] = True
    return flask_app

@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()

def test_index_endpoint(client):
    """Test the main index endpoint."""
    response = client.get('/')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'app_name' in data
    assert 'build_sha' in data
    assert 'timestamp' in data
    assert 'version' in data
    assert 'pod' in data

def test_health_endpoint(client):
    """Test the health check endpoint."""
    response = client.get('/health')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['status'] == 'healthy'
    assert 'timestamp' in data

def test_ready_endpoint(client):
    """Test the readiness endpoint."""
    response = client.get('/ready')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['status'] == 'ready'
    assert 'timestamp' in data

def test_metrics_endpoint(client):
    """Test the metrics endpoint."""
    response = client.get('/metrics')
    assert response.status_code == 200
    assert response.content_type == 'text/plain; charset=utf-8'
    
    metrics = response.data.decode('utf-8')
    assert 'app_info' in metrics
    assert 'app_memory_usage_bytes' in metrics
    assert 'app_cpu_percent' in metrics

def test_version_endpoint(client):
    """Test the version endpoint."""
    response = client.get('/version')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'app_name' in data
    assert 'version' in data
    assert 'build_sha' in data

def test_404_error(client):
    """Test 404 error handling."""
    response = client.get('/nonexistent')
    assert response.status_code == 404
    
    data = json.loads(response.data)
    assert data['error'] == 'Not Found'
    assert data['status'] == 404

def test_index_response_format(client):
    """Test that index response has correct format."""
    response = client.get('/')
    data = json.loads(response.data)
    
    # Check pod information structure
    assert isinstance(data['pod'], dict)
    assert 'name' in data['pod']
    assert 'namespace' in data['pod']
    assert 'node' in data['pod']
    
    # Check timestamp format (ISO 8601)
    assert 'T' in data['timestamp']
    assert data['timestamp'].endswith('Z')
