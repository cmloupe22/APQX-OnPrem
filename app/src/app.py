"""
APQX Sample Application
A simple Flask web application that demonstrates GitOps deployment.
"""

import os
import json
from datetime import datetime
from flask import Flask, jsonify, Response
import psutil
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Application metadata from environment variables
APP_NAME = os.getenv('APP_NAME', 'apqx-sample-app')
BUILD_SHA = os.getenv('BUILD_SHA', 'dev')
VERSION = os.getenv('APP_VERSION', '1.0.0')
POD_NAME = os.getenv('POD_NAME', 'unknown')
POD_NAMESPACE = os.getenv('POD_NAMESPACE', 'default')
NODE_NAME = os.getenv('NODE_NAME', 'unknown')

@app.route('/')
def index():
    """Main endpoint returning application information."""
    response_data = {
        'app_name': APP_NAME,
        'version': VERSION,
        'build_sha': BUILD_SHA,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'pod': {
            'name': POD_NAME,
            'namespace': POD_NAMESPACE,
            'node': NODE_NAME
        }
    }
    
    logger.info(f"Request served from pod {POD_NAME}")
    return jsonify(response_data)

@app.route('/health')
def health():
    """Health check endpoint for liveness probe."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 200

@app.route('/ready')
def ready():
    """Readiness check endpoint."""
    # Add any readiness checks here (DB connections, etc.)
    return jsonify({
        'status': 'ready',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 200

@app.route('/metrics')
def metrics():
    """Prometheus-compatible metrics endpoint."""
    # Get process info
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    
    metrics_output = f"""# HELP app_info Application information
# TYPE app_info gauge
app_info{{app_name="{APP_NAME}",version="{VERSION}",build_sha="{BUILD_SHA}"}} 1

# HELP app_memory_usage_bytes Memory usage in bytes
# TYPE app_memory_usage_bytes gauge
app_memory_usage_bytes {memory_info.rss}

# HELP app_cpu_percent CPU usage percentage
# TYPE app_cpu_percent gauge
app_cpu_percent {process.cpu_percent(interval=0.1)}

# HELP app_requests_total Total number of requests
# TYPE app_requests_total counter
app_requests_total 1
"""
    
    return Response(metrics_output, mimetype='text/plain')

@app.route('/version')
def version():
    """Version information endpoint."""
    return jsonify({
        'app_name': APP_NAME,
        'version': VERSION,
        'build_sha': BUILD_SHA,
        'build_date': os.getenv('BUILD_DATE', 'unknown')
    })

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'error': 'Not Found',
        'status': 404,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'error': 'Internal Server Error',
        'status': 500,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    logger.info(f"Starting {APP_NAME} v{VERSION} on port {port}")
    logger.info(f"Build SHA: {BUILD_SHA}")
    app.run(host='0.0.0.0', port=port, debug=False)
