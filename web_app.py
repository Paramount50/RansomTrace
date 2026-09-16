import http.server
import socketserver
import json
import os
from urllib.parse import urlparse, parse_qs
from ransom_tracer import RansomTracer

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

class RansomTraceHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.path = '/landing.html'
        elif self.path == '/dashboard':
            self.path = '/index.html'
        return super().do_GET()

    def do_POST(self):
        if self.path == '/api/analyze':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                request_json = json.loads(post_data.decode('utf-8'))
                sample_trace = request_json.get('trace_data', '')
                
                artifact_name = request_json.get('artifact_name', 'WannaCry_Memory_Network_Dump.raw')
                
                # Initialize the forensic engine
                tracer = RansomTracer()
                
                # Run the analysis pipeline
                results = tracer.analyze_artifact(artifact_name, sample_trace)
                
                # Generate HTML report inside static/reports so it's downloadable
                report_path = os.path.join(STATIC_DIR, "reports", "forensic_report.html")
                generated_file = tracer.generate_html_report(results, report_path)
                results['report_url'] = '/reports/forensic_report.html'
                
                # Send response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(results).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

class ReuseTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

# Ensure static directory exists
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, 'reports'), exist_ok=True)

if __name__ == '__main__':
    print(f"\n  [!] Starting RansomTrace Web Dashboard on port {PORT}")
    print(f"  [!] Navigate to http://localhost:{PORT} in your browser")
    print("-" * 60)
    
    with ReuseTCPServer(("", PORT), RansomTraceHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  [!] Shutting down server.")
