# Scr-LFI-Protect
A security reverse proxy designed to protect web applications from
Local File Inclusion (LFI) attacks with real-time file leak prevention.

## Features
- Scanning request URL, forms, JSON for path traversal patterns (`../`, `..\`)
- Analyzing filenames in `multipart/form-data` (Remote File Inclusion prevention)
- Detecting file content leaks in web server responses
- Trie data structure for high-performance leak detection
- YAML-based flexible configuration
- Admin panel (under development)

## Configuration
### Basic Configuration
Create a `config.yaml` file:
```yaml
proxy:
    listen: ":1545"
    server: "http://localhost:1544"
    max-req-body-size: 16000000
    check-url: true
    check-query: true
    check-filenames: true
    check-json: true
    check-file-leaks: true
    check-all-fields: true
    check-fields: [] # use when check-all-fields is false
files:
    paths:
        - .
    exclude:
        - example/files
        - example/templates
        - example/static
logs:
	logs-path: logs
```
### Configuration options
- `proxy.listen` - Reverse proxy lustening address
- `proxy.server` - Target web application address
- `proxy.max-req-body-size` - Maximal request body size in bytes
- `proxy.check-url` - Inspect request URL for traversal patterns (true/false)
- `proxy.check-query` - Inspect request URL query and text fields in form data (true/false)
- `proxy.check-filenames` - Inspect file names in forms (true/false)
- `proxy.check-json` - Inspect request JSON (true/false)
- `proxy.check-file-leaks` - Inapect response for local file content leaks (true/false)
- `proxy.check-all-fields` - Inspect every field in query, forms, JSON (true/false). If false, a list of fields from `proxy.check-fields` is used.

- `files.paths` - List of sensitive files or directories to protect
- `files.exclude` - Files, directories or patterns to exclude from monitoring

- `logs.logs-path` - Directory to save logs
