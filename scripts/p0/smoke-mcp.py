#!/usr/bin/env python3
"""Read-only HTTP/OAuth metadata and denial checks. No token or grant is created."""
import argparse
import datetime
import json
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-url', required=True, help='Canonical URL ending in /mcp')
    parser.add_argument('--connect-origin', help='Optional loopback HTTP origin for pre-proxy checks')
    args = parser.parse_args()
    public = urllib.parse.urlsplit(args.public_url)
    if (public.scheme not in ('https', 'http') or public.path != '/mcp'
            or public.query or public.fragment or public.username or not public.hostname):
        parser.error('Expected an http(s) origin with /mcp and no query/credentials')
    origin = urllib.parse.urlunsplit((public.scheme, public.netloc, '', '', ''))
    connect = (args.connect_origin or origin).rstrip('/')
    if args.connect_origin:
        parsed = urllib.parse.urlsplit(connect)
        if (parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost')
                or parsed.path or parsed.query or parsed.fragment or parsed.username):
            parser.error('--connect-origin must be a loopback HTTP origin')
    # Do not inherit HTTP_PROXY for a local preflight or leak the test to a proxy.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    checks = []

    def request(path, token=None, host=None, body=None):
        headers = {'Host': host or public.netloc, 'Accept': 'application/json, text/event-stream'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if body is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(connect + path, headers=headers, data=body)
        try:
            response = opener.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read(262145)

    def check(name, condition):
        checks.append({'name': name, 'passed': bool(condition)})

    try:
        code, headers, body = request('/.well-known/oauth-protected-resource')
        metadata = json.loads(body)
        check('resource_metadata', code == 200 and metadata.get('resource') == args.public_url
              and metadata.get('authorization_servers') == [origin])
        check('metadata_no_store', 'no-store' in headers.get('Cache-Control', ''))
        code, _, body = request('/.well-known/oauth-authorization-server')
        metadata = json.loads(body)
        check('oauth_metadata', code == 200 and metadata.get('issuer') == origin
              and metadata.get('token_endpoint') == origin + '/token'
              and 'S256' in metadata.get('code_challenge_methods_supported', []))
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}).encode()
        code, headers, _ = request('/mcp', body=body)
        check('anonymous_mcp_denied', code == 401 and origin + '/.well-known/oauth-protected-resource'
              in headers.get('WWW-Authenticate', ''))
        code, _, _ = request('/mcp', token='p0-intentionally-invalid', body=body)
        check('invalid_bearer_denied', code == 401)
        code, _, _ = request('/mcp', host='invalid.example', body=body)
        check('wrong_host_denied', code == 403)
    except (OSError, ValueError) as error:
        checks.append({'name': 'request_error', 'passed': False, 'error': str(error)})
    passed = bool(checks) and all(c['passed'] for c in checks)
    print(json.dumps({'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'public_url': args.public_url, 'connect_origin': connect,
                      'passed': passed, 'checks': checks,
                      'cloud_client_verified': False, 'task_execution_verified': False}, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
