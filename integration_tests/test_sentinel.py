"""Offline tests of the unified origin boundary and Android adapter."""
import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import sentinel

class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(sentinel.app)

    def test_origin_and_host_boundaries(self):
        for headers in ({'host':'evil.example'}, {'origin':'https://evil.example'}, {'sec-fetch-site':'cross-site'}):
            self.assertEqual(self.client.post('/api/v1/scans',headers=headers,json={}).status_code,403)

    def test_repository_mount_and_redirect(self):
        self.assertEqual(self.client.get('/repository',follow_redirects=False).headers['location'],'/repository/')
        self.assertEqual(self.client.get('/repository/api/session').status_code,200)
        page=self.client.get('/repository/')
        self.assertEqual(page.status_code,200)
        self.assertIn('/repository/assets/',page.text)
        self.assertIn('RepoSentinel',page.text)

    def test_landing_and_shared_theme(self):
        page=self.client.get('/')
        self.assertEqual(page.status_code,200)
        self.assertIn('href="/android/"',page.text)
        self.assertIn('href="/repository/"',page.text)
        self.assertEqual(self.client.get('/android',follow_redirects=False).headers['location'],'/android/')
        self.assertEqual(self.client.get('/shared/theme.css').status_code,200)

    @patch('sentinel.http.client.HTTPConnection')
    def test_fixed_android_destination(self, constructor):
        upstream=MagicMock(); upstream.status=200; upstream.read.return_value=b'{"ok":true}'
        upstream.getheaders.return_value=[('Content-Type','application/json')]
        constructor.return_value.getresponse.return_value=upstream
        with patch.object(sentinel,'ANDROID_PORT',12345):
            result=sentinel.forward('/api/v1/scans','POST',{'host':'external','origin':'http://testserver','x-custom':'kept'},b'{}')
        constructor.assert_called_once_with('127.0.0.1',12345,timeout=120)
        args=constructor.return_value.request.call_args
        self.assertEqual(args.kwargs['headers']['Host'],'127.0.0.1:12345')
        self.assertEqual(args.kwargs['headers']['Origin'],'http://127.0.0.1:12345')
        self.assertEqual(result.status_code,200)

    def test_android_not_started(self):
        with patch.object(sentinel,'ANDROID_PORT',None):
            self.assertEqual(self.client.get('/api/v1/scans').status_code,503)
