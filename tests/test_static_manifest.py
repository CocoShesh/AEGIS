import tempfile,unittest,zipfile,struct,json
from pathlib import Path
from test_scanner import scanner
from android_resources import xml_paths,ResourceGap

class ManifestRulesTests(unittest.TestCase):
 def appscan(self,children='',attrs='',body='',**kw):
  # Simple XML fixture with arbitrary application children.
  xml=f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.test.app"><uses-sdk android:minSdkVersion="{kw.get("minimum",23)}" android:targetSdkVersion="{kw.get("target",30)}"/>{body}<application {attrs}>{children}</application></manifest>'
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'app.apk'
   with zipfile.ZipFile(path,'w') as z:
    z.writestr('AndroidManifest.xml',xml)
    for name,data in kw.get('resources',{}).items():z.writestr(name,data)
   return scanner.analyze(str(path),'app.apk')
 def rules(self,r):return {f['rule'] for f in r['findings']}
 def test_permissions_and_scoped_combination(self):
  body=''.join(f'<uses-permission android:name="android.permission.{p}"/>' for p in ['SEND_SMS','INTERNET','REQUEST_INSTALL_PACKAGES','SYSTEM_ALERT_WINDOW'])
  receiver='<receiver android:name=".Boot" android:exported="false"><intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter></receiver>'
  r=self.appscan(receiver,body=body)
  self.assertTrue({'perm-sms-family','request-install-packages','overlay-capability','boot-receiver','capability-install-startup'}<=self.rules(r))
  self.assertNotIn('exported-component',self.rules(r));self.assertNotIn('capability-sms-network',self.rules(r))
  evidence_ids=[e['id'] for f in r['findings'] for e in f['evidence']]
  self.assertEqual(len(evidence_ids),len(set(evidence_ids)))
  for f in r['findings']:
   self.assertEqual(f['evidence_tier'],'MANIFEST_CONFIG');self.assertEqual(f['evidence'][0]['sha256'],r['sha256'])
 def test_application_permission_inheritance(self):
  body='<permission android:name="org.test.SIG" android:protectionLevel="signature"/>'
  r=self.appscan('<service android:name=".Protected" android:exported="true"/>',attrs='android:permission="org.test.SIG"',body=body)
  self.assertNotIn('exported-component',self.rules(r));self.assertNotIn('exported-weak-permission',self.rules(r))
  self.assertEqual(r['components'][0]['permission_protection'],'Signature')
 def test_custom_numeric_signature_and_normal_default(self):
  for value,expected in [('0x12','Signature'),('2','Signature'),('normal','Normal'),('dangerous','Dangerous')]:
   r=self.appscan('<service android:name=".Guard" android:exported="true" android:permission="org.test.G"/>',body=f'<permission android:name="org.test.G" android:protectionLevel="{value}"/>')
   self.assertEqual(r['components'][0]['permission_protection'],expected)
   self.assertEqual('exported-weak-permission' in self.rules(r),expected!='Signature')
 def test_provider_write_permission_does_not_hide_open_read(self):
  r=self.appscan('<provider android:name=".P" android:exported="true" android:writePermission="android.permission.BIND_DEVICE_ADMIN"/>')
  self.assertIn('exported-component',self.rules(r))
 def test_implicit_exports_and_installability(self):
  child='<service android:name=".S"><intent-filter><action android:name="org.test.ACTION"/></intent-filter></service>'
  r=self.appscan(child,target=30);self.assertIn('exported-component',self.rules(r));self.assertTrue(r['components'][0]['effective_exported'])
  r=self.appscan(child,target=31);self.assertIn('exported-missing',self.rules(r));self.assertNotIn('exported-component',self.rules(r));self.assertIsNone(r['components'][0]['effective_exported'])
 def test_provider_legacy_default_and_disabled_component(self):
  self.assertIn('exported-component',self.rules(self.appscan('<provider android:name=".P"/>',target=16)))
  self.assertNotIn('exported-component',self.rules(self.appscan('<provider android:name=".P"/>',target=30,minimum=23)))
  self.assertNotIn('exported-component',self.rules(self.appscan('<service android:name=".S" android:exported="true" android:enabled="false"/>')))
 def test_activity_alias_inherits_target_guard(self):
  r=self.appscan('<activity android:name=".A" android:permission="org.test.SIG"/><activity-alias android:name=".Alias" android:targetActivity=".A" android:exported="true"/>',body='<permission android:name="org.test.SIG" android:protectionLevel="signature"/>')
  self.assertNotIn('exported-component',self.rules(r));self.assertEqual(r['components'][1]['permission'],'org.test.SIG')
 def test_accessibility_and_admin_xml_exact_evidence(self):
  child='<service android:name=".Access" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"><intent-filter><action android:name="android.accessibilityservice.AccessibilityService"/></intent-filter><meta-data android:name="android.accessibilityservice" android:resource="@xml/access"/></service><receiver android:name=".Admin" android:permission="android.permission.BIND_DEVICE_ADMIN"><intent-filter><action android:name="android.app.action.DEVICE_ADMIN_ENABLED"/></intent-filter><meta-data android:name="android.app.device_admin" android:resource="@xml/admin"/></receiver>'
  r=self.appscan(child,resources={'res/xml/access.xml':b'<accessibility-service/>','res/xml/admin.xml':b'<device-admin><uses-policies><wipe-data/></uses-policies></device-admin>'})
  self.assertTrue({'accessibility-service','device-admin'}<=self.rules(r));self.assertFalse(r['static_analysis_gaps'])
  self.assertTrue(any(e['path']=='res/xml/admin.xml' for f in r['findings'] for e in f['evidence']))
 def test_network_inheritance_and_debug_scope(self):
  xml=b'<network-security-config><base-config cleartextTrafficPermitted="false"/><domain-config cleartextTrafficPermitted="true"><domain>example.test</domain><trust-anchors><certificates src="user" overridePins="true"/></trust-anchors></domain-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides></network-security-config>'
  r=self.appscan(attrs='android:networkSecurityConfig="@xml/network" android:usesCleartextTraffic="true"',resources={'res/xml/network.xml':xml})
  self.assertTrue({'cleartext-policy','network-user-trust','network-pin-override','network-debug-trust'}<=self.rules(r))
  self.assertEqual(next(f for f in r['findings'] if f['rule']=='network-debug-trust')['severity'],'info')
  self.assertEqual(len([f for f in r['findings'] if f['rule']=='cleartext-policy']),1)
 def test_network_resource_overrides_manifest_cleartext_flag(self):
  r=self.appscan(attrs='android:networkSecurityConfig="@xml/n" android:usesCleartextTraffic="true"',resources={'res/xml/n.xml':b'<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>'})
  self.assertNotIn('cleartext-policy',self.rules(r))
 def test_missing_and_malformed_resources_are_gaps(self):
  for resources in [{},{'res/xml/n.xml':b'invalid'},{'res/xml/n.xml':b'<wrong-root/>'}]:
   r=self.appscan(attrs='android:networkSecurityConfig="@xml/n"',resources=resources)
   self.assertTrue(r['static_analysis_gaps']);self.assertEqual(next(c for c in r['coverage'] if c['name']=='Referenced XML configuration')['status'],'Partial')
   self.assertNotIn('cleartext-policy',self.rules(r));self.assertEqual(r['state'],'PARTIAL')
 def test_backup_configuration_is_info_not_exposure_proof(self):
  r=self.appscan(attrs='android:fullBackupContent="@xml/backup"',resources={'res/xml/backup.xml':b'<full-backup-content><exclude domain="sharedpref" path="."/></full-backup-content>'})
  self.assertEqual(next(f for f in r['findings'] if f['rule']=='backup-exposure')['severity'],'info');self.assertEqual(r['backup_policy']['resolved_rules'][0]['excludes'],1)
  self.assertNotIn('backup-exposure',self.rules(self.appscan(attrs='android:allowBackup="false"')))
  self.assertEqual(r['risk'],'Inconclusive')
 def test_broad_grants_not_exact_root_path(self):
  r=self.appscan('<provider android:name=".P"><grant-uri-permission android:path="/"/></provider>');self.assertNotIn('broad-uri-grant',self.rules(r))
  r=self.appscan('<provider android:name=".P"><grant-uri-permission android:pathPrefix="/"/></provider>');self.assertIn('broad-uri-grant',self.rules(r))
 def test_sdk23_permission_and_maxsdk_preserved(self):
  r=self.appscan(body='<uses-permission-sdk-23 android:name="android.permission.RECORD_AUDIO" android:maxSdkVersion="28"/>')
  self.assertIn('android.permission.RECORD_AUDIO',r['permissions']);self.assertEqual(r['permission_details'][0]['max_sdk'],'28')
 def test_xml_resource_depth_and_budget(self):
  deep=b'<network-security-config>'+b'<domain-config>'*70+b'</domain-config>'*70+b'</network-security-config>'
  for data in [deep,b'x'*(2*1024*1024+1)]:
   r=self.appscan(attrs='android:networkSecurityConfig="@xml/n"',resources={'res/xml/n.xml':data});self.assertTrue(r['static_analysis_gaps'])
 def test_ai_receives_rule_ids_and_full_aggregate(self):
  import integrations
  r=self.appscan(body='<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>')
  r['findings']*=20
  value=integrations.intelligence_input(r)
  self.assertTrue(any(f['rule']=='overlay-capability' for f in value['findings']));self.assertEqual(value['static_rule_counts']['overlay-capability'],20)
  self.assertNotIn('org.test.app',json.dumps(value))

class ResourceTableTests(unittest.TestCase):
 def table(self,value=b'res/xml/network.xml'):
  payload=bytes([len(value),len(value)])+value+b'\0';payload+=b'\0'*((-len(payload))%4)
  pool=struct.pack('<HHIIIIII',1,28,32+len(payload),1,0,256,32,0)+struct.pack('<I',0)+payload
  # One type with a default ResTable_config and one string-valued file entry.
  entry=struct.pack('<HHI',8,0,0)+struct.pack('<HBBI',8,0,3,0)
  typechunk=struct.pack('<HHI',0x201,24,28+len(entry))+struct.pack('<BBHII',1,0,0,1,28)+struct.pack('<I',4)+struct.pack('<I',0)+entry
  package=bytearray(288);struct.pack_into('<HHI',package,0,0x200,288,288+len(typechunk));struct.pack_into('<I',package,8,0x7f)
  body=pool+bytes(package)+typechunk
  return struct.pack('<HHII',2,12,12+len(body),1)+body
 def test_numeric_reference_to_xml_path(self):self.assertEqual(xml_paths(self.table(),0x7f010000),['res/xml/network.xml'])
 def test_obfuscated_xml_path_resolves_in_real_scan(self):
  r=ManifestRulesTests().appscan(attrs='android:networkSecurityConfig="@0x7f010000"',resources={'resources.arsc':self.table(b'res/8G.xml'),'res/8G.xml':b'<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>'})
  self.assertFalse(r['static_analysis_gaps']);self.assertIn('cleartext-policy',{f['rule'] for f in r['findings']})
  self.assertEqual(next(f for f in r['findings'] if f['rule']=='cleartext-policy')['evidence'][0]['path'],'res/8G.xml')
 def test_truncated_table_and_unresolved_id_are_gaps(self):
  for data,id in [(self.table()[:-1],0x7f010000),(self.table(),0x7f020000),(b'bad',0x7f010000)]:
   with self.assertRaises(ResourceGap):xml_paths(data,id)
