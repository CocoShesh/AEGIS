"""Deterministic manifest/config evidence. Declared capabilities are not malware verdicts."""
import json,re,xml.etree.ElementTree as ET
A='{http://schemas.android.com/apk/res/android}'
RULES=[
 ('perm-sms-family','SMS and call-log capabilities','Permissions'),('accessibility-service','Accessibility service declaration','Permissions'),('notification-listener','Notification listener declaration','Permissions'),('device-admin','Device administrator policies','Permissions'),('sms-receiver-priority','SMS broadcast priority','Manifest'),('boot-receiver','Boot/startup receiver','Manifest'),('request-install-packages','Package installation permission','Permissions'),('query-all-packages','Installed-app enumeration','Permissions'),('manage-external-storage','All-files access','Permissions'),('overlay-capability','Overlay permission','Permissions'),('network-user-trust','User-added trust anchors','Network'),('network-pin-override','Certificate pin override','Network'),('network-debug-trust','Debug trust configuration','Network'),('task-configuration','Non-default task configuration','Manifest'),('backup-exposure','Backup configuration','Manifest'),('shared-user-id','Shared user identity','Manifest'),('secret-code','Dialer entry point','Manifest'),('broad-uri-grant','Broad provider URI grants','Components / IPC'),('dangerous-permission-count','Sensitive permission inventory','Permissions'),('exported-component','Unguarded exported component','Components / IPC'),('exported-weak-permission','Non-signature component guard','Components / IPC'),('exported-missing','Missing required exported declaration','Manifest'),('legacy-provider-export','Legacy provider exposure','Components / IPC'),('min-sdk-context','Legacy Android compatibility','Manifest'),('test-only','Test-only installation','Manifest'),('direct-boot-aware','Before-unlock component','Manifest'),('capability-install-startup','Installer/startup capability combination','Capabilities'),('capability-sms-network','SMS/network capability combination','Capabilities'),('capability-accessibility-overlay','Accessibility/overlay capability combination','Capabilities'),('capability-admin-startup','Device-admin/startup capability combination','Capabilities')]
RULE_IDS={r[0] for r in RULES}|{'debuggable','cleartext-policy'}
SMS={'READ_SMS','SEND_SMS','RECEIVE_SMS','RECEIVE_MMS','RECEIVE_WAP_PUSH','READ_CALL_LOG','WRITE_CALL_LOG','PROCESS_OUTGOING_CALLS','CALL_PHONE'}
DANGEROUS=SMS|{'READ_CONTACTS','WRITE_CONTACTS','GET_ACCOUNTS','READ_CALENDAR','WRITE_CALENDAR','CAMERA','RECORD_AUDIO','ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','ACCESS_BACKGROUND_LOCATION','READ_PHONE_STATE','READ_PHONE_NUMBERS','ANSWER_PHONE_CALLS','BODY_SENSORS','BODY_SENSORS_BACKGROUND','ACTIVITY_RECOGNITION','READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE','READ_MEDIA_IMAGES','READ_MEDIA_VIDEO','READ_MEDIA_AUDIO','READ_MEDIA_VISUAL_USER_SELECTED','BLUETOOTH_SCAN','BLUETOOTH_CONNECT','BLUETOOTH_ADVERTISE','POST_NOTIFICATIONS','NEARBY_WIFI_DEVICES'}
BIND={'BIND_ACCESSIBILITY_SERVICE','BIND_NOTIFICATION_LISTENER_SERVICE','BIND_DEVICE_ADMIN'}

def protection(value):
    if value is None:return 'Unknown'
    try:base=int(value,0)&15
    except ValueError:
        base=value.split('|')[0].strip()
        return 'Signature' if base in ('signature','signatureOrSystem','internal') else 'Dangerous' if base=='dangerous' else 'Normal' if base=='normal' else 'Unknown'
    return {0:'Normal',1:'Dangerous',2:'Signature',3:'Signature',4:'Signature'}.get(base,'Unknown')

def analyze_manifest(root,report,emit,resources):
    report['tools']['manifest_rules']='manifest/config 1.0'
    report['manifest_checks_complete']=False
    gaps=[];permission_nodes=[n for n in root if n.tag in ('uses-permission','uses-permission-sdk-23')]
    report['permissions']=sorted({n.get(A+'name','') for n in permission_nodes if n.get(A+'name')})
    short={p.rsplit('.',1)[-1] for p in report['permissions'] if p.startswith('android.permission.')}
    custom={n.get(A+'name'):protection(n.get(A+'protectionLevel','normal')) for n in root.findall('permission')}
    def level(name):
        if not name:return 'None'
        if name in custom:return custom[name]
        suffix=name.removeprefix('android.permission.')
        if name.startswith('android.permission.') and suffix in BIND:return 'Signature'
        if name.startswith('android.permission.') and suffix in DANGEROUS:return 'Dangerous'
        if name in ('android.permission.INTERNET','android.permission.ACCESS_NETWORK_STATE','android.permission.RECEIVE_BOOT_COMPLETED'):return 'Normal'
        return 'Unknown'
    report['permission_details']=[{'name':n.get(A+'name'),'protection':level(n.get(A+'name')),'max_sdk':n.get(A+'maxSdkVersion'),'declaration':n.tag,'scope':'Declared; grant and runtime use are not verified'} for n in permission_nodes]
    evidence_number=0
    def ev(node,path='AndroidManifest.xml',location=None):
        nonlocal evidence_number
        evidence_number+=1
        return dict(id='E-manifest-'+str(evidence_number),path=path,location=location or node.tag,snippet=ET.tostring(node,encoding='unicode')[:4096],analyzer='manifest-config',sha256=report['sha256'],evidence_tier='MANIFEST_CONFIG')
    def add(rule,title,node,severity='low',category='Manifest',message='',path='AndroidManifest.xml',extra=None):
        emit(rule,title,severity,category,message or 'This is a declared static capability or configuration. Runtime use, reachability and malicious intent have not been established.',[ev(node,path)]+(extra or []),'High')
        report['findings'][-1].update(source_label='STATIC',evidence_tier='MANIFEST_CONFIG',assessment_type='Configuration' if category in ('Manifest','Network','Components / IPC') else 'Capability')
    def xml(reference,label,expected=None):
        try:
            values=resources.resolve(reference)
            if expected and any(node.tag!=expected for _,node in values):raise ValueError()
            return values
        except Exception:
            gaps.append(label+': declared XML could not be resolved or parsed; configuration remains unverified.')
            return []
    app=root.find('application')
    if app is None:
        gaps.append('Application declaration is absent; application/component configuration checks are incomplete.')
        report['static_analysis_gaps']=gaps;return
    enabled=app.get(A+'enabled','true')!='false';target=report.get('target_sdk');minimum=report.get('min_sdk')
    if app.get(A+'debuggable')=='true':add('debuggable','Debuggable application build',app,'high',message='The manifest explicitly enables debugging. This is a release-hardening issue, not proof of malware.')
    if short&SMS:add('perm-sms-family','SMS or call-log capability declared',next(n for n in permission_nodes if n.get(A+'name','').rsplit('.',1)[-1] in SMS),'medium','Permissions',message='Declared capabilities: '+', '.join(sorted(short&SMS))+'. SMS/dialer/backup apps may legitimately request them; grants and runtime use are unverified.')
    for perm,rule,title in [('REQUEST_INSTALL_PACKAGES','request-install-packages','Package installation permission declared'),('QUERY_ALL_PACKAGES','query-all-packages','Broad installed-app enumeration declared'),('MANAGE_EXTERNAL_STORAGE','manage-external-storage','All-files access declared'),('SYSTEM_ALERT_WINDOW','overlay-capability','Draw-over-apps capability declared')]:
        if perm in short:add(rule,title,next(n for n in permission_nodes if n.get(A+'name')=='android.permission.'+perm),'medium' if perm!='QUERY_ALL_PACKAGES' else 'low','Permissions')
    if short&DANGEROUS:add('dangerous-permission-count','Sensitive permission inventory: '+str(len(short&DANGEROUS)),root,'info','Permissions',message='Known sensitive permission declarations: '+', '.join(sorted(short&DANGEROUS))+'. SDK-specific applicability, runtime grants and usage remain unverified; count does not measure maliciousness.')
    if root.get(A+'sharedUserId'):add('shared-user-id','Shared user identity declared',root,'info',message='Shared UID declaration may permit same-signed applications to share an identity on compatible Android versions. Platform restrictions and other packages are not verified.')
    if isinstance(minimum,int) and minimum<26:add('min-sdk-context','Legacy Android versions supported',root,'info',message=f'minSdkVersion={minimum} expands compatibility to legacy devices. This is compatibility context, not evidence of malicious intent.')
    if app.get(A+'testOnly')=='true':add('test-only','Test-only application build',app,'info',message='testOnly=true changes normal installability. Development builds legitimately use this flag.')
    app_permission=app.get(A+'permission','');nodes=[n for n in app if n.tag in ('activity','activity-alias','service','receiver','provider')]
    activity_permissions={n.get(A+'name'):n.get(A+'permission',app_permission) for n in nodes if n.tag=='activity'}
    boot=[];access=[];admin=[];sms_receivers=[];launchers=[]
    for node in nodes:
        filters=node.findall('intent-filter');actions={a.get(A+'name') for f in filters for a in f.findall('action')};categories={c.get(A+'name') for f in filters for c in f.findall('category')}
        declared=node.get(A+'exported');active=enabled and node.get(A+'enabled','true')!='false'
        if declared in ('true','false'):exported=declared=='true';export_basis='Explicit'
        elif node.tag=='provider':exported=target<17 if isinstance(target,int) else None;export_basis='Target SDK default'
        elif filters and isinstance(target,int) and target>=31:exported=None;export_basis='Required declaration missing';add('exported-missing','Required exported declaration is missing',node,'low',message='This component has an intent filter and targets Android 12+. Installability requires an explicit exported value; external exposure is unresolved.')
        else:exported=bool(filters);export_basis='Intent-filter default'
        guard=node.get(A+'permission',activity_permissions.get(node.get(A+'targetActivity'),app_permission) if node.tag=='activity-alias' else app_permission)
        guards=[node.get(A+'readPermission',guard),node.get(A+'writePermission',guard)] if node.tag=='provider' else [guard]
        levels=[level(g) for g in guards]
        component=dict(name=node.get(A+'name',''),type=node.tag,exported=declared or 'Unspecified',effective_exported=exported,export_basis=export_basis,enabled=active,permission=guard,permission_protection=level(guard),read_permission=guards[0] if node.tag=='provider' else None,write_permission=guards[1] if node.tag=='provider' else None,actions=sorted(a for a in actions if a),scope='Manifest declaration; caller checks and runtime reachability not verified')
        report['components'].append(component)
        if active and exported:
            if 'None' in levels:add('exported-component','Exported component has an unguarded access path',node,'medium','Components / IPC',message='Effective export is true ('+export_basis+'). At least one access path has no component/application permission guard. Provider path permissions, URI grants and code-level caller checks may further restrict access; exploitation is not established.')
            elif any(v in ('Normal','Dangerous') for v in levels):add('exported-weak-permission','Exported component uses a non-signature permission guard',node,'low','Components / IPC',message='The component is guarded by a normal/dangerous permission; eligible third-party applications may obtain that permission. Caller validation and reachability need review.')
        if node.tag=='provider' and active and isinstance(minimum,int) and minimum<17 and exported is not True:add('legacy-provider-export','Provider export restrictions do not apply on pre-17 devices',node,'info','Components / IPC',message='This APK supports pre-17 Android, where provider exported=false is not enforced. Actual legacy-device use and permission guards must be assessed separately.')
        if active and 'android.intent.category.LAUNCHER' in categories and 'android.intent.action.MAIN' in actions:launchers.append(node)
        if active and actions&{'android.intent.action.BOOT_COMPLETED','android.intent.action.LOCKED_BOOT_COMPLETED','android.intent.action.QUICKBOOT_POWERON','android.intent.action.USER_PRESENT'}:boot.append(node);add('boot-receiver','Startup or unlock event receiver declared',node,'info',message='The manifest declares startup/unlock event handling. Delivery, permission grants and runtime persistence are not verified.')
        if active and node.tag=='service' and guard=='android.permission.BIND_ACCESSIBILITY_SERVICE' and 'android.accessibilityservice.AccessibilityService' in actions:
            access.append(node);add('accessibility-service','Accessibility service declared',node,'medium','Permissions',message='A protected accessibility service is declared. User activation, DEX subclass and runtime UI actions are not verified.')
            meta=next((m for m in node.findall('meta-data') if m.get(A+'name')=='android.accessibilityservice'),None)
            if meta is not None and meta.get(A+'resource'):
                for path,config in xml(meta.get(A+'resource'),'Accessibility settings','accessibility-service'):add('accessibility-service','Accessibility settings inspected',config,'info','Permissions',path=path,extra=[ev(node)])
            else:gaps.append('Accessibility service settings XML is absent; configured accessibility capabilities are unresolved.')
        if active and node.tag=='service' and guard=='android.permission.BIND_NOTIFICATION_LISTENER_SERVICE' and 'android.service.notification.NotificationListenerService' in actions:add('notification-listener','Notification listener service declared',node,'medium','Permissions',message='Notification access capability is declared. User activation and actual notification/OTP capture are not verified.')
        if active and node.tag=='receiver' and guard=='android.permission.BIND_DEVICE_ADMIN' and 'android.app.action.DEVICE_ADMIN_ENABLED' in actions:
            admin.append(node);add('device-admin','Device administrator receiver declared',node,'medium','Permissions')
            meta=next((m for m in node.findall('meta-data') if m.get(A+'name')=='android.app.device_admin'),None)
            if meta is not None and meta.get(A+'resource'):
                for path,config in xml(meta.get(A+'resource'),'Device administrator policies','device-admin'):
                    policies=[n.tag for n in config.findall('./uses-policies/*')];add('device-admin','Device administrator policies inspected',config,'medium' if {'wipe-data','force-lock'}&set(policies) else 'info','Permissions',message='Declared policies: '+', '.join(policies)+'. Device-admin activation and policy execution are not verified.',path=path,extra=[ev(node)])
            else:gaps.append('Device administrator policy XML is absent; requested administrator policies are unresolved.')
        if active and 'android.provider.Telephony.SMS_RECEIVED' in actions:
            sms_receivers.append(node)
            for f in filters:
                if not any(a.get(A+'name')=='android.provider.Telephony.SMS_RECEIVED' for a in f.findall('action')):continue
                try:priority=int(f.get(A+'priority','0'))
                except ValueError:continue
                if priority>100:add('sms-receiver-priority','Elevated SMS receiver priority declared',f,'medium' if short&SMS else 'low',message=f'priority={priority}. Delivery/order depend on Android restrictions and app role; message interception is not proven.',extra=[ev(node)])
        if node.get(A+'directBootAware')=='true':add('direct-boot-aware','Component can operate before device unlock',node,'info',message='directBootAware=true permits access to device-protected storage before unlock. This is context, not evidence of data theft.')
        if node.tag in ('activity','activity-alias') and (A+'taskAffinity' in node.attrib and node.get(A+'taskAffinity')!=root.get('package') or node.get(A+'launchMode') in ('singleTask','singleInstance')):add('task-configuration','Non-default task configuration declared',node,'info',message='Task affinity/launch mode configuration warrants version-specific review. This declaration alone does not prove StrandHogg or task hijacking.')
        for data in node.findall('./intent-filter/data'):
            if data.get(A+'scheme')=='android_secret_code':add('secret-code','Dialer secret-code entry point declared',data,'low',extra=[ev(node)])
        for grant in node.findall('grant-uri-permission'):
            if grant.get(A+'pathPrefix')=='/' or grant.get(A+'pathPattern') in ('*','.*'):add('broad-uri-grant','Provider declares a broad URI grant pattern',grant,'low','Components / IPC',message='A broad grant pattern is declared. Actual URI grants, caller permissions and exposed data must be reviewed.',extra=[ev(node)])
    if 'REQUEST_INSTALL_PACKAGES' in short and 'INTERNET' in short and boot and not launchers:add('capability-install-startup','Installer/network/startup capabilities without a launcher',app,'medium','Capabilities',message='Related declarations coexist in this APK. App stores, updaters and background agents may legitimately use them. No download-to-install data flow or dropper behavior is established.',extra=[ev(boot[0])])
    if short&SMS and 'INTERNET' in short and sms_receivers:add('capability-sms-network','SMS receiver and network capabilities coexist',app,'medium','Capabilities',message='SMS/network declarations coexist. This does not prove SMS exfiltration, toll fraud or a source-to-network flow.',extra=[ev(sms_receivers[0])])
    if access and {'SYSTEM_ALERT_WINDOW','INTERNET'}<=short:add('capability-accessibility-overlay','Accessibility, overlay and network capabilities coexist',app,'medium','Capabilities',message='Related capabilities warrant review. Activation, overlay rendering and credential capture are not observed.',extra=[ev(access[0])])
    if admin and boot:add('capability-admin-startup','Device administrator and startup capabilities coexist',app,'low','Capabilities',message='Administrator and startup declarations coexist. Enterprise agents commonly use this combination; destructive runtime behavior is not established.',extra=[ev(admin[0]),ev(boot[0])])
    backup=app.get(A+'allowBackup','true');report['backup_policy']={'allow_backup':backup,'full_backup_content':app.get(A+'fullBackupContent'),'data_extraction_rules':app.get(A+'dataExtractionRules'),'scope':'Declared configuration; OEM/device transfer behavior and sensitive-data exposure are unverified'}
    if backup!='false':add('backup-exposure','Application backup is enabled or uses the platform default',app,'info',message='Backup declaration requires review against stored data and backup exclusions. This alone is not a vulnerability or malware finding; OS and OEM transfer behavior vary.')
    for attribute,expected in [('fullBackupContent','full-backup-content'),('dataExtractionRules','data-extraction-rules')]:
        reference=app.get(A+attribute)
        if reference and reference not in ('false','true','0','1'):
            for path,config in xml(reference,'Backup rules '+attribute,expected):report['backup_policy'].setdefault('resolved_rules',[]).append({'path':path,'includes':len(config.findall('.//include')),'excludes':len(config.findall('.//exclude'))})
    reference=app.get(A+'networkSecurityConfig')
    if reference:
        for path,config in xml(reference,'Network security configuration','network-security-config'):
            base=config.find('base-config');default=target<28 if isinstance(target,int) else None
            if base is not None and base.get('cleartextTrafficPermitted') in ('true','false'):default=base.get('cleartextTrafficPermitted')=='true'
            def walk(node,clear,debug=False):
                if node.get('cleartextTrafficPermitted') in ('true','false'):clear=node.get('cleartextTrafficPermitted')=='true'
                debug=debug or node.tag=='debug-overrides'
                if node.tag in ('base-config','domain-config') and clear is True:add('cleartext-policy','Network config permits cleartext traffic',node,'medium','Network',message='Cleartext is permitted for this declared configuration scope. Actual HTTP traffic and selected device resource variant are not verified.',path=path)
                if node.tag=='certificates' and node.get('src')=='user':add('network-debug-trust' if debug else 'network-user-trust','Debug trust anchors declared' if debug else 'User-installed certificate trust declared',node,'info' if debug and app.get(A+'debuggable')!='true' else 'low','Network',message='User-added trust anchors are configured. '+('Debug overrides apply only to debuggable builds. ' if debug else '')+'TLS interception and actual traffic are not established.',path=path)
                if node.tag=='certificates' and node.get('overridePins')=='true':add('network-pin-override','Certificate anchor can override pins',node,'info' if debug and app.get(A+'debuggable')!='true' else 'low','Network',message='overridePins=true is declared for this trust anchor. Debug-only scope and release configuration must be considered; a runtime TLS bypass is not established.',path=path)
                for child in node:walk(child,clear,debug)
            walk(config,default)
            if base is None and default is True:add('cleartext-policy','Base network policy uses a cleartext-permitted default',config,'low','Network',message='The target SDK default permits cleartext outside any overriding domain-specific policy. Actual HTTP usage is unverified.',path=path)
    elif app.get(A+'usesCleartextTraffic')=='true':add('cleartext-policy','Cleartext traffic explicitly enabled',app,'medium','Network',message='The manifest explicitly permits cleartext traffic; runtime HTTP usage has not been established.')
    report['static_analysis_gaps']=gaps
    report['manifest_checks_complete']=True
