"""Bounded APK XML resource resolution. No extraction or APK execution."""
import re,struct

class ResourceGap(ValueError):pass

def chunks(data,start,end):
    while start<end:
        if start+8>end:raise ResourceGap('Truncated resource chunk')
        kind,header,size=struct.unpack_from('<HHI',data,start)
        if header<8 or size<header or start+size>end:raise ResourceGap('Invalid resource chunk bounds')
        yield kind,start,header,size
        start+=size

def string_pool(data,start,header,size):
    end=start+size
    if header<28:raise ResourceGap('Invalid resource string pool')
    count,_,flags,offset,_=struct.unpack_from('<IIIII',data,start+8)
    if count>250000 or start+header+4*count>end:raise ResourceGap('Resource string pool exceeds bounds')
    def length(pos,wide):
        if pos+(2 if wide else 1)>end:raise ResourceGap('Truncated resource string')
        n=struct.unpack_from('<H',data,pos)[0] if wide else data[pos];pos+=2 if wide else 1
        marker=0x8000 if wide else 0x80
        if n&marker:
            if pos+(2 if wide else 1)>end:raise ResourceGap('Truncated resource string length')
            extra=struct.unpack_from('<H',data,pos)[0] if wide else data[pos]
            n=((n&(marker-1))<<(16 if wide else 8))|extra;pos+=2 if wide else 1
        return n,pos
    result=[]
    for i in range(count):
        pos=start+offset+struct.unpack_from('<I',data,start+header+i*4)[0]
        if pos<start+header+count*4 or pos>=end:raise ResourceGap('Resource string offset outside pool')
        if flags&0x100:
            _,pos=length(pos,False);n,pos=length(pos,False);width=1;encoding='utf-8'
        else:n,pos=length(pos,True);width=2;encoding='utf-16le'
        if n*width>65536 or pos+n*width>end:raise ResourceGap('Resource string exceeds bounds')
        result.append(data[pos:pos+n*width].decode(encoding,'strict'))
    return result

def xml_paths(data,resource_id):
    """Resolve simple string file resources; dynamic/complex references stay gaps."""
    if len(data)<12 or struct.unpack_from('<H',data)[0]!=2:raise ResourceGap('Unsupported resources.arsc table')
    _,header,total=struct.unpack_from('<HHI',data)
    if total!=len(data):raise ResourceGap('Resource table size mismatch')
    strings=[];paths=[]
    for kind,pos,h,size in chunks(data,header,total):
        if kind==1:strings=string_pool(data,pos,h,size)
        if kind!=0x200:continue
        if h<284:raise ResourceGap('Unsupported resource package header')
        package_id=struct.unpack_from('<I',data,pos+8)[0]
        type_offset=struct.unpack_from('<I',data,pos+284)[0] if h>=288 else 0
        for ck,cp,ch,cs in chunks(data,pos+h,pos+size):
            if ck!=0x201:continue
            if ch<24:raise ResourceGap('Invalid resource type header')
            type_id,flags=struct.unpack_from('<BB',data,cp+8);count,entries_start=struct.unpack_from('<II',data,cp+12)
            if count>250000 or entries_start<ch or entries_start>cs:raise ResourceGap('Resource type bounds exceeded')
            target_index=resource_id&0xffff
            if ((package_id<<24)|((type_id+type_offset)<<16))!=(resource_id&0xffff0000):continue
            table=cp+ch;offset=None
            if flags&1:
                if table+count*4>cp+entries_start:raise ResourceGap('Invalid sparse resource offsets')
                for i in range(count):
                    index,off=struct.unpack_from('<HH',data,table+i*4)
                    if index==target_index:offset=off*4;break
            elif target_index<count:
                width=2 if flags&2 else 4
                if table+count*width>cp+entries_start:raise ResourceGap('Invalid resource entry offsets')
                off=struct.unpack_from('<H' if width==2 else '<I',data,table+target_index*width)[0]
                if off!=(0xffff if width==2 else 0xffffffff):offset=off*4 if width==2 else off
            if offset is None:continue
            ep=cp+entries_start+offset
            if ep+8>cp+cs:raise ResourceGap('Resource entry outside type')
            entry_size,entry_flags=struct.unpack_from('<HH',data,ep)
            if entry_flags&1:continue
            if entry_size<8 or ep+entry_size+8>cp+cs:raise ResourceGap('Invalid resource value')
            value_size,_,dtype,index=struct.unpack_from('<HBBI',data,ep+entry_size)
            if value_size!=8:raise ResourceGap('Unsupported resource value')
            if dtype==3 and index<len(strings) and strings[index] not in paths:paths.append(strings[index])
    if not paths:raise ResourceGap('XML resource ID could not be resolved')
    return paths

class XmlResources:
    def __init__(self,read,parse,names):self.read=read;self.parse=parse;self.names=set(names);self.cache={};self.table=None
    def resolve(self,reference):
        if reference in self.cache:return self.cache[reference]
        match=re.fullmatch(r'@(?:[A-Za-z0-9_.]+:)?xml/([A-Za-z0-9_]+)',str(reference))
        if match:
            name=match.group(1);paths=sorted(p for p in self.names if re.fullmatch(r'res/xml(?:-[A-Za-z0-9_-]+)?/'+re.escape(name)+r'\.xml',p))
        elif re.fullmatch(r'@?0x[0-9a-fA-F]{8}|[0-9]{8,10}',str(reference)):
            if self.table is None:self.table=self.read('resources.arsc')
            value=str(reference).lstrip('@');paths=xml_paths(self.table,int(value,16 if value.startswith('0x') else 10))
        else:raise ResourceGap('Unsupported XML resource reference')
        if not paths or len(paths)>16:raise ResourceGap('XML resource is missing or has too many variants')
        result=[]
        for path in paths:
            # Resource shrinkers rename XML files outside res/xml (e.g. res/Qq.xml).
            # Use the table's exact archive member, never a filesystem path.
            if not re.fullmatch(r'res/[A-Za-z0-9_./-]{1,240}',path) or any(part in ('','..','.') for part in path.split('/')) or path not in self.names:raise ResourceGap('XML resource path is invalid or absent')
            root=self.parse(self.read(path));stack=[(root,0)];count=0
            while stack:
                node,depth=stack.pop();count+=1
                if depth>64 or count>20000:raise ResourceGap('XML resource complexity exceeds bounds')
                stack.extend((child,depth+1) for child in node)
            result.append((path,root))
        self.cache[reference]=result
        return result
