import re
from typing import Dict, Set, Optional, List, Tuple
from collections import defaultdict, Counter
import hashlib

class NameGenerator:
    """Intelligent name generation based on usage patterns and context analysis"""
    
    def __init__(self):
        self.class_mappings: Dict[str, str] = {}
        self.method_mappings: Dict[str, str] = {}
        self.field_mappings: Dict[str, str] = {}
        self.package_mappings: Dict[str, str] = {}
        
        # Usage pattern tracking
        self.method_usage_patterns: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.field_usage_patterns: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.class_inheritance_patterns: Dict[str, Set[str]] = defaultdict(set)
        
        # Context-based naming
        self.android_api_patterns = self._load_android_api_patterns()
        self.common_method_patterns = self._load_common_method_patterns()
        self.semantic_keywords = self._load_semantic_keywords()
        
        # Obfuscation detection patterns
        self.obfuscated_patterns = [
            re.compile(r'^[a-z]$'),  # Single lowercase letter
            re.compile(r'^[A-Z]$'),  # Single uppercase letter
            re.compile(r'^[a-zA-Z]{1,2}$'),  # Very short names (1-2 chars)
            re.compile(r'^[Il1O0]+$'),  # Confusing characters only
            re.compile(r'^[a-z]{1,3}\d*$'),  # Short letters with optional numbers
            re.compile(r'^\w{1,3}$'),  # Generic short identifiers
            re.compile(r'^(aa|bb|cc|dd|ee|ff|gg|hh|ii|jj|kk|ll|mm|nn|oo|pp|qq|rr|ss|tt|uu|vv|ww|xx|yy|zz)$'),  # Repeated letters
        ]
        
        # Counter for generating unique names
        self.name_counters = defaultdict(int)
    
    def _load_android_api_patterns(self) -> Dict[str, List[str]]:
        """Load common Android API usage patterns"""
        return {
            'activity': ['onCreate', 'onResume', 'onPause', 'onDestroy', 'startActivity'],
            'service': ['onStartCommand', 'onBind', 'onUnbind', 'stopSelf'],
            'receiver': ['onReceive', 'registerReceiver', 'unregisterReceiver'],
            'view': ['findViewById', 'setOnClickListener', 'setVisibility', 'inflate'],
            'database': ['getReadableDatabase', 'getWritableDatabase', 'execSQL', 'query'],
            'network': ['HttpURLConnection', 'execute', 'doInBackground', 'onPostExecute'],
            'crypto': ['encrypt', 'decrypt', 'generateKey', 'cipher', 'digest'],
            'file': ['openFileInput', 'openFileOutput', 'getExternalStorageDirectory'],
        }
    
    def _load_common_method_patterns(self) -> Dict[str, List[str]]:
        """Load common method naming patterns"""
        return {
            'getter': ['get', 'is', 'has', 'can', 'should'],
            'setter': ['set', 'put', 'add', 'remove', 'update'],
            'action': ['do', 'perform', 'execute', 'run', 'start', 'stop'],
            'validation': ['validate', 'check', 'verify', 'ensure'],
            'conversion': ['to', 'from', 'parse', 'format', 'convert'],
            'lifecycle': ['init', 'create', 'destroy', 'cleanup', 'dispose'],
        }
    
    def _load_semantic_keywords(self) -> Dict[str, List[str]]:
        """Load semantic keywords for context analysis"""
        return {
            'data': ['data', 'info', 'content', 'payload', 'message'],
            'config': ['config', 'settings', 'preferences', 'options'],
            'security': ['key', 'token', 'auth', 'credential', 'certificate'],
            'ui': ['view', 'layout', 'widget', 'dialog', 'fragment'],
            'network': ['url', 'request', 'response', 'connection', 'client'],
            'storage': ['file', 'database', 'cache', 'storage', 'repository'],
        }
    
    def is_obfuscated(self, name: str) -> bool:
        """Detect if a name is likely obfuscated using multiple heuristics"""
        if not name or len(name) == 0:
            return False
            
        # Check against obfuscation patterns
        for pattern in self.obfuscated_patterns:
            if pattern.match(name):
                return True
        
        # Check for meaningless character sequences
        if self._is_meaningless_sequence(name):
            return True
            
        # Check entropy (randomness) of the name
        if self._has_high_entropy(name) and len(name) <= 8:
            return True
            
        return False
    
    def _is_meaningless_sequence(self, name: str) -> bool:
        """Check if name is a meaningless character sequence"""
        # Check for patterns like "aaa", "abc", "xyz"
        if len(set(name)) == 1 and len(name) > 1:  # All same character
            return True
            
        # Check for sequential patterns
        if len(name) >= 3:
            ascii_vals = [ord(c) for c in name.lower()]
            if all(ascii_vals[i] + 1 == ascii_vals[i + 1] for i in range(len(ascii_vals) - 1)):
                return True
                
        return False
    
    def _has_high_entropy(self, name: str) -> bool:
        """Calculate entropy to detect random-looking names"""
        if len(name) <= 2:
            return False
            
        char_counts = Counter(name.lower())
        total_chars = len(name)
        entropy = -sum((count / total_chars) * (count / total_chars).bit_length() 
                      for count in char_counts.values())
        
        # High entropy threshold for short names
        return entropy > 2.5 and len(name) <= 6
    
    def analyze_usage_context(self, name: str, context_type: str, usage_info: Dict) -> str:
        """Analyze usage context to determine appropriate name category"""
        if context_type == 'method':
            return self._analyze_method_context(name, usage_info)
        elif context_type == 'field':
            return self._analyze_field_context(name, usage_info)
        elif context_type == 'class':
            return self._analyze_class_context(name, usage_info)
        else:
            return 'unknown'
    
    def _analyze_method_context(self, method_name: str, usage_info: Dict) -> str:
        """Analyze method usage patterns to determine its purpose"""
        # Check method calls and API usage
        called_methods = usage_info.get('called_methods', [])
        return_type = usage_info.get('return_type', '')
        parameters = usage_info.get('parameters', [])
        
        # Analyze Android API patterns
        for category, patterns in self.android_api_patterns.items():
            if any(pattern in ' '.join(called_methods).lower() for pattern in patterns):
                return category
        
        # Analyze method signature patterns
        if return_type in ['boolean', 'bool']:
            return 'predicate'
        elif len(parameters) == 0 and return_type != 'void':
            return 'getter'
        elif len(parameters) > 0 and return_type == 'void':
            return 'setter'
        elif 'String' in return_type or 'toString' in called_methods:
            return 'formatter'
        
        return 'method'
    
    def _analyze_field_context(self, field_name: str, usage_info: Dict) -> str:
        """Analyze field usage patterns"""
        field_type = usage_info.get('type', '')
        access_pattern = usage_info.get('access_pattern', '')
        
        # Analyze field type
        if 'String' in field_type:
            if any(keyword in field_name.lower() for keyword in ['url', 'uri', 'path']):
                return 'url'
            elif any(keyword in field_name.lower() for keyword in ['key', 'token', 'auth']):
                return 'credential'
            else:
                return 'text'
        elif field_type in ['int', 'long', 'Integer', 'Long']:
            return 'counter' if 'count' in access_pattern else 'number'
        elif field_type in ['boolean', 'Boolean']:
            return 'flag'
        elif 'List' in field_type or 'Array' in field_type:
            return 'collection'
        
        return 'field'
    
    def _analyze_class_context(self, class_name: str, usage_info: Dict) -> str:
        """Analyze class usage patterns"""
        superclass = usage_info.get('superclass', '')
        interfaces = usage_info.get('interfaces', [])
        methods = usage_info.get('methods', [])
        
        # Check Android component patterns
        if 'Activity' in superclass:
            return 'activity'
        elif 'Service' in superclass:
            return 'service'
        elif 'BroadcastReceiver' in superclass:
            return 'receiver'
        elif 'View' in superclass or any('View' in iface for iface in interfaces):
            return 'view'
        elif any('Listener' in iface for iface in interfaces):
            return 'listener'
        elif any(method.startswith('on') for method in methods):
            return 'callback'
        
        return 'class'
    
    def generate_meaningful_name(self, original_name: str, context_type: str, 
                                context_category: str, usage_info: Dict = None) -> str:
        """Generate meaningful names based on context and usage patterns"""
        usage_info = usage_info or {}
        
        if context_type == 'class':
            return self._generate_class_name(original_name, context_category, usage_info)
        elif context_type == 'method':
            return self._generate_method_name(original_name, context_category, usage_info)
        elif context_type == 'field':
            return self._generate_field_name(original_name, context_category, usage_info)
        elif context_type == 'package':
            return self._generate_package_name(original_name, context_category, usage_info)
        else:
            return self._generate_generic_name(original_name, context_type)
    
    def _generate_class_name(self, original_name: str, category: str, usage_info: Dict) -> str:
        """Generate meaningful class names"""
        base_names = {
            'activity': 'MainActivity',
            'service': 'BackgroundService',
            'receiver': 'BroadcastReceiver',
            'view': 'CustomView',
            'listener': 'EventListener',
            'callback': 'CallbackHandler',
            'adapter': 'DataAdapter',
            'fragment': 'ContentFragment',
            'dialog': 'CustomDialog',
            'util': 'UtilityClass',
            'helper': 'HelperClass',
            'manager': 'DataManager',
            'provider': 'ContentProvider',
            'builder': 'ObjectBuilder',
            'factory': 'ObjectFactory',
        }
        
        base_name = base_names.get(category, 'DeobfuscatedClass')
        counter = self.name_counters[f'class_{category}']
        self.name_counters[f'class_{category}'] += 1
        
        if counter == 0:
            return base_name
        else:
            return f"{base_name}{counter}"
    
    def _generate_method_name(self, original_name: str, category: str, usage_info: Dict) -> str:
        """Generate meaningful method names"""
        base_names = {
            'getter': 'getValue',
            'setter': 'setValue',
            'predicate': 'isValid',
            'action': 'performAction',
            'validation': 'validateInput',
            'conversion': 'convertData',
            'lifecycle': 'initialize',
            'activity': 'handleActivity',
            'service': 'processService',
            'network': 'handleNetwork',
            'crypto': 'processCrypto',
            'database': 'queryDatabase',
            'file': 'handleFile',
            'formatter': 'formatData',
        }
        
        base_name = base_names.get(category, 'deobfuscatedMethod')
        counter = self.name_counters[f'method_{category}']
        self.name_counters[f'method_{category}'] += 1
        
        if counter == 0:
            return base_name
        else:
            return f"{base_name}{counter}"
    
    def _generate_field_name(self, original_name: str, category: str, usage_info: Dict) -> str:
        """Generate meaningful field names"""
        base_names = {
            'text': 'textValue',
            'url': 'urlString',
            'credential': 'authToken',
            'counter': 'itemCount',
            'number': 'numericValue',
            'flag': 'isEnabled',
            'collection': 'dataList',
            'config': 'configValue',
            'ui': 'uiComponent',
            'data': 'dataObject',
        }
        
        base_name = base_names.get(category, 'deobfuscatedField')
        counter = self.name_counters[f'field_{category}']
        self.name_counters[f'field_{category}'] += 1
        
        if counter == 0:
            return base_name
        else:
            return f"{base_name}{counter}"
    
    def _generate_package_name(self, original_name: str, category: str, usage_info: Dict) -> str:
        """Generate meaningful package names"""
        # Extract meaningful parts from the original package name
        parts = original_name.split('.')
        meaningful_parts = []
        
        for part in parts:
            if not self.is_obfuscated(part):
                meaningful_parts.append(part)
            else:
                meaningful_parts.append(f"pkg{len(meaningful_parts)}")
        
        return '.'.join(meaningful_parts)
    
    def _generate_generic_name(self, original_name: str, context_type: str) -> str:
        """Generate generic meaningful names"""
        counter = self.name_counters[f'generic_{context_type}']
        self.name_counters[f'generic_{context_type}'] += 1
        
        return f"deobfuscated{context_type.capitalize()}{counter}"
    
    def get_name_mapping(self, original_name: str, context_type: str) -> Optional[str]:
        """Get existing name mapping if available"""
        mappings = {
            'class': self.class_mappings,
            'method': self.method_mappings,
            'field': self.field_mappings,
            'package': self.package_mappings,
        }
        
        return mappings.get(context_type, {}).get(original_name)
    
    def store_name_mapping(self, original_name: str, new_name: str, context_type: str):
        """Store name mapping for consistency"""
        mappings = {
            'class': self.class_mappings,
            'method': self.method_mappings,
            'field': self.