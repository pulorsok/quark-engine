import re
import logging
from typing import Dict, Set, Optional, List, Tuple, Any
from collections import defaultdict, Counter
from dataclasses import dataclass

@dataclass
class NameContext:
    """Context information for name generation"""
    original_name: str
    usage_count: int
    access_patterns: List[str]
    related_names: Set[str]
    semantic_hints: List[str]

class DeobfuscationEngine:
    """Main deobfuscation engine with name restoration logic"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Name mappings
        self.class_mappings: Dict[str, str] = {}
        self.method_mappings: Dict[str, str] = {}
        self.field_mappings: Dict[str, str] = {}
        self.package_mappings: Dict[str, str] = {}
        
        # Usage tracking
        self.class_usage: Counter = Counter()
        self.method_usage: Counter = Counter()
        self.field_usage: Counter = Counter()
        
        # Context tracking
        self.class_contexts: Dict[str, NameContext] = {}
        self.method_contexts: Dict[str, NameContext] = {}
        self.field_contexts: Dict[str, NameContext] = {}
        
        # Obfuscation detection patterns
        self.obfuscated_patterns = [
            re.compile(r'^[a-z]$'),                    # Single lowercase letter
            re.compile(r'^[A-Z]$'),                    # Single uppercase letter
            re.compile(r'^[a-zA-Z]{1,3}$'),           # Very short names (1-3 chars)
            re.compile(r'^[Il1O0]+$'),                # Confusing characters only
            re.compile(r'^[a-z]{1,2}\d+$'),           # Pattern like 'a1', 'b2', 'ab123'
            re.compile(r'^[A-Z]{1,2}\d+$'),           # Pattern like 'A1', 'B2', 'AB123'
            re.compile(r'^[a-zA-Z]\d{2,}$'),          # Single letter + multiple digits
            re.compile(r'^_+[a-zA-Z0-9]*$'),          # Leading underscores
            re.compile(r'^[a-zA-Z0-9]{32,}$'),        # Very long random strings
            re.compile(r'^[a-zA-Z]*[0-9]{3,}[a-zA-Z]*$'),  # Contains 3+ consecutive digits
        ]
        
        # Common Android/Java patterns that are NOT obfuscated
        self.non_obfuscated_patterns = [
            re.compile(r'^(get|set|is|has)[A-Z]'),    # Getters/setters
            re.compile(r'^on[A-Z]'),                  # Event handlers
            re.compile(r'^(onCreate|onDestroy|onStart|onStop|onPause|onResume)$'),  # Android lifecycle
            re.compile(r'^(toString|equals|hashCode|clone)$'),  # Object methods
            re.compile(r'^(main|init|run|start|stop)$'),  # Common method names
            re.compile(r'^[A-Z][a-zA-Z]*Activity$'),  # Android Activities
            re.compile(r'^[A-Z][a-zA-Z]*Service$'),   # Android Services
            re.compile(r'^[A-Z][a-zA-Z]*Fragment$'),  # Android Fragments
            re.compile(r'^[A-Z][a-zA-Z]*Adapter$'),   # Android Adapters
        ]
        
        # Semantic hint patterns
        self.semantic_patterns = {
            'network': ['http', 'url', 'request', 'response', 'socket', 'connection'],
            'crypto': ['encrypt', 'decrypt', 'hash', 'cipher', 'key', 'crypto'],
            'file': ['file', 'read', 'write', 'stream', 'buffer', 'io'],
            'ui': ['view', 'button', 'text', 'image', 'layout', 'widget'],
            'data': ['data', 'json', 'xml', 'parse', 'serialize', 'database'],
            'security': ['permission', 'auth', 'token', 'secure', 'verify'],
            'system': ['system', 'process', 'thread', 'service', 'manager'],
        }
        
        # Name generation counters
        self.class_counter = 0
        self.method_counter = 0
        self.field_counter = 0
        self.package_counter = 0
    
    def is_obfuscated(self, name: str) -> bool:
        """Detect if a name is likely obfuscated using multiple heuristics"""
        if not name or len(name) == 0:
            return False
        
        # Check if it matches non-obfuscated patterns first
        for pattern in self.non_obfuscated_patterns:
            if pattern.match(name):
                return False
        
        # Check obfuscation patterns
        for pattern in self.obfuscated_patterns:
            if pattern.match(name):
                return True
        
        # Additional heuristics
        if self._has_suspicious_characteristics(name):
            return True
        
        return False
    
    def _has_suspicious_characteristics(self, name: str) -> bool:
        """Check for additional suspicious characteristics"""
        # Very high ratio of consonants to vowels
        vowels = sum(1 for c in name.lower() if c in 'aeiou')
        consonants = sum(1 for c in name.lower() if c.isalpha() and c not in 'aeiou')
        
        if len(name) > 3 and vowels == 0 and consonants > 2:
            return True
        
        # Repeating patterns
        if len(name) > 4 and len(set(name)) < len(name) / 2:
            return True
        
        # Mixed case in unusual patterns
        if re.search(r'[a-z][A-Z][a-z]', name) and len(name) < 6:
            return True
        
        return False
    
    def analyze_context(self, name: str, context_type: str, **kwargs) -> NameContext:
        """Analyze context for better name generation"""
        usage_count = kwargs.get('usage_count', 0)
        access_patterns = kwargs.get('access_patterns', [])
        related_names = kwargs.get('related_names', set())
        
        # Extract semantic hints
        semantic_hints = []
        for category, keywords in self.semantic_patterns.items():
            for keyword in keywords:
                if keyword.lower() in name.lower() or any(keyword.lower() in related.lower() for related in related_names):
                    semantic_hints.append(category)
                    break
        
        return NameContext(
            original_name=name,
            usage_count=usage_count,
            access_patterns=access_patterns,
            related_names=related_names,
            semantic_hints=semantic_hints
        )
    
    def generate_meaningful_name(self, context: NameContext, name_type: str) -> str:
        """Generate meaningful names based on context and usage patterns"""
        base_name = ""
        
        # Use semantic hints if available
        if context.semantic_hints:
            primary_hint = context.semantic_hints[0]
            if name_type == 'class':
                base_name = f"{primary_hint.capitalize()}Class"
            elif name_type == 'method':
                base_name = f"{primary_hint}Method"
            else:
                base_name = f"{primary_hint}Field"
        else:
            # Generate based on type and usage
            if name_type == 'class':
                self.class_counter += 1
                base_name = f"DeobfClass{self.class_counter}"
            elif name_type == 'method':
                self.method_counter += 1
                if 'static' in context.access_patterns:
                    base_name = f"staticMethod{self.method_counter}"
                elif 'private' in context.access_patterns:
                    base_name = f"privateMethod{self.method_counter}"
                else:
                    base_name = f"method{self.method_counter}"
            elif name_type == 'field':
                self.field_counter += 1
                if 'static' in context.access_patterns and 'final' in context.access_patterns:
                    base_name = f"CONSTANT_{self.field_counter}"
                elif 'static' in context.access_patterns:
                    base_name = f"staticField{self.field_counter}"
                else:
                    base_name = f"field{self.field_counter}"
            else:  # package
                self.package_counter += 1
                base_name = f"pkg{self.package_counter}"
        
        # Add usage frequency indicator for highly used items
        if context.usage_count > 10:
            base_name += "_frequent"
        elif context.usage_count > 50:
            base_name += "_common"
        
        return base_name
    
    def deobfuscate_class_name(self, class_name: str, **kwargs) -> str:
        """Restore meaningful class names"""
        if not self.is_obfuscated(class_name):
            return class_name
        
        if class_name in self.class_mappings:
            return self.class_mappings[class_name]
        
        # Track usage
        self.class_usage[class_name] += 1
        
        # Analyze context
        context = self.analyze_context(
            class_name, 
            'class',
            usage_count=self.class_usage[class_name],
            **kwargs
        )
        
        # Generate new name
        new_name = self.generate_meaningful_name(context, 'class')
        
        # Store mappings and context
        self.class_mappings[class_name] = new_name
        self.class_contexts[class_name] = context
        
        self.logger.debug(f"Deobfuscated class: {class_name} -> {new_name}")
        return new_name
    
    def deobfuscate_method_name(self, method_name: str, **kwargs) -> str:
        """Restore meaningful method names"""
        if not self.is_obfuscated(method_name):
            return method_name
        
        if method_name in self.method_mappings:
            return self.method_mappings[method_name]
        
        # Track usage
        self.method_usage[method_name] += 1
        
        # Analyze context
        context = self.analyze_context(
            method_name,
            'method',
            usage_count=self.method_usage[method_name],
            **kwargs
        )
        
        # Generate new name
        new_name = self.generate_meaningful_name(context, 'method')
        
        # Store mappings and context
        self.method_mappings[method_name] = new_name
        self.method_contexts[method_name] = context
        
        self.logger.debug(f"Deobfuscated method: {method_name} -> {new_name}")
        return new_name
    
    def deobfuscate_field_name(self, field_name: str, **kwargs) -> str:
        """Restore meaningful field names"""
        if not self.is_obfuscated(field_name):
            return field_name
        
        if field_name in self.field_mappings:
            return self.field_mappings[field_name]
        
        # Track usage
        self.field_usage[field_name] += 1
        
        # Analyze context
        context = self.analyze_context(
            field_name,
            'field',
            usage_count=self.field_usage[field_name],
            **kwargs
        )
        
        # Generate new name
        new_name = self.generate_meaningful_name(context, 'field')
        
        # Store mappings and context
        self.field_mappings[field_name] = new_name
        self.field_contexts[field_name] = context
        
        self.logger.debug(f"Deobfuscated field: {field_name} -> {new_name}")
        return new_name
    
    def deobfuscate_package_name(self, package_name: str, **kwargs) -> str:
        """Restore meaningful package names"""
        if not self.is_obfuscated(package_name):
            return package_name
        
        if package_name in self.package_mappings:
            return self.package_mappings[package_name]
        
        # Analyze context
        context = self.analyze_context(package_name, 'package', **kwargs)
        
        # Generate new name
        new_name = self.generate_meaningful_name(context, 'package')
        
        # Store mapping
        self.package_mappings[package_name] = new_name
        
        self.logger.debug(f"Deobfuscated package: {package_name} -> {new_name}")
        return new_name
    
    def get_mapping_statistics(self) -> Dict[str, Any]:
        """Get statistics about the deobfuscation process"""
        return {
            'classes_deobfuscated': len(self.class_mappings),
            'methods_deobfuscated': len(self.method_mappings),
            'fields_deobfuscated': len(self.field_mappings),
            'packages_deobfuscated': len(self.package_mappings),
            'total_class_usages': sum(self.class_usage.values()),
            'total_method_usages': sum(self.method_usage.values()),
            'total_field_usages': sum(self.field_usage.values()),
            'most_used_classes': self.class_usage.most_common(10),
            'most_used_methods': self.method_usage.most_common(10),
            'most_used_fields': self.field_usage.most_common(10),
        }
    
    def export_mappings(self) -> Dict[str, Dict[str, str]]:
        """Export all name mappings for external use"""
        return {
            'classes': self.class_mappings.copy(),
            'methods': self.method_mappings.copy(),
            'fields': self.field_mappings.copy(),
            'packages': self.package_mappings.copy(),
        }
    
    def import_mappings(self, mappings: Dict[str, Dict[str, str]]) -> None:
        """Import name mappings from external source"""
        if 'classes' in mappings:
            self.class_mappings.update(mappings['classes'])
        if 'methods' in mappings:
            self.method_mappings.update(mappings['methods'])
        if 'fields' in mappings:
            self.field_mappings.update(mappings['fields'])
        if 'packages' in mappings:
            self.package_mappings.update(mappings['packages'])
        
        self.logger.info(f"Imported mappings: {len(mappings)} categories")
    
    def clear_mappings(self) -> None:
        """Clear all mappings and reset counters"""
        self.class_mappings.clear()
        self.method_mappings.clear()
        self.field_mappings.clear()
        self.package_mappings.clear()
        
        self.class_usage.clear()
        self.method_usage.clear()
        self.field_usage.clear()
        
        self.class_contexts.clear()
        self.method_contexts.clear()
        self.field_contexts.clear()
        
        self.class_counter = 0
        self.method_counter = 0
        self.field_counter = 0
        self.package_counter = 0
        
        self.logger.info("Cleared all deobfuscation mappings and contexts")