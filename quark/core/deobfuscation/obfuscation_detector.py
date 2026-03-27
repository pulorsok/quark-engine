import re
from typing import Dict, Set, List, Optional, Tuple
from collections import defaultdict, Counter
import string
import math

class ObfuscationDetector:
    """
    Heuristics-based detector for obfuscated identifiers in Android applications.
    Uses multiple detection strategies to identify obfuscated classes, methods, and fields.
    """
    
    def __init__(self):
        # Compile regex patterns for different obfuscation types
        self.single_char_pattern = re.compile(r'^[a-zA-Z]$')
        self.short_name_pattern = re.compile(r'^[a-zA-Z]{1,3}$')
        self.confusing_chars_pattern = re.compile(r'^[Il1O0]+$')
        self.sequential_pattern = re.compile(r'^[a-z]+\d*$')
        self.random_pattern = re.compile(r'^[a-zA-Z]{2,8}$')
        
        # Common obfuscation patterns
        self.obfuscation_patterns = [
            self.single_char_pattern,
            self.short_name_pattern,
            self.confusing_chars_pattern
        ]
        
        # Dictionary words and common programming terms (subset for performance)
        self.common_words = {
            'get', 'set', 'is', 'has', 'can', 'should', 'will', 'create', 'init',
            'start', 'stop', 'run', 'execute', 'process', 'handle', 'update',
            'add', 'remove', 'delete', 'find', 'search', 'load', 'save',
            'read', 'write', 'open', 'close', 'connect', 'disconnect',
            'main', 'test', 'util', 'helper', 'manager', 'service', 'client',
            'server', 'handler', 'listener', 'adapter', 'factory', 'builder'
        }
        
        # Android-specific terms
        self.android_terms = {
            'activity', 'fragment', 'service', 'receiver', 'provider',
            'intent', 'bundle', 'context', 'view', 'layout', 'widget',
            'adapter', 'listener', 'callback', 'async', 'task'
        }
        
        # Statistics for entropy calculation
        self.identifier_stats = defaultdict(int)
        self.length_distribution = Counter()
        
    def is_obfuscated_identifier(self, identifier: str, context: str = 'unknown') -> bool:
        """
        Main method to detect if an identifier is obfuscated.
        
        Args:
            identifier: The identifier to check
            context: Context type ('class', 'method', 'field', 'package')
            
        Returns:
            True if the identifier appears to be obfuscated
        """
        if not identifier or len(identifier) == 0:
            return False
            
        # Skip system/framework identifiers
        if self._is_system_identifier(identifier):
            return False
            
        # Apply multiple heuristics
        obfuscation_score = 0
        
        # Pattern-based detection
        if self._matches_obfuscation_patterns(identifier):
            obfuscation_score += 3
            
        # Length-based detection
        if self._is_suspicious_length(identifier, context):
            obfuscation_score += 2
            
        # Entropy-based detection
        if self._has_high_entropy(identifier):
            obfuscation_score += 2
            
        # Dictionary-based detection
        if not self._contains_meaningful_words(identifier):
            obfuscation_score += 1
            
        # Context-specific checks
        if self._violates_naming_conventions(identifier, context):
            obfuscation_score += 2
            
        # Character distribution analysis
        if self._has_suspicious_char_distribution(identifier):
            obfuscation_score += 1
            
        return obfuscation_score >= 4
        
    def _matches_obfuscation_patterns(self, identifier: str) -> bool:
        """Check if identifier matches known obfuscation patterns."""
        return any(pattern.match(identifier) for pattern in self.obfuscation_patterns)
        
    def _is_suspicious_length(self, identifier: str, context: str) -> bool:
        """Check if identifier length is suspicious for its context."""
        length = len(identifier)
        
        if context == 'class':
            return length <= 2 or (length == 3 and identifier.islower())
        elif context == 'method':
            return length <= 2
        elif context == 'field':
            return length <= 2
        elif context == 'package':
            return length <= 2
            
        return length <= 2
        
    def _has_high_entropy(self, identifier: str) -> bool:
        """Calculate entropy to detect random-looking identifiers."""
        if len(identifier) <= 2:
            return False
            
        # Calculate character frequency
        char_counts = Counter(identifier.lower())
        total_chars = len(identifier)
        
        # Calculate Shannon entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)
            
        # High entropy threshold (adjusted for identifier length)
        max_entropy = math.log2(min(26, len(identifier)))
        entropy_ratio = entropy / max_entropy if max_entropy > 0 else 0
        
        return entropy_ratio > 0.8 and len(identifier) >= 4
        
    def _contains_meaningful_words(self, identifier: str) -> bool:
        """Check if identifier contains recognizable words."""
        lower_id = identifier.lower()
        
        # Check for exact matches
        if lower_id in self.common_words or lower_id in self.android_terms:
            return True
            
        # Check for partial matches (camelCase or snake_case)
        words = self._extract_words_from_identifier(identifier)
        for word in words:
            if word.lower() in self.common_words or word.lower() in self.android_terms:
                return True
                
        return False
        
    def _extract_words_from_identifier(self, identifier: str) -> List[str]:
        """Extract potential words from camelCase or snake_case identifiers."""
        words = []
        
        # Handle camelCase
        camel_words = re.findall(r'[A-Z][a-z]*|[a-z]+', identifier)
        words.extend(camel_words)
        
        # Handle snake_case
        if '_' in identifier:
            snake_words = identifier.split('_')
            words.extend(snake_words)
            
        # Filter out very short words
        return [word for word in words if len(word) >= 2]
        
    def _violates_naming_conventions(self, identifier: str, context: str) -> bool:
        """Check if identifier violates common naming conventions."""
        if context == 'class':
            # Classes should start with uppercase
            return not identifier[0].isupper() and len(identifier) > 1
        elif context == 'method':
            # Methods should start with lowercase (Java convention)
            return identifier[0].isupper() and not self._is_constant_name(identifier)
        elif context == 'field':
            # Fields typically start with lowercase unless constants
            if self._is_constant_name(identifier):
                return False
            return identifier[0].isupper()
            
        return False
        
    def _is_constant_name(self, identifier: str) -> bool:
        """Check if identifier follows constant naming convention."""
        return identifier.isupper() and ('_' in identifier or len(identifier) <= 5)
        
    def _has_suspicious_char_distribution(self, identifier: str) -> bool:
        """Analyze character distribution for obfuscation indicators."""
        if len(identifier) <= 3:
            return False
            
        # Check for repeated characters
        char_counts = Counter(identifier.lower())
        max_char_freq = max(char_counts.values())
        
        # If any character appears more than 60% of the time, it's suspicious
        if max_char_freq / len(identifier) > 0.6:
            return True
            
        # Check for sequential characters (abc, xyz, etc.)
        if self._has_sequential_chars(identifier):
            return True
            
        return False
        
    def _has_sequential_chars(self, identifier: str) -> bool:
        """Check for sequential character patterns."""
        lower_id = identifier.lower()
        
        for i in range(len(lower_id) - 2):
            if (ord(lower_id[i+1]) == ord(lower_id[i]) + 1 and 
                ord(lower_id[i+2]) == ord(lower_id[i]) + 2):
                return True
                
        return False
        
    def _is_system_identifier(self, identifier: str) -> bool:
        """Check if identifier belongs to system/framework code."""
        system_prefixes = [
            'android', 'java', 'javax', 'org.apache', 'com.google',
            'androidx', 'kotlin', 'dalvik', 'libcore'
        ]
        
        lower_id = identifier.lower()
        return any(lower_id.startswith(prefix) for prefix in system_prefixes)
        
    def analyze_obfuscation_level(self, identifiers: List[Tuple[str, str]]) -> Dict[str, float]:
        """
        Analyze the overall obfuscation level of a set of identifiers.
        
        Args:
            identifiers: List of (identifier, context) tuples
            
        Returns:
            Dictionary with obfuscation statistics
        """
        total_count = len(identifiers)
        if total_count == 0:
            return {'obfuscation_ratio': 0.0, 'confidence': 0.0}
            
        obfuscated_count = 0
        context_stats = defaultdict(lambda: {'total': 0, 'obfuscated': 0})
        
        for identifier, context in identifiers:
            context_stats[context]['total'] += 1
            if self.is_obfuscated_identifier(identifier, context):
                obfuscated_count += 1
                context_stats[context]['obfuscated'] += 1
                
        obfuscation_ratio = obfuscated_count / total_count
        
        # Calculate confidence based on sample size and consistency
        confidence = min(1.0, total_count / 100.0)  # More samples = higher confidence
        
        # Adjust confidence based on context consistency
        context_ratios = []
        for stats in context_stats.values():
            if stats['total'] > 0:
                ratio = stats['obfuscated'] / stats['total']
                context_ratios.append(ratio)
                
        if context_ratios:
            ratio_variance = sum((r - obfuscation_ratio) ** 2 for r in context_ratios) / len(context_ratios)
            confidence *= (1.0 - min(0.5, ratio_variance))  # Lower variance = higher confidence
            
        return {
            'obfuscation_ratio': obfuscation_ratio,
            'confidence': confidence,
            'total_identifiers': total_count,
            'obfuscated_identifiers': obfuscated_count,
            'context_breakdown': dict(context_stats)
        }
        
    def get_obfuscation_indicators(self, identifier: str, context: str = 'unknown') -> List[str]:
        """
        Get specific indicators that suggest the identifier is obfuscated.
        
        Returns:
            List of human-readable obfuscation indicators
        """
        indicators = []
        
        if self._matches_obfuscation_patterns(identifier):
            indicators.append("Matches known obfuscation patterns")
            
        if self._is_suspicious_length(identifier, context):
            indicators.append(f"Suspicious length for {context}")
            
        if self._has_high_entropy(identifier):
            indicators.append("High character entropy (random-looking)")
            
        if not self._contains_meaningful_words(identifier):
            indicators.append("Contains no recognizable words")
            
        if self._violates_naming_conventions(identifier, context):
            indicators.append(f"Violates {context} naming conventions")
            
        if self._has_suspicious_char_distribution(identifier):
            indicators.append("Suspicious character distribution")
            
        return indicators