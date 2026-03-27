"""
Quark-Engine Deobfuscation Module

This module provides comprehensive deobfuscation capabilities for Android APK analysis.
It can restore meaningful names for obfuscated classes, methods, and fields using
heuristic-based detection and context-aware name generation.
"""

from .deobfuscator import DeobfuscationEngine
from .name_generator import NameGenerator
from .pattern_analyzer import PatternAnalyzer
from .context_analyzer import ContextAnalyzer

__version__ = "1.0.0"
__author__ = "Quark-Engine Team"

__all__ = [
    "DeobfuscationEngine",
    "NameGenerator", 
    "PatternAnalyzer",
    "ContextAnalyzer"
]

# Default deobfuscation engine instance
default_engine = None

def get_default_engine():
    """Get the default deobfuscation engine instance."""
    global default_engine
    if default_engine is None:
        default_engine = DeobfuscationEngine()
    return default_engine

def deobfuscate_name(name, context="unknown"):
    """Convenience function to deobfuscate a name using the default engine."""
    engine = get_default_engine()
    return engine.deobfuscate_name(name, context)

def is_obfuscated(name):
    """Convenience function to check if a name is obfuscated using the default engine."""
    engine = get_default_engine()
    return engine.is_obfuscated(name)

# Configuration constants
DEFAULT_MIN_NAME_LENGTH = 2
DEFAULT_MAX_NAME_LENGTH = 50
DEFAULT_OBFUSCATION_THRESHOLD = 0.7

# Common obfuscation patterns
COMMON_OBFUSCATED_PATTERNS = [
    r'^[a-z]$',                    # Single lowercase letter
    r'^[A-Z]$',                    # Single uppercase letter  
    r'^[a-zA-Z]{1,2}$',           # Very short names (1-2 chars)
    r'^[Il1O0]+$',                # Confusing similar characters
    r'^[a-z]+\d+$',               # Letter followed by numbers
    r'^\w{1,3}$',                 # Generic short identifiers
]

# Context types for deobfuscation
CONTEXT_CLASS = "class"
CONTEXT_METHOD = "method"
CONTEXT_FIELD = "field"
CONTEXT_PACKAGE = "package"
CONTEXT_VARIABLE = "variable"