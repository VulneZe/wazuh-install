"""
Configuration Cache
Implements caching for configuration operations to improve performance
"""

import time
import hashlib
import json
from typing import Any, Optional, Dict
from threading import Lock
from dataclasses import dataclass
from functools import wraps


@dataclass
class CacheEntry:
    """Cache entry with expiration"""
    value: Any
    timestamp: float
    ttl: int = 3600  # Default TTL: 1 hour
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired"""
        return time.time() - self.timestamp > self.ttl


class ConfigCache:
    """Thread-safe configuration cache"""
    
    def __init__(self, default_ttl: int = 3600):
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = Lock()
        self.default_ttl = default_ttl
    
    def _generate_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Generate a unique cache key from function arguments"""
        key_data = {
            'func': func_name,
            'args': str(args),
            'kwargs': str(sorted(kwargs.items()))
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            
            if entry.is_expired():
                del self._cache[key]
                return None
            
            return entry.value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache"""
        with self._lock:
            entry_ttl = ttl if ttl is not None else self.default_ttl
            self._cache[key] = CacheEntry(
                value=value,
                timestamp=time.time(),
                ttl=entry_ttl
            )
    
    def invalidate(self, key: str) -> None:
        """Invalidate a specific cache entry"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove expired cache entries and return count of removed entries"""
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)


# Global cache instance
global_cache = ConfigCache()


def cached(ttl: Optional[int] = None):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = global_cache._generate_key(
                func.__name__,
                args,
                kwargs
            )
            
            # Try to get from cache
            cached_value = global_cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            global_cache.set(cache_key, result, ttl)
            
            return result
        return wrapper
    return decorator


def cache_invalidate(*keys: str):
    """Decorator to invalidate cache entries after function execution"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            for key in keys:
                global_cache.invalidate(key)
            return result
        return wrapper
    return decorator
