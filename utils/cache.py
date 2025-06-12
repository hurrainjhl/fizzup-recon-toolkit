import os
import json
import hashlib
import time
from functools import wraps
from typing import Callable, Any, Dict, Optional

class CacheManager:
    """
    Intelligent caching system with expiration and automatic invalidation
    Supports both memory and disk-based caching
    """
    def __init__(self, cache_dir: str = ".recon_cache", max_memory_items: int = 1000, default_ttl: int = 3600):
        self.cache_dir = cache_dir
        self.max_memory_items = max_memory_items
        self.default_ttl = default_ttl
        self.memory_cache: Dict[str, Dict] = {}
        self._ensure_cache_dir()
    
    def _ensure_cache_dir(self):
        """Create cache directory if it doesn't exist"""
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
    
    def _get_cache_key(self, func: Callable, *args, **kwargs) -> str:
        """Generate unique cache key for function call"""
        arg_hash = hashlib.sha256()
        arg_hash.update(json.dumps((args, kwargs), sort_keys=True).encode())
        return f"{func.__module__}.{func.__name__}_{arg_hash.hexdigest()[:16]}"
    
    def _get_cache_path(self, key: str) -> str:
        """Get file path for cache key"""
        return os.path.join(self.cache_dir, f"{key}.json")
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve cached item from memory or disk"""
        # Check memory cache first
        if key in self.memory_cache:
            item = self.memory_cache[key]
            if item['expiry'] > time.time():
                return item['data']
            del self.memory_cache[key]
        
        # Check disk cache
        cache_file = self._get_cache_path(key)
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    item = json.load(f)
                    if item['expiry'] > time.time():
                        # Promote to memory cache
                        self.memory_cache[key] = item
                        return item['data']
                    os.remove(cache_file)  # Remove expired cache
            except (json.JSONDecodeError, KeyError):
                os.remove(cache_file)
        return None
    
    def set(self, key: str, data: Any, expiry: Optional[int] = None):
        """Store data in cache with expiration"""
        if expiry is None:
            expiry = self.default_ttl
        expiry_time = time.time() + expiry
        item = {'data': data, 'expiry': expiry_time, 'created': time.time()}
        
        # Store in memory
        self.memory_cache[key] = item
        
        # Persist to disk
        cache_file = self._get_cache_path(key)
        with open(cache_file, 'w') as f:
            json.dump(item, f)
        
        # Clean memory cache if needed
        if len(self.memory_cache) > self.max_memory_items:
            self._clean_memory_cache()
    
    def _clean_memory_cache(self):
        """Remove expired items from memory cache"""
        now = time.time()
        expired_keys = [k for k, v in self.memory_cache.items() if v['expiry'] <= now]
        for key in expired_keys:
            del self.memory_cache[key]
        
        # If still over limit, remove oldest items
        if len(self.memory_cache) > self.max_memory_items:
            oldest = sorted(self.memory_cache.items(), key=lambda x: x[1]['created'])[:self.max_memory_items//2]
            for key, _ in oldest:
                del self.memory_cache[key]
    
    def clear(self, key: Optional[str] = None):
        """Clear specific cache or all caches"""
        if key:
            # Clear specific key
            if key in self.memory_cache:
                del self.memory_cache[key]
            cache_file = self._get_cache_path(key)
            if os.path.exists(cache_file):
                os.remove(cache_file)
        else:
            # Clear all caches
            self.memory_cache.clear()
            for file in os.listdir(self.cache_dir):
                if file.endswith('.json'):
                    os.remove(os.path.join(self.cache_dir, file))
    
    def cached(self, expiry: Optional[int] = None):
        """
        Decorator for caching function results
        Usage:
            @cache_manager.cached(expiry=3600)
            def expensive_operation(param):
                ...
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                key = self._get_cache_key(func, *args, **kwargs)
                if cached_data := self.get(key):
                    return cached_data
                
                result = func(*args, **kwargs)
                self.set(key, result, expiry)
                return result
            return wrapper
        return decorator

# Global cache instance
cache_manager = CacheManager()

# Direct decorator for convenience
def cache_result(expiry: int = 3600):
    return cache_manager.cached(expiry)

# Example test usage
if __name__ == "__main__":
    @cache_result(expiry=10)
    def expensive_calculation(x):
        print("Performing expensive calculation...")
        time.sleep(2)
        return x * 2
    
    print(expensive_calculation(5))  # Calculates
    print(expensive_calculation(5))  # Uses cache
    time.sleep(11)
    print(expensive_calculation(5))  # Cache expired, recalculates

