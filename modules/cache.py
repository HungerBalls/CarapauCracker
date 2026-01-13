# cache.py — CarapauCracker Result Cache
"""
Cache system for scan results to avoid redundant operations
"""
import json
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from modules.config import OUTPUTS_DIR
from modules.utils import log
from colorama import Fore

CACHE_DIR = OUTPUTS_DIR / ".cache"
CACHE_EXPIRY_HOURS = 24  # Cache expires after 24 hours


def get_cache_key(target: str, operation: str, params: Dict[str, Any] = None) -> str:
    """
    Generate cache key from target and operation
    
    Args:
        target: Target IP or hostname
        operation: Operation type (e.g., 'nmap_quick', 'whois')
        params: Additional parameters
    
    Returns:
        Cache key (hash)
    """
    key_string = f"{target}:{operation}"
    if params:
        key_string += f":{json.dumps(params, sort_keys=True)}"
    
    return hashlib.md5(key_string.encode()).hexdigest()


def get_cache_path(cache_key: str) -> Path:
    """Get path to cache file"""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{cache_key}.json"


def is_cache_valid(cache_path: Path) -> bool:
    """
    Check if cache file is still valid (not expired)
    
    Args:
        cache_path: Path to cache file
    
    Returns:
        True if cache is valid, False otherwise
    """
    if not cache_path.exists():
        return False
    
    try:
        # Check file age
        file_time = datetime.fromtimestamp(cache_path.stat().st_mtime)
        age = datetime.now() - file_time
        
        if age > timedelta(hours=CACHE_EXPIRY_HOURS):
            return False
        
        # Check if file is readable JSON
        with open(cache_path, 'r') as f:
            json.load(f)
        
        return True
    except Exception:
        return False


def get_cached_result(target: str, operation: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
    """
    Get cached result if available and valid
    
    Args:
        target: Target IP or hostname
        operation: Operation type
        params: Operation parameters
    
    Returns:
        Cached result or None
    """
    cache_key = get_cache_key(target, operation, params)
    cache_path = get_cache_path(cache_key)
    
    if not is_cache_valid(cache_path):
        return None
    
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            log(Fore.CYAN + f"[💾] Using cached result for {operation} on {target}", None)
            return data
    except Exception as e:
        log(Fore.YELLOW + f"[⚠] Error reading cache: {e}", None)
        return None


def save_result_to_cache(target: str, operation: str, result: Dict[str, Any], params: Dict[str, Any] = None):
    """
    Save result to cache
    
    Args:
        target: Target IP or hostname
        operation: Operation type
        result: Result data to cache
        params: Operation parameters
    """
    cache_key = get_cache_key(target, operation, params)
    cache_path = get_cache_path(cache_key)
    
    try:
        cache_data = {
            "target": target,
            "operation": operation,
            "params": params or {},
            "result": result,
            "timestamp": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=CACHE_EXPIRY_HOURS)).isoformat()
        }
        
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)
        
        log(Fore.GREEN + f"[💾] Result cached for {operation} on {target}", None)
    except Exception as e:
        log(Fore.YELLOW + f"[⚠] Error saving to cache: {e}", None)


def clear_cache(older_than_hours: Optional[int] = None):
    """
    Clear cache files
    
    Args:
        older_than_hours: Only clear files older than this (None = clear all)
    """
    if not CACHE_DIR.exists():
        return
    
    cleared = 0
    now = datetime.now()
    
    for cache_file in CACHE_DIR.glob("*.json"):
        try:
            if older_than_hours:
                file_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
                if (now - file_time) < timedelta(hours=older_than_hours):
                    continue
            
            cache_file.unlink()
            cleared += 1
        except Exception:
            pass
    
    log(Fore.CYAN + f"[🗑️] Cleared {cleared} cache files", None)


def get_cache_stats() -> Dict[str, int]:
    """Get cache statistics"""
    if not CACHE_DIR.exists():
        return {"total": 0, "valid": 0, "expired": 0}
    
    total = 0
    valid = 0
    expired = 0
    
    for cache_file in CACHE_DIR.glob("*.json"):
        total += 1
        if is_cache_valid(cache_file):
            valid += 1
        else:
            expired += 1
    
    return {
        "total": total,
        "valid": valid,
        "expired": expired
    }
