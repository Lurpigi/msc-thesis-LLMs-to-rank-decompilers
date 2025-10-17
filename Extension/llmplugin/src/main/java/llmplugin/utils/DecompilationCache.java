package llmplugin.utils;

import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class DecompilationCache {
    private static class CacheEntry {
        String enhancedCode;
        //long timestamp;
        String styleUsed;
        
        CacheEntry(String code, String style) {
            this.enhancedCode = code;
            this.styleUsed = style;
            //this.timestamp = System.currentTimeMillis();
        }
    }
    
    private final ConcurrentHashMap<String, CacheEntry> cache;
    //private final long maxCacheSize = 1000; // Maximum cache entries
    //private final long cacheTimeoutMs = 30 * 60 * 1000; // 30 minutes
    
    public DecompilationCache() {
        this.cache = new ConcurrentHashMap<>();
    }
    
    public synchronized void put(String functionKey, String code, String style) {
        // Evict oldest entries if cache is too large
       /* if (cache.size() >= maxCacheSize) {
            evictOldEntries();
        }*/
        cache.put(functionKey, new CacheEntry(code, style));
    }
    
    public synchronized String get(String functionKey) {
        CacheEntry entry = cache.get(functionKey);
        if (entry == null) {
            return null;
        }
        
        /* Check if entry has expired
        if (System.currentTimeMillis() - entry.timestamp > cacheTimeoutMs) {
            cache.remove(functionKey);
            return null;
        }*/
        
        return entry.enhancedCode;
    }
    
    public synchronized boolean contains(String functionKey) {
        return get(functionKey) != null;
    }
    
    public synchronized void clear() {
        cache.clear();
    }
    
    /*private void evictOldEntries() {
        if (cache.size() < maxCacheSize * 0.8) return;
        
        // Simple eviction: remove 20% of oldest entries
        cache.entrySet().stream()
            .sorted((e1, e2) -> Long.compare(e1.getValue().timestamp, e2.getValue().timestamp))
            .limit(maxCacheSize / 5)
            .forEach(entry -> cache.remove(entry.getKey()));
    }*/
    
    
    public static String createFunctionKey(Program program, Function function) {
        return program.getName() + "::" + function.getEntryPoint().toString() + "::" + function.getName();
    }
}
