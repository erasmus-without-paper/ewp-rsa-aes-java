package eu.erasmuswithoutpaper.rsaaes;

import java.util.LinkedHashMap;
import java.util.Map;

class LruCache<K, V> extends LinkedHashMap<K, V> {

  private static final long serialVersionUID = 1L;

  private final int maxEntries;

  LruCache(int maxEntries) {
    super((int) (maxEntries * 1.3f + 1), 0.75f, true);
    this.maxEntries = maxEntries;
  }

  @Override
  protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
    return this.size() > this.maxEntries;
  }
}
