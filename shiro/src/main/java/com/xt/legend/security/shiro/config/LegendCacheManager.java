package com.xt.legend.security.shiro.config;

import org.apache.shiro.cache.AbstractCacheManager;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;

/**
 * Create User: wangtao
 * Create In 2019-07-10 11:28
 * Description:
 **/
public class LegendCacheManager extends AbstractCacheManager {

    @Override
    protected Cache createCache(String s) throws CacheException {
        return null;
    }
}
