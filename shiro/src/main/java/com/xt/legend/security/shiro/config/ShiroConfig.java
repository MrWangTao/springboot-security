package com.xt.legend.security.shiro.config;

import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <p>SecurityManager is the core of shiro</p>
 *
 * Create User: wangtao
 * Create In 2019-07-09 15:08
 * Description: shiro's configuration
 **/
@Configuration
public class ShiroConfig {

    /**
     * SecurityManager其中两种实现方式
     * <p>1. DefaultWebSecurityManager：web工程使用</p>
     * <p>2. DefaultSecurityManager：非web工程使用</p>
     * 注意：如果在web工程中使用非web的安全管理器，那么安全管理器将不起作用
     *
     * @return
     */
    @Bean
    public DefaultWebSecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(legendShiroRealm());
        securityManager.setSessionManager(legendWebSessionManager());
        return securityManager;
    }

    /**
     * <p>设置密码的加密方式，凭证匹配器</p>
     *
     * @return
     */
    @Bean
    public Realm legendShiroRealm() {
        LegendShiroRealm realm = new LegendShiroRealm();
        realm.setCredentialsMatcher(credentialsMatcher());
        return realm;
    }

    /**
     * 凭证匹配器
     * <p>设置加密方式</p>
     * <p>设置加密次数</p>
     * <p>默认情况下加密后转换成二进制</p>
     *
     * @return
     */
    @Bean
    public CredentialsMatcher credentialsMatcher() {
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("md5");
        hashedCredentialsMatcher.setHashIterations(2);
        return hashedCredentialsMatcher;
    }

    /**
     * 过滤器链
     * <p>用户设置过滤器中各个环节需要添加的过滤器链</p>
     *
     * @param securityManager
     * @return
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean factory = new ShiroFilterFactoryBean();
        factory.setSecurityManager(securityManager);
        factory.setLoginUrl("/login");
        // 过滤器链
        // 注意此处使用的是LinkedHashMap，是有顺序的，shiro会按从上到下的顺序匹配验证，匹配了就不再继续验证
        // 所以上面的url要苛刻，宽松的url要放在下面，尤其是"/**"要放到最下面，如果放前面的话其后的验证规则就没作用了
       /* Map<String, String> chainMap = new LinkedHashMap<>();
        chainMap.put("/static/**", "anon");
        chainMap.put("/login", "anon");
        chainMap.put("/**", "authc");*/
        factory.setFilterChainDefinitionMap(chainMap());
        return factory;
    }

    @Autowired
    private ShiroFilterChainConfig shiroFilterChainConfig;

    private Map<String, String> chainMap() {
        LinkedHashMap<String, String> chainMap = new LinkedHashMap<>();
        shiroFilterChainConfig.getAnon().forEach(s -> chainMap.put(s, "anon"));
        shiroFilterChainConfig.getAuthc().forEach(s -> chainMap.put(s, "authc"));
        return chainMap;
    }

    /**
     * 自定义WebSessionManager
     *
     * 系统默认为DefaultWebSessionManager
     *
     * @return
     */
    @Bean
    public LegendWebHeaderSessionManager legendWebSessionManager() {
        LegendWebHeaderSessionManager sessionManager = new LegendWebHeaderSessionManager();
        // 自定义SessionDAO
        // sessionManager.setSessionDAO(legendSessionDAO());
        // 自定义cache
        // sessionManager.setCacheManager(legendCacheManager());
        return sessionManager;
    }

    /**
     * 自定义SessionDAO
     *
     * @return
     */
    @Bean
    public LegendSessionDAO legendSessionDAO() {
        return new LegendSessionDAO();
    }

    @Bean
    public LegendCacheManager legendCacheManager() {
        return new LegendCacheManager();
    }



}
