package com.xt.legend.security.shiro.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Create User: wangtao
 * Create In 2019-07-10 11:33
 * Description: shiro filter 配置类
 **/
@Component
//@PropertySource("classpath:application.yml")
// 注意： @ConfigurationProperties 中prefix路径不能用大写的字母，否则会报错Prefix must be in canonical form
@ConfigurationProperties(prefix = "com.xt.legend.filters")
@Data
public class ShiroFilterChainConfig {

    private String login;
    private String logout;
    private List<String> anon;
    private List<String> authc;

}
