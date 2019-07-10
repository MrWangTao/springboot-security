package com.xt.legend.security.shiro.bean;

import lombok.Builder;
import lombok.Data;

/**
 * Create User: wangtao
 * Create In 2019-07-09 16:27
 * Description:
 **/
@Data
@Builder
public class User {

    private String username;
    private String password;
    private String salt;

}
