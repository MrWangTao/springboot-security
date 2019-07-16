package com.xt.legend.security.shiro.config;

import com.xt.legend.security.shiro.bean.User;
import com.xt.legend.security.shiro.util.CommonUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.Objects;

/**
 * Create User: wangtao
 * Create In 2019-07-09 14:25
 * Description: 继承AuthoringRealm
 **/
public class LegendShiroRealm extends AuthorizingRealm {

    /**
     * 授权
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        // 这里获取的内容是在认证过程中返回的SimpleAuthenticationInfo中的第一个参数
        String username = (String) principalCollection.getPrimaryPrincipal();
        // 根据参数获取访问权限
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.addStringPermission("test");
        return simpleAuthorizationInfo;
    }

    /**
     * 认证
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String username =  (String) authenticationToken.getPrincipal();
        //处理session，实现同一时间只能在一个地方登录
        /*DefaultWebSecurityManager securityManager = (DefaultWebSecurityManager) SecurityUtils.getSecurityManager();
        DefaultWebSessionManager sessionManager = (DefaultWebSessionManager)securityManager.getSessionManager();
        Collection<Session> sessions = sessionManager.getSessionDAO().getActiveSessions();//获取当前已登录的用户session列表
        for(Session session:sessions){
            //清除该用户以前登录时保存的session
            if(username.equals(String.valueOf(session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY)))) {
                sessionManager.getSessionDAO().delete(session);
            }
        }*/
        char[] credentials = (char[]) authenticationToken.getCredentials();
        if (StringUtils.isEmpty(username)) {
            throw new UnknownAccountException("unknown account");
        }
        // 从数据库进行查询对应的用户信息
        User user = getUserByUsername(username);
        if (Objects.isNull(user)) {
            throw new UnknownAccountException("unknown account");
        }
        /*if (!credentials.equals(user.getPassword())) {
            throw new IncorrectCredentialsException("account or password error");
        }*/
        // getName() 是当前类的名字
        return new SimpleAuthenticationInfo(username, user.getPassword(), ByteSource.Util.bytes(user.getSalt().getBytes()), getName());
    }

    private User getUserByUsername(String username) {
        String password = CommonUtils.securePassword("123456");
        if ("tower".equals(username)) {
            return User.builder().username("tower").password(password).salt("bear").build();
        }
        return null;
    }

}

