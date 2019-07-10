package com.xt.legend.security.shiro.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.DelegatingSession;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.session.mgt.WebSessionKey;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.util.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;

/**
 * Create User: wangtao
 * Create In 2019-07-09 18:37
 * Description:
 **/
@Slf4j
public class LegendWebHeaderSessionManager extends DefaultSessionManager implements WebSessionManager {

    private final String X_AUTH_TOKEN = "x-auth-token";

    /**
     * Header入口
     * 每次请求都会来进行验证
     *
     * @param session
     * @param context
     */
    @Override
    protected void onStart(Session session, SessionContext context) {
        super.onStart(session, context);
        // 是不是http请求
        if (!WebUtils.isHttp(context)) {
            log.debug("SessionContext argument is not HTTP compatible or does not have an HTTP request/response pair. No session ID cookie will be set.");
        } else {
            HttpServletRequest request = WebUtils.getHttpRequest(context);
            HttpServletResponse response = WebUtils.getHttpResponse(context);
            Serializable sessionId = session.getId();
            this.storeSessionId(sessionId, request, response);
            // 移除原有的相关sessionId，声明相关Session是新的
            request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
        }
    }

    /**
     * 将sessionId存放到请求头Header中
     * 没有sessionid时 会产生sessionid 并放入 response header中
     *
     * @param sessionId
     * @param requst
     * @param response
     */
    private void storeSessionId(Serializable sessionId, HttpServletRequest requst, HttpServletResponse response) {
        if (sessionId == null) {
            String msg = "sessionId cannot be null when persisting for subsequent requests.";
            throw new IllegalArgumentException(msg);
        } else {
            String idString = sessionId.toString();
            response.setHeader(this.X_AUTH_TOKEN, idString);
            log.info("Set session ID header for session with id {}", idString);
        }
    }

    /**
     *
     *
     * @param sessionKey
     * @return
     */
    @Override
    protected Serializable getSessionId(SessionKey sessionKey) {
        Serializable id = super.getSessionId(sessionKey);
        if (id == null && WebUtils.isWeb(sessionKey)) {
            ServletRequest request = WebUtils.getRequest(sessionKey);
            ServletResponse response = WebUtils.getResponse(sessionKey);
            id = getSessionId(request, response);
        }
        return id;
    }

    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
        return this.getReferencedSessionId(request, response);
    }

    //获取sessionid
    private Serializable getReferencedSessionId(ServletRequest request, ServletResponse response) {
        String id = this.getSessionIdHeaderValue(request, response);

        //DefaultWebSessionManager 中代码 直接copy过来
        if (id != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE, "header");
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
        }
        //不会把sessionid放在URL后
        request.setAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED, Boolean.FALSE);
        return id;
    }

    private String getSessionIdHeaderValue(ServletRequest request, ServletResponse response) {
        if (!(request instanceof HttpServletRequest)) {
            log.debug("Current request is not an HttpServletRequest - cannot get session ID cookie.  Returning null.");
            return null;
        } else {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            // 在request 中 读取 x-auth-token 信息  作为 sessionId
            String sessionId = httpRequest.getHeader(this.X_AUTH_TOKEN);
            // 每次读取之后 都把当前的 sessionId 放入 response 中
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            if (!StringUtils.isEmpty(sessionId)) {
                httpResponse.setHeader(this.X_AUTH_TOKEN, sessionId);
                log.info("Current session ID is {}", sessionId);
            }
            return sessionId;
        }
    }

    @Override
    protected void onStop(Session session, SessionKey key) {
        super.onStop(session, key);
        if (WebUtils.isHttp(key)) {
            HttpServletRequest request = WebUtils.getHttpRequest(key);
            HttpServletResponse response = WebUtils.getHttpResponse(key);
            log.debug("Session has been stopped (subject logout or explicit stop).  Removing session ID cookie.");
            removeSessionIdHeader(request, response);
        } else {
            log.debug("SessionKey argument is not HTTP compatible or does not have an HTTP request/response " +
                    "pair. Session ID cookie will not be removed due to stopped session.");
        }
    }

    // 创建session
    protected Session createExposedSession(Session session, SessionContext context) {
        if (!WebUtils.isWeb(context)) {
            return super.createExposedSession(session, context);
        } else {
            ServletRequest request = WebUtils.getRequest(context);
            ServletResponse response = WebUtils.getResponse(context);
            SessionKey key = new WebSessionKey(session.getId(), request, response);
            return new DelegatingSession(this, key);
        }
    }

    protected Session createExposedSession(Session session, SessionKey key) {
        if (!WebUtils.isWeb(key)) {
            return super.createExposedSession(session, key);
        }

        ServletRequest request = WebUtils.getRequest(key);
        ServletResponse response = WebUtils.getResponse(key);
        SessionKey sessionKey = new WebSessionKey(session.getId(), request, response);
        return new DelegatingSession(this, sessionKey);
    }

    private void removeSessionIdHeader(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader(this.X_AUTH_TOKEN, "deleteMe");
    }

    protected void onExpiration(Session s, ExpiredSessionException ese, SessionKey key) {
        super.onExpiration(s, ese, key);
        this.onInvalidation(key);
    }

    protected void onInvalidation(Session session, InvalidSessionException ise, SessionKey key) {
        super.onInvalidation(session, ise, key);
        this.onInvalidation(key);
    }

    private void onInvalidation(SessionKey key) {
        ServletRequest request = WebUtils.getRequest(key);
        if (request != null) {
            request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID);
        }

        if (WebUtils.isHttp(key)) {
            log.debug("Referenced session was invalid.  Removing session ID header.");
            this.removeSessionIdHeader(WebUtils.getHttpRequest(key), WebUtils.getHttpResponse(key));
        } else {
            log.debug("SessionKey argument is not HTTP compatible or does not have an HTTP request/response pair. Session ID cookie will not be removed due to invalidated session.");
        }

    }



    @Override
    public boolean isServletContainerSessions() {
        return false;
    }

}
