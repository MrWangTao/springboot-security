package com.xt.legend.security.shiro.controller;

import com.xt.legend.security.shiro.bean.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Create User: wangtao
 * Create In 2019-07-09 16:50
 * Description:
 **/
@RestController
public class LoginController {

    @PostMapping("/login")
    public String login(@RequestBody User user) {
        Subject subject = SecurityUtils.getSubject();
        String password = user.getPassword();
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(), password);
        String result;
        try {
            //shiro帮我们匹配密码什么的，我们只需要把东西传给它，它会根据我们在UserRealm里认证方法设置的来验证
            subject.login(token);
            result = "OK";
        } catch (UnknownAccountException e) {
            //账号不存在和下面密码错误一般都合并为一个账号或密码错误，这样可以增加暴力破解难度
            e.printStackTrace();
            result = "账号不存在";
        } catch (DisabledAccountException e) {
            e.printStackTrace();
            result = "账号未启用！";
        } catch (IncorrectCredentialsException e) {
            e.printStackTrace();
            result = "密码错误！";
        } catch (Throwable e) {
            e.printStackTrace();
            result = "未知错误！";
        }
        return result;
    }

    /**
     *
     * @return
     */
    @GetMapping("/index")
    public String index() {
        return "index";
    }

    /**
     * 登出
     *
     * @return
     */
    @GetMapping("/logout")
    public String logout() {
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        return "logout success";
    }


    /*public static void main(String[] args) {
        System.out.println(test());
    }

    private static int test() {
        int i = 111;
        try {
            return i;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.out.println("finally");
            i = 222;
        }
        return i;
    }*/

}
