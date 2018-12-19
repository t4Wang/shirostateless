package com.routz.shiro.demo.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 在登录时传入对象，访问权限过滤器判断控制访问
 */
public class NothingToDoToken implements AuthenticationToken {

    private String userId;
    private String password;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public Object getPrincipal() {
        return userId;
    }

    @Override
    public Object getCredentials() {
        return password;
    }
}
