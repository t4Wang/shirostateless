package com.routz.shiro.demo.realms;

import com.routz.shiro.demo.token.NothingToDoToken;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class NothingToDoRealm extends AuthorizingRealm {

    public NothingToDoRealm() {
        super();
        setName("NothingToDoRealm");
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof NothingToDoToken;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("什么也不做 授权验证");
        return null;
    }

    /**
     * 登录判断使用的
     * @param token 用户输入token
     * @return 用于与用户输入token比对的可靠账号信息
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
        return info;
    }

}
