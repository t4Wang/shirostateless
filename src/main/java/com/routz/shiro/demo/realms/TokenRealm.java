package com.routz.shiro.demo.realms;

import com.routz.shiro.demo.service.UserService;
import com.routz.shiro.demo.token.StatelessToken;
import com.routz.shiro.demo.util.HmacSHA256Utils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 无状态请求一个需要权限的url过程：
 * 1. StatelessAuthcFilter isAccessAllowed
 * 2. StatelessAuthcFilter onAccessDenied
 * 3. StatelessRealm doGetAuthenticationInfo 登录
 * 4. StatelessRealm doGetAuthorizationInfo 授权
 * （授权未通过）5.AuthRealm doGetAuthorizationInfo
 */
public class TokenRealm extends AuthorizingRealm {
    public TokenRealm() {
        super();
        setName("StatelessRealm");
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        //仅支持StatelessToken类型的Token
        return token instanceof StatelessToken;
    }
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 根据用户名查找角色
        System.out.println("无状态 授权验证");
        // 获取当前登录输入的用户名，等价于(String) principalCollection.fromRealm(getName()).iterator().next();
        String userId = (String) super.getAvailablePrincipal(principals);

        // 权限信息对象info，用来存放查出的用户的所有角色和权限
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 用户的角色
        String role = userService.role(userId);
        // 用户的权限
        String permission = userService.auth(userId);
        info.addRole(role);
        info.addStringPermission(permission);
        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        StatelessToken statelessToken = (StatelessToken) token;
        String userId = statelessToken.getUsername();
        String key = getKey(userId); //根据用户名获取密钥（和客户端的一样）
        //在服务器端生成客户端参数消息摘要
        String serverDigest = HmacSHA256Utils.digest(key, statelessToken.getParams());
        System.out.println(statelessToken.getToken());
        //然后进行客户端消息摘要和服务器端消息摘要的匹配
        return new SimpleAuthenticationInfo(
                userId,
                serverDigest,
                getName());
    }

    private String getKey(String username) {
        String hashedPasswordBase64 = new Sha256Hash(username).toBase64();
        return hashedPasswordBase64;
    }

    @Autowired
    private UserService userService;
}
