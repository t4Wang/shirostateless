package com.routz.shiro.demo.realms;

import com.routz.shiro.demo.domain.User;
import com.routz.shiro.demo.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Base64;

/**
 *
 * TODO 密码处理： 判断手机登录还是账号登录，
 * 如果是手机登录，登陆成功时手机号+盐值哈希存入数据库，每次登录后更换盐值和加密数据
 * 电脑登录，账号密码登录，明文密码加盐比对，每次登录后更换盐值和加密密码
 *
 * 手机登录，如果shiro判断它没有登录的话，根据传过来的手机号和token进行判断登录
 *
 * 做一个拦截器，如果过来带token，就放入shiro session中确认已登录
 *
 * TODO principals 填写用户id，这样不用区分是用户名密码登录还是手机验证码登录
 *
 * @author wrzhxy@qq.com
 * @date 2017年12月28日
 */
//@Component
public class UsernamePasswordRealm extends AuthorizingRealm {

    public UsernamePasswordRealm() {
        setName("UsernamePasswordRealm");		//This name must match the name in the User class's getPrincipals() method
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("SHA-256");
        hashedCredentialsMatcher.setHashIterations(1024);
        hashedCredentialsMatcher.setStoredCredentialsHexEncoded(false);	// 这一行决定hex还是base64
        setCredentialsMatcher(hashedCredentialsMatcher);
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    /**
     * 授权验证
     *
     * 验证的用户信息只是登录时从数据库取出后的对象。
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("用户名密码 授权验证");
        //获取当前登录输入的用户名，等价于(String) principalCollection.fromRealm(getName()).iterator().next();
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

    /**
     * 登录验证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("登录验证");
        // UsernamePasswordToken对象用来存放提交的登录信息
        UsernamePasswordToken upt = (UsernamePasswordToken) token;
        // 使用user_id

        // 查出是否有此用户
        String username_upt = upt.getUsername();
        User user = userService.user(username_upt);

        if (user != null) {
            // 若存在，将此用户存放到登录认证info中，无需自己做密码对比，Shiro会为我们进行密码对比校验
            // 第三个插入盐
            // 将Base64字符串解码转换为byte数组
            byte[] decode = Base64.getDecoder().decode(user.getSalt());
            ByteSource bytes = ByteSource.Util.bytes(decode);
            SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(user.getUserId(), user.getPassword(), bytes, getName());
            System.out.println(info);
            return info;
        }
        return null;
    }

    @Autowired
    private UserService userService;
}
