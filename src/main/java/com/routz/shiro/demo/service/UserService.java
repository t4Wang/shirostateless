package com.routz.shiro.demo.service;

import com.routz.shiro.demo.domain.User;
import com.routz.shiro.demo.util.Constants;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service("userService")
public class UserService {

    public String auth(String userId) {
        if ("123".equals(userId))
            return "book";
        return null;
    }

    public String role(String userId) {
        if ("123".equals(userId))
            return "user";
        return null;
    }

    public User user(String userId) {
        User user = new User();
        user.setPassword("IifLa4pswnevQKaQpHA+9x2HzJzU39Boe2AwdK0AJZ8=");
        user.setUserId("123");
        user.setSalt("ieQF0BSjAEb0nX3bcAx35w==");
        if ("123".equals(userId)) return user;
        return null;
    }

    /**
     * 账号密码登录
     * @param userId
     * @param password
     */
    public void login(String userId, String password) {
        Subject currentUser = SecurityUtils.getSubject();

        if (!currentUser.isAuthenticated()) {
            // 根据手机号从数据库获取用户
            // 模拟从数据库取用户数据
            User udb = this.user(userId);
            if (udb == null) throw new AuthorizationException("账户不存在");

            UsernamePasswordToken token = new UsernamePasswordToken(udb.getUserId(), password, udb.getSalt());
            token.setRememberMe(true);

            try {
                currentUser.login(token);

                // 更新手机盐值
                // 将盐插入数据库
                // 根据密码 盐值生成新加密密码
                // 更新登录时间和ip
            } catch (UnknownAccountException uae) {
                throw new AuthorizationException("There is no user with username of " + token.getPrincipal());
            } catch (IncorrectCredentialsException ice) {
                throw new AuthorizationException("Password for account " + token.getPrincipal() + " was incorrect!");
            } catch (LockedAccountException lae) {
                throw new AuthorizationException("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            } catch (AuthenticationException ae) {
                // ... catch more exceptions here (maybe custom ones specific to your application?
                //unexpected condition?  error?
                ae.printStackTrace();
                throw new AuthorizationException("未知权限校验错误");
            }
        }
    }
}
