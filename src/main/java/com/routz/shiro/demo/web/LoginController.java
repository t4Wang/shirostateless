package com.routz.shiro.demo.web;

import com.routz.shiro.demo.service.UserService;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
public class LoginController {
    @RequestMapping("/sessionlogin")
    public String sessionlogin(String userId, String password) {
        userService.login(userId, password);
        return "session登录成功";
    }

    @RequestMapping("/statelesslogin")
    public String statelesslogin(String userId) {
        return "无状态登录成功";
    }

    @Autowired
    public LoginController(UserService userService) {
        this.userService = userService;
    }
    private UserService userService;
}
