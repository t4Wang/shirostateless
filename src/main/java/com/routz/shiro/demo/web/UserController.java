package com.routz.shiro.demo.web;

import com.routz.shiro.demo.service.UserService;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class UserController {

    @RequestMapping("/unnauth")
    public String unnauth() {
        return "不需要访问权限的请求";
    }

    @RequestMapping("/nauth")
    @RequiresPermissions("user:book")
    public String nauth(String userId) {
        return "需要访问权限的请求";
    }

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
    public UserController(UserService userService) {
        this.userService = userService;
    }
    private UserService userService;
}
