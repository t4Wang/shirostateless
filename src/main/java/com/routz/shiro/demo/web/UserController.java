package com.routz.shiro.demo.web;

import org.apache.shiro.authz.annotation.RequiresPermissions;
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

    @RequestMapping("/statelogin")
    public String login(String userId, String password) {
        return "登录成功";
    }

}
