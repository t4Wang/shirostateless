package com.routz.shiro.demo.web;

import com.routz.shiro.demo.service.UserService;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    /**
     * 不需要权限，也不需要登录
     */
    @RequestMapping("/unnauth")
    public String unnauth() {
        return "不需要访问权限也不需要登录的请求";
    }
}
