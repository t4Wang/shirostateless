package com.routz.shiro.demo.web;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test2")
public class Test2Controller {

    /**
     * 不需要权限，也不需要登录
     */
    @RequestMapping("/unnauth")
    public String unnauth() {
        return "请求地址不在shiro过滤器过滤列表里的请求";
    }
}
