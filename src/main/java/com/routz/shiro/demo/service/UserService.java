package com.routz.shiro.demo.service;

import com.routz.shiro.demo.domain.User;
import org.springframework.stereotype.Service;

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
}
