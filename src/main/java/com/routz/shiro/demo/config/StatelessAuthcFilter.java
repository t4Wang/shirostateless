package com.routz.shiro.demo.config;

import com.routz.shiro.demo.token.StatelessToken;
import com.routz.shiro.demo.util.Constants;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.springframework.util.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class StatelessAuthcFilter extends AccessControlFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        // session登录
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        // 登录状态判断
        Subject subject = getSubject(request, response);
        if (subject.isAuthenticated()) return true;
        //1、客户端生成的消息摘要
        String signature = request.getParameter(Constants.PARAM_SIGNATURE);
        //2、客户端传入的userId
        String userId = request.getParameter(Constants.PARAM_USER);

        if (!StringUtils.hasText(signature) || !StringUtils.hasText(userId)) {
            onLoginFail(response);
            return false;
        }

        //3、客户端请求的参数列表
        Map<String, String[]> params = new HashMap<>(request.getParameterMap());
        params.remove(Constants.PARAM_SIGNATURE);

        // 生成无状态Token
        StatelessToken statelessToken = new StatelessToken(userId, params, signature);
        // 如果不执行登录会判断没有授权，直接退出

        //5、委托给Realm进行登录
        try {
            subject.login(statelessToken);
        } catch (Exception e) {
            e.printStackTrace();
            // AuthenticationException
            onLoginFail(response);
            return false;
        }
        return true;

    }

    // 登录失败 写出信息
    private void onLoginFail(ServletResponse response) throws IOException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        httpResponse.getWriter().write("失败");
    }
}

