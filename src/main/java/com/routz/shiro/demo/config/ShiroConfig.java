package com.routz.shiro.demo.config;

import com.routz.shiro.demo.realms.NothingToDoRealm;
import com.routz.shiro.demo.realms.TokenRealm;
import com.routz.shiro.demo.realms.UsernamePasswordRealm;
import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.*;

/**
 */
@Configuration
public class ShiroConfig {

	@Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    public DefaultAdvisorAutoProxyCreator getDefaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator daap = new DefaultAdvisorAutoProxyCreator();
        daap.setProxyTargetClass(true);
        return daap;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilter(DefaultWebSecurityManager securityManager) {

        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        Map<String, Filter> filters = new HashMap();
        filters.put("statelessAuthc", statelessAuthcFilter());
        shiroFilterFactoryBean.setFilters(filters);

        shiroFilterFactoryBean.setLoginUrl("/login/sessionlogin");
        // 登录成功后要跳转的连接
        shiroFilterFactoryBean.setSuccessUrl("/test/unnauth");
        shiroFilterFactoryBean.setUnauthorizedUrl("/error");

        // 拦截器
        Map<String,String> filterChainDefinitionMap = new LinkedHashMap<>();

        //我做的是无状态的，这里的东西实际上是用不到的，仅供参考
        //配置退出 过滤器,其中的具体的退出代码Shiro已经替我们实现了
        filterChainDefinitionMap.put("/login/logout", "logout");
        filterChainDefinitionMap.put("/css/**","anon");
        filterChainDefinitionMap.put("/js/**","anon");
        filterChainDefinitionMap.put("/img/**","anon");

        // 登录请求需要放行
        filterChainDefinitionMap.put("/login/sessionlogin", "anon");
        filterChainDefinitionMap.put("/login/statelesslogin", "anon");
        // 将想要纳入shiro statelessAuthc管理的放入map
        filterChainDefinitionMap.put("/test/*", "statelessAuthc");
        filterChainDefinitionMap.put("/**", "anon");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
//        shiroFilterFactoryBean.setFilterChainDefinitions("/user/*=statelessAuthc");
        return shiroFilterFactoryBean;
    }

    @Bean
    public DefaultWebSecurityManager defaultWebSecurityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();

        //设置realm.
        securityManager.setAuthenticator(modularRealmAuthenticator());
        // 设置了sessionManager之后，httpSession默认由shiro session代理 各种session获取不到
//        securityManager.setSessionManager(sessionManager());
        // 多个realm
        // 添加到securityManager的管理之下
        List<Realm> realms=new ArrayList<>();
        realms.add(tokenRealm());
        realms.add(usernamePasswordRealm());
        realms.add(nothingToDoRealm());
        securityManager.setRealms(realms);

        return securityManager;
    }

    /**
     * 让spring管理的realm Bean
     */
    @Bean
    public TokenRealm tokenRealm() {
        TokenRealm tokenRealm = new TokenRealm();
        tokenRealm.setCachingEnabled(false);
        return tokenRealm;
    }

    @Bean
    public UsernamePasswordRealm usernamePasswordRealm() {
        UsernamePasswordRealm usernamePasswordRealm = new UsernamePasswordRealm();
        return usernamePasswordRealm;
    }

    @Bean
    public NothingToDoRealm nothingToDoRealm() {
	    NothingToDoRealm nothingToDoRealm = new NothingToDoRealm();
	    return nothingToDoRealm;
    }

    /**
     * 如果有多个realm，会使用这个来选择策略，进行调度，判断realm的权限校验是否通过
     * @return
     */
    @Bean
    public ModularRealmAuthenticator modularRealmAuthenticator(){
        ModularRealmAuthenticator modularRealmAuthenticator=new ModularRealmAuthenticator();
        // 只要有一个realm成功，就放行，并且不继续判断realm
        modularRealmAuthenticator.setAuthenticationStrategy(new FirstSuccessfulStrategy());
        return modularRealmAuthenticator;
    }

    @Bean
    public StatelessAuthcFilter statelessAuthcFilter() {
	    return new StatelessAuthcFilter();
    }
}
