shrio登录鉴权步骤

手机登录

1. 访问controller登录

2. controller根据传过来的参数判断身份

    短信验证码登录，只要验证码输入成功，即判断成功登录
    构造 NothingToDoToken，调用subject.login(NothingToDoToken)

3. NothingToDoRealm处理登录授权请求

    ModularRealmAuthenticator 遍历在 securityManager 注册的所有 realm ,调用 support 判断 Token 是否是支持的类型
    NothingToDoRealm 支持
    调用 NothingToDoRealm 的 doGetAuthenticationInfo 方法，将token传进info直接判断登录成功

4. controller将接下来需要的密钥返回用户

电脑登录

1. 访问controller登录

2. controller根据传过来的参数判断身份

    账号密码登录
    构造UsernamePasswordToken,调用subject.login(UsernamePasswordToken)

3. UsernamePasswordRealm处理登录授权请求

    ModularRealmAuthenticator 遍历在 securityManager 注册的所有 realm ,调用 support 判断 Token 是否是支持的类型
    UsernamePasswordRealm 支持
    调用 UsernamePasswordRealm 的 doGetAuthenticationInfo 方法
    数据库查询账号密码，封装进info，与token比对




鉴权操作：一个成功剩下的就不执行了

无状态授权

1. statelessAuthcFilter 判断访问

    进入 statelessAuthcFilter isAccessAllowed 直接判断false 不允许访问
    进入 statelessAuthcFilter onAccessDenied 封装 statelessToken 调用 subject.login(statelessToken)鉴权
    // AccessControlFilter PathMatchingFilter AdviceFilter doFilterInternal

2. 进入 TokenRealm

    ModularRealmAuthenticator 遍历在 securityManager 注册的所有 realm ,调用 support 判断 Token 是否是支持的类型
    TokenRealm支持
    进入 TokenRealm doGetAuthenticationInfo 通过hmac加密生成info，
    进入 AuthenticatingRealm getAuthenticationInfo 判断info token 是否相等

        login失败：直接返回失败403

3. 授权

    statelessAuthcFilter 鉴权通过，返回true
    进入 TokenRealm doGetAuthorizationInfo 通过数据库查询用户id，授予用户权限
    // isPermitted 
    判断用户权限，进入controller方法体

        授权失败
    
    



