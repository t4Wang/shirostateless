package com.routz.shiro.demo.token;

import org.apache.shiro.authc.AuthenticationToken;

import java.util.Map;

public class StatelessToken implements AuthenticationToken {

    private String preKey;
    private Map<String, ?> params;
    private String signature;

    public StatelessToken(String preKey, Map<String, ?> params, String signature) {
        this.preKey = preKey;
        this.params = params;
        this.signature = signature;
    }

    public String getPreKey() {
        return preKey;
    }

    public void setPreKey(String preKey) {
        this.preKey = preKey;
    }

    public  Map<String, ?> getParams() {
        return params;
    }

    public void setParams( Map<String, ?> params) {
        this.params = params;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    @Override
    public Object getPrincipal() {
        return preKey;
    }

    @Override
    public Object getCredentials() {
        return signature;
    }
}
