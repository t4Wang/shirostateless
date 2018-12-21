package com.routz.shiro.demo.util;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 参考开涛的加密类
 * <p>User: Zhang Kaitao
 * <p>Date: 14-2-26
 * <p>Version: 1.0
 */
public class HmacSHA256Utils {

    // 把key和这个长字符串使用HmacSHA256算法加密
    public static String digest(String key, String content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] secretByte = key.getBytes("utf-8");
            byte[] dataBytes = content.getBytes("utf-8");

            SecretKey secret = new SecretKeySpec(secretByte, "HMACSHA256");
            mac.init(secret);

            byte[] doFinal = mac.doFinal(dataBytes);
            byte[] hexB = new Hex().encode(doFinal);
            return new String(hexB, "utf-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 把所有参数值按字母顺序排序并拼成一个长字符串
    public static String digest(String key, Map<String, ?> map) {
        StringBuilder s = new StringBuilder();
        List<String> list = new ArrayList<>();

        for(Object values : map.values()) {
            if(values instanceof String[]) {
                for(String value : (String[])values) {
                    list.add(value);
                }
            } else if(values instanceof List) {
                for(String value : (List<String>)values) {
                    list.add(value);
                }
            } else {
                list.add(values.toString());
            }
        }
        Collections.sort(list);

        for (String str : list) {
            s.append(str);
        }

        return digest(key, s.toString());
    }

}
