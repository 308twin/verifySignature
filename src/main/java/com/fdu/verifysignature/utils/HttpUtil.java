/*
 * @Author: LHD
 * @Date: 2025-02-19 16:59:40
 * @LastEditors: 308twin 790816436@qq.com
 * @LastEditTime: 2025-02-19 17:01:59
 * @Description: 
 * 
 * Copyright (c) 2025 by 308twin@790816436@qq.com, All Rights Reserved. 
 */
package com.fdu.verifysignature.utils;

import java.security.PublicKey;

import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

public class HttpUtil {
    private static final RestTemplate restTemplate = new RestTemplate();
    
    public static String getPublicKey(String baseUrl, String tableName) {
        String url = UriComponentsBuilder.fromHttpUrl(baseUrl)
                .path("/getPublicKey")
                .queryParam("tableName", tableName)
                .toUriString();
        
        return restTemplate.getForObject(url, String.class);
    }
}
