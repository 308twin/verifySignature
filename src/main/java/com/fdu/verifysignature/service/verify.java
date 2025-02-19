/*
 * @Author: LHD
 * @Date: 2025-02-19 16:54:25
 * @LastEditors: 308twin 790816436@qq.com
 * @LastEditTime: 2025-02-19 17:06:43
 * @Description: 
 * 
 * Copyright (c) 2025 by 308twin@790816436@qq.com, All Rights Reserved. 
 */
package com.fdu.verifysignature.service;

import com.fdu.verifysignature.utils.HttpUtil;

public class verify {
    private static final String BASE_URL = "http://10.176.24.28:9090/api"; // 需要替换为实际的服务器地址
    
    public String getPublicKeyFromServer(String tableName) {
        return HttpUtil.getPublicKey(BASE_URL, tableName);
    }

    public static void main (String[] args) {
        verify v = new verify();
        String tableName = "supervise_online_vehicle";
        String publicKey = v.getPublicKeyFromServer(tableName);
        System.out.println("Public key for table " + tableName + " is: " + publicKey);
    }
}
