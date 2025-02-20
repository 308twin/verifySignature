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

import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.springframework.jdbc.core.JdbcTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fdu.verifysignature.utils.CanonicalJsonGenerator;
import com.fdu.verifysignature.utils.HttpUtil;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.fdu.verifysignature.utils.CanonicalJsonGenerator;

public class verify {
    private static final Logger logger = LoggerFactory.getLogger(verify.class);
    private static final String BASE_URL = "http://10.176.24.28:9090/api"; // 需要替换为实际的服务器地址
    private final JdbcTemplate jdbcTemplate;
    private final CanonicalJsonGenerator canonicalJsonGenerator;
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .disable(SerializationFeature.INDENT_OUTPUT)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    private static final ThreadLocal<TreeMap<String, String>> threadLocalTreeMap = ThreadLocal
            .withInitial(TreeMap::new);

    public verify(JdbcTemplate jdbcTemplate, CanonicalJsonGenerator canonicalJsonGenerator) {
        this.jdbcTemplate = jdbcTemplate;
        this.canonicalJsonGenerator = canonicalJsonGenerator;
    }

    public PublicKey getPublicKeyFromServer(String tableName) {
        try {
            String publicKeyStr = HttpUtil.getPublicKey(BASE_URL, tableName);
            if (publicKeyStr == null || publicKeyStr.isEmpty()) {
                logger.error("从服务器获取的公钥为空");
                return null;
            }

            byte[] keyBytes = java.util.Base64.getDecoder().decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(keyBytes));
        } catch (IllegalArgumentException e) {
            logger.error("Base64解码失败: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            logger.error("获取公钥失败: {}", e.getMessage());
            return null;
        }
    }

    // 使用公钥验证签名
    public boolean verifySignature(String tableName, byte[] data, byte[] signatureBytes) {
        try {
            PublicKey publicKey = getPublicKeyFromServer(tableName);
            if (publicKey == null) {
                throw new IllegalStateException("Public key not found for table: " + tableName);
            }
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public Map<String, Object> getRecordByTxId(String tableName, String txId) {
        String sql = String.format("SELECT * FROM %s WHERE tx_id = ?", tableName);
        try {
            List<Map<String, Object>> results = jdbcTemplate.queryForList(sql, txId);
            return results.isEmpty() ? null : results.get(0);
        } catch (Exception e) {
            logger.error("查询交易记录失败: " + e.getMessage(), e);
            return null;
        }
    }

    // 验证数据库记录的签名
    public boolean verifyDatabaseRecord(String tableName, Map<String, Object> record, String signatureBase64) {
        try {
            // 获取线程内复用的 TreeMap 并清空旧数据
            TreeMap<String, String> canonicalJsonMap = threadLocalTreeMap.get();
            canonicalJsonMap.clear();

            // 过滤和标准化数据
            for (Map.Entry<String, Object> entry : record.entrySet()) {
                String columnName = entry.getKey();
                // 排除签名相关字段
                if ("signature".equalsIgnoreCase(columnName) || "verify_hash".equalsIgnoreCase(columnName)) {
                    continue;
                }
                // 统一转换字段值
                String value = entry.getValue() == null ? "" : entry.getValue().toString().trim();
                canonicalJsonMap.put(columnName, value);
            }

            // 生成规范的 JSON 字符串
            String canonicalJson = objectMapper.writeValueAsString(canonicalJsonMap);
            byte[] data = canonicalJson.getBytes(StandardCharsets.UTF_8);
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

            // 验证签名
            return verifySignature(tableName, data, signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

    /**
     * 根据 tx_id 查询并生成规范化的JSON
     */
    public String generateCanonicalJson(String tableName, String txId) {
        try {

            Map<String, Object> record = getRecordByTxId(tableName, txId);

            // 获取TreeMap并清空
            TreeMap<String, String> canonicalJsonMap = threadLocalTreeMap.get();
            canonicalJsonMap.clear();

            // 处理所有字段
            record.forEach((key, value) -> {
                // 排除不需要的字段
                if (!"signature".equalsIgnoreCase(key) &&
                        !"verify_hash".equalsIgnoreCase(key)) {
                    canonicalJsonMap.put(key, normalizeValue(value));
                }
            });

            return objectMapper.writeValueAsString(canonicalJsonMap);

        } catch (Exception e) {
            logger.error("生成规范化JSON失败: " + txId, e);
            throw new RuntimeException("生成规范化JSON失败", e);
        }
    }

    /**
     * 统一的值格式化方法
     */
    private String normalizeValue(Object value) {
        if (value == null) {
            return "";
        }
        // 处理不同类型的值
        return value.toString().trim();
    }

    public boolean testVerifyTransactionSignature(String tableName, String txId) {
        try {
            Map<String, Object> record = getRecordByTxId(tableName, txId);
            if (record == null || record.isEmpty()) {
                System.out.println("未找到交易记录: " + txId);
                return false;
            }

            // 获取记录中的签名
            String signatureBase64 = (String) record.get("signature");
            if (signatureBase64 == null || signatureBase64.isEmpty()) {
                System.out.println("记录中未包含签名信息");
                return false;
            }

            // 验证签名
            boolean isValid = verifyDatabaseRecord(tableName, record, signatureBase64);

            // 打印验证结果
            System.out.println("交易 " + txId + " 的签名验证结果: " + (isValid ? "有效" : "无效"));
            return isValid;
        } catch (Exception e) {
            System.err.println("验证签名时发生错误: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        // 创建数据源
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://localhost:3306/block_chain");
        config.setUsername("root");
        config.setPassword("199795");
        config.setDriverClassName("com.mysql.cj.jdbc.Driver");

        // 创建连接池
        HikariDataSource dataSource = new HikariDataSource(config);

        // 创建JdbcTemplate
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

        CanonicalJsonGenerator generator = new CanonicalJsonGenerator(jdbcTemplate);
        verify v = new verify(jdbcTemplate, generator);

        String tableName = "supervise_online_vehicle";
        String txId = "17ed0d9d591161beca121aa28232395f661dab51d9fd401488c11101b6fd7df2";

        System.out.println(v.testVerifyTransactionSignature(tableName, txId));
    }
}
