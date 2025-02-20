package com.fdu.verifysignature.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.TreeMap;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Service
public class CanonicalJsonGenerator {
    private static final Log LOG = LogFactory.getLog(CanonicalJsonGenerator.class);
    
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .disable(SerializationFeature.INDENT_OUTPUT)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
            
    private static final ThreadLocal<TreeMap<String, String>> threadLocalTreeMap = 
            ThreadLocal.withInitial(TreeMap::new);
            
    private final JdbcTemplate jdbcTemplate;
    
    public CanonicalJsonGenerator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Map<String, Object> getRecordByTxId(String tableName, String txId) {
        String sql = String.format("SELECT * FROM %s WHERE tx_id = ?", tableName);
        try {
            List<Map<String, Object>> results = jdbcTemplate.queryForList(sql, txId);
            return results.isEmpty() ? null : results.get(0);
        } catch (Exception e) {
            LOG.error("查询交易记录失败: " + e.getMessage(), e);
            return null;
        }
    }
}