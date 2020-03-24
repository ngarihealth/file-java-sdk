package com.ngari.util;

import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FileAuth {
    private static FileAuth instance;
    private  String accessKey;
    private final SecretKeySpec secretKey;

    public FileAuth(String accessKey, String secret) {
        if (isNullOrEmpty(accessKey) || isNullOrEmpty(secret)) {
            throw new IllegalArgumentException("empty key or secret");
        }
        byte[] sk = utf8Bytes(secret);
        SecretKeySpec secretKeySpec = new SecretKeySpec(sk, "HmacSHA1");
        this.accessKey = accessKey;
        this.secretKey = secretKeySpec;
        instance = this;
    }
    public static FileAuth instance(){
        if(instance == null){
            throw new IllegalStateException("FileAuth not setup,please check");
        }
        return instance;
    }

    public String getAccessKey() {
        return accessKey;
    }

    private Mac createMac() {
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(secretKey);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            throw new IllegalArgumentException(e);
        }
        return mac;
    }
    public String sign(byte[] data) {
        Mac mac = createMac();
        return encodeToString(mac.doFinal(data));
    }

     /**
     * 编码数据
     *
     * @param data 字节数组
     * @return 结果字符串
     */

    private static String encodeToString(byte[] data) {

        return Base64.encodeToString(data, Base64.URL_SAFE | Base64.NO_WRAP);
    }
    /**
     * 解码数据
     *
     * @param data 编码过的字符串
     * @return 原始数据
     */
    public static byte[] decode(String data) {
        return Base64.decode(data, Base64.URL_SAFE | Base64.NO_WRAP);
    }

    public String sign(String data) {
        return sign(utf8Bytes(data));
    }


    private static boolean isNullOrEmpty(String s) {
        return s == null || "".equals(s);
    }
    private static byte[] utf8Bytes(String data) {
        return data.getBytes(StandardCharsets.UTF_8);
    }


    /**
     * 签名时间有效期校验，签名数据默认两小时有效
     * @param expireTime 过期时间戳(s)
     * @return if expired return true,else return false
     */
    private  boolean isTimeExpired(long expireTime){
        long nowTime=System.currentTimeMillis()/1000;
        return nowTime > expireTime;
    }

    /**
     * 根据fileId生成token、
     * token=过期时间戳:accessKey:sign
     * @param fileId 文件id
     * @param expires 有效时间 如3600s
     * @return
     */
    public  String createToken(String fileId,long expires){
        if(instance==null){
            return null;
        }
        long deadline = System.currentTimeMillis()/1000 + expires;
        //signStr=fileId?deadline
        String sign = this.sign(fileId + "?" + deadline);
        //token=deadline:accessKey:sign
        return StringUtils.join(new Object []{deadline,this.accessKey,sign},":");
    }
    private String createTokens(String fileIds, long expires){
        String[] keys = StringUtils.split(fileIds,',');
        String[]tokens=new String[keys.length];
        for (int i = 0; i < keys.length; i++) {
            tokens[i] = createToken(keys[i], expires);
        }
        return StringUtils.join(tokens, ",");
    }
    private String createTokensByListStr(String fileIdListStr, long expires){
        List<Object> fileIdList = JSONUtils.parse(fileIdListStr, List.class);
        List<String> strList = new ArrayList<>();
        for (Object o : fileIdList) {
            strList.add(String.valueOf(o));
        }
        return JSONUtils.toString(createTokens(strList, expires));
    }
    private List<String> createTokens(List<String> fileIdList, long expires){

        List<String> list = Lists.newArrayList();
        for (String s : fileIdList) {
            list.add(createToken(s, expires));
        }
        return list;
    }

    public String createUploadToken(String bucket){
        Map<String, Object> policy = new HashMap<>();
        policy.put("scope", bucket);
        policy.put("deadline", System.currentTimeMillis() / 1000 + 3600L);
        return createUploadToken(bucket, policy);
    }
    public String createUploadToken(String bucket,long expires){
        Map<String, Object> policy = new HashMap<>();
        policy.put("scope", bucket);
        policy.put("deadline", System.currentTimeMillis() / 1000 + expires);
        return createUploadToken(bucket, policy);
    }

    /**
     * 生成上传凭证
     * @param bucket 需要上传到的bucket
     * @param policy 上传策略
     * @return
     */
    public  String createUploadToken(String bucket, Map<String,Object> policy){
        String sign=this.sign(JSONUtils.toString(policy));
        return this.accessKey + ':' + sign + ':' + encodeToString(utf8Bytes(JSONUtils.toString(policy)));
    }

    public static void main(String[] args) {
        //只需初始一次，不用每次new
        FileAuth fileAuth = new FileAuth("accessKey","secret");
        //生成上传token,指定上传空间，默认有效期为1h
        String uptk = fileAuth.createUploadToken("other-doc");
        System.out.println(uptk);
        //针对文件id，生成浏览token,有效期为1小时
        String token=fileAuth.createToken("5dbf93147826c67027c438bf",3600L);
        System.out.println(token);
        //其他格式
        System.out.println(fileAuth.createTokens("a,b,c", 3600));
        System.out.println(fileAuth.createTokensByListStr("[\"a\",\"b\"]", 3600));
        System.out.println(fileAuth.createTokensByListStr("[1,2]", 3600));
        System.out.println(fileAuth.createTokens(Lists.newArrayList("a","b"), 3600));
    }




}
