package com.tisign;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class TiSign {
    private static final Charset UTF8 = StandardCharsets.UTF_8;
    private String host;         //请求header的host字段
    private String xtcAction;    //请求接口action
    private String xtcVersion;   //请求接口版本
    private String xtcService;   //请求接口服务名
    private String xtcTimestamp; //请求unix时间搓，精确到秒
    private String contentType;  //http请求Header的Content-type值，当前网关只支持: application/json  multipart/form-data
    private String httpMethod;   //http请求方法，只能为 POST 或者 GET

    // Ti平台获取的签名密钥(通过 管理中心-个人中心-密钥管理 获取)，非常重要，请妥善保管
    private String secretId;
    private String secretKey;

    public TiSign(String host, String action, String version, String service, String contentType, String httpMethod,
                  String secretId, String secretKey) {
        this.host = host;
        this.xtcAction = action;
        this.xtcVersion = version;
        this.xtcService = service;
        this.contentType = contentType;
        this.httpMethod = httpMethod;

        this.secretId = secretId;
        this.secretKey = secretKey;
    }

    public String CreateHeaderWithSignature(Map<String, String> header) throws Exception {
        // 1. 构造canonical request 字符串
        // 1.1 设置http请求方法: POST 或 GET
        String httpRequestMethod = this.httpMethod;
        if (httpRequestMethod == null) {
            throw new Exception(
                    "Request method should not be null, can only be GET or POST");
        }
        // 1.2 设置常量URI和QueryString
        String canonicalUri = "/";
        String canonicalQueryString = "";
        // 1.3 拼接关键header信息，包括content-type和根域名host
        String canonicalHeaders = "content-type:" + this.contentType + "\nhost:" + this.host + "\n";
        // 1.4 设置常量签名头字符串
        String signedHeaders = "content-type;host";
        // 1.5 对常量payload进行hash计算
        String requestPayload = "";
        String hashedRequestPayload = this.sha256Hex(requestPayload);
        // 1.6 按照固定格式拼接所有请求信息
        String canonicalRequest =
                httpRequestMethod
                        + "\n"
                        + canonicalUri
                        + "\n"
                        + canonicalQueryString
                        + "\n"
                        + canonicalHeaders
                        + "\n"
                        + signedHeaders
                        + "\n"
                        + hashedRequestPayload;

        // 2. 构造用于计算签名的字符串
        // 2.1 构造请求时间，根据请求header的X-TC-Timestamp字段(unix时间搓，精确到秒)，计算UTC标准日期
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000);
        this.xtcTimestamp = timestamp;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        String date = sdf.format(new Date(Long.valueOf(timestamp + "000")));
        // 2.2 构造凭证范围，固定格式为：Date/service/tc3_request
        String credentialScope = date + "/" + this.xtcService + "/" + "tc3_request";
        // 2.3 对第1步构造的 canonicalRequest 进行hash计算
        String hashedCanonicalRequest =
                this.sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        // 2.4 按照固定格式构造用于签名的字符串
        String stringToSign =
                "TC3-HMAC-SHA256\n" + timestamp + "\n" + credentialScope + "\n" + hashedCanonicalRequest;

        // 3. 对第2步构造的字符串进行签名
        // 3.1 用平台分配secretKey对步骤2计算的标准UTC时间进行hash计算，生成secretDate
        byte[] secretDate = this.hmac256(("TC3" + this.secretKey).getBytes(StandardCharsets.UTF_8), date);
        // 3.2 用3.1生成的secretDate对请求模块进行hash计算，生成secretService
        byte[] secretService = this.hmac256(secretDate, this.xtcService);
        // 3.3 用3.2生成的secretService对tc3_request常量字符串进行hash计算, 生成secretKey
        byte[] secretSigning = this.hmac256(secretService, "tc3_request");
        // 3.4 用3.3生成的secretKey对第2构造的签名字符串进行hash计算，并生成最终的签名字符串
        String signature =
                DatatypeConverter.printHexBinary(this.hmac256(secretSigning, stringToSign)).toLowerCase();

        // 4. 构造http请求头的authorization字段
        // 4.1 按照固定格式构造authorization字符串
        String authorization =
                "TC3-HMAC-SHA256 "
                        + "Credential="
                        + this.secretId
                        + "/"
                        + credentialScope
                        + ", "
                        + "SignedHeaders="
                        + signedHeaders
                        + ", "
                        + "Signature="
                        + signature;

        // 构造http请求header的map
        header.put("Host", this.host);
        header.put("X-TC-Action", this.xtcAction);
        header.put("X-TC-Version", this.xtcVersion);
        header.put("X-TC-Service", this.xtcService);
        header.put("X-TC-Timestamp", this.xtcTimestamp);
        header.put("Content-Type", this.contentType);
        header.put("Authorization", authorization);

        return authorization;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getHost() {
        return this.host;
    }

    public void setAction(String action) {
        this.xtcAction = action;
    }

    public String getAction(){
        return this.xtcAction;
    }

    public void setVersion(String version) {
        this.xtcVersion = version;
    }

    public String getVersion(){
        return this.xtcVersion;
    }

    public void setService(String service) {
        this.xtcService = service;
    }

    public String getService() {
        return this.xtcService;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getContentType(){
        return this.contentType;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public String getHttpMethod(){
        return httpMethod;
    }

    public void setSecretId(String secretId) {
        this.secretId = secretId;
    }

    public String getSecretId() {
        return this.secretId;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getSecretKey() {
        return this.secretKey;
    }

    private static String sha256Hex(String s) throws Exception {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("SHA-256 is not supported." + e.getMessage());
        }
        byte[] d = md.digest(s.getBytes(UTF8));
        return DatatypeConverter.printHexBinary(d).toLowerCase();
    }

    public static String sha256Hex(byte[] b) throws Exception {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("SHA-256 is not supported." + e.getMessage());
        }
        byte[] d = md.digest(b);
        return DatatypeConverter.printHexBinary(d).toLowerCase();
    }

    public static byte[] hmac256(byte[] key, String msg) throws Exception {
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("HmacSHA256 is not supported." + e.getMessage());
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, mac.getAlgorithm());
        try {
            mac.init(secretKeySpec);
        } catch (InvalidKeyException e) {
            throw new Exception(e.getClass().getName() + "-" + e.getMessage());
        }
        return mac.doFinal(msg.getBytes(UTF8));
    }
}
