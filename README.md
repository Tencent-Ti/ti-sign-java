## 简介

欢迎使用Ti开发者工具(Tisign)，此工具是Ti平台配套的用于计算http请求签名的开发工具

## 依赖环境
1. 依赖环境：JDK 8 版本及以上
2. 本工具依赖的SecrectID和SerectKey需在Ti控制平台(管理中心-个人中心-密钥管理)获取，请务必妥善保管
3. 访问平台内部的接口请参考<Ti平台产品白皮书>

## 调用示例

```java
import com.tisign.TiSign;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class SignExample {
    public static void main(String []args){
        /* 以Ti平台 查询用户是否拥有Admin权限 接口为例, 以下是接口的基本信息:
            action: DescribeIsAdmin
            service: ti-auth
            version: 2020-10-10
            content-type: application/json
            http请求方法: POST
            网关访问地址: 127.0.0.1
        */
        try{
            String host = "127.0.0.1";               //访问网关的host
            String action = "DescribeIsAdmin";       //请求接口
            String version = "2020-10-10";           //接口版本
            String service = "ti-auth";              //接口所属服务
            String contentType = "application/json"; //http请求的content-type, 当前网关只支持: application/json  multipart/form-data
            String httpMethod = "POST";              //http请求方法，当前网关只支持: POST GET
            // Ti平台生成的鉴权密钥信息(通过 管理中心-个人中心-密钥管理 获取)
            String secretId = "test-secret-id";
            String secretKey = "test-secret-key";

            // 创建TiSign对象
            TiSign ts = new TiSign(host, action, version, service, contentType, httpMethod, secretId, secretKey);
            // 生成通过网关访问后端服务，所需http的请求header map 和 签名信息
            Map<String, String> httpHeaderMap = new HashMap<String, String>();
            String authorization = ts.CreateHeaderWithSignature(httpHeaderMap);
            // 打印签名信息
            System.out.println("============= 签名字符串 Authorization =============");
            System.out.println("authorization: " + authorization);
            // 打印http header信息
            System.out.println("============ 通过网关访问后端服务Http请求头 ============");
            Iterator<Map.Entry<String, String>> iterable = httpHeaderMap.entrySet().iterator();
            while(iterable.hasNext()){
                Map.Entry<String, String> entry = iterable.next();
                System.out.println(entry.getKey() + ": " + entry.getValue());
            }
        }catch (Exception e) {
            System.out.println(e.toString());
        }
    }
}
```
