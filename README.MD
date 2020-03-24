# 文件上传浏览凭证工具类

## 生成上传凭证
用法
````java
//只需初始一次，不用每次new
FileAuth fileAuth = new FileAuth("accessKey","secret");
//生成上传token,指定上传空间，默认有效期为1h
String uptk = fileAuth.createUploadToken("other-doc");
````

## 生成浏览凭证
用法
````java
//只需初始一次，不用每次new
FileAuth fileAuth = new FileAuth("accessKey","secret");
 //针对文件id，生成浏览token,有效期为1小时
String token=fileAuth.createToken("5dbf93147826c67027c438bf",3600L);

````