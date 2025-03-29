# 编译OpenSSL

```shell
#配置
perl Configure VC-WIN64A no-filenames no-shared no-apps no-autoload-config no-tests no-deprecated no-docs no-legacy no-sock no-srp no-srtp no-psk no-ui-console no-quic no-dgram no-http no-ssl no-ssl3 no-tls no-dtls no-engine no-comp no-ec no-ec2m no-dynamic-engine no-ocsp no-cms no-cmp --prefix=G:/osslbuild/release
perl Configure VC-WIN64A no-filenames no-shared no-apps no-autoload-config no-tests no-deprecated no-docs no-legacy no-sock no-srp no-srtp no-psk no-ui-console no-quic no-dgram no-http no-ssl no-ssl3 no-tls no-dtls no-engine no-comp no-ec no-ec2m no-dynamic-engine no-ocsp no-cms no-cmp -d --prefix=G:/osslbuild/debug

#编译
nmake
#安装，配置时不指定--prefix就默认安装到Program Files文件夹中
nmake install
```
