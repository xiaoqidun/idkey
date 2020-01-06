# idkey
golang argon2id 密码hash和验证
# 安装方法
go get -u github.com/xiaoqidun/idkey
# 使用方法
```go
// 生成argon2id hash密码
hash := idkey.Encode("admin")
// 进行argon2id hash验证
verify := idkey.Verify("admin", hash)
```
