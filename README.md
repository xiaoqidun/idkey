# idkey[![PkgGoDev](https://pkg.go.dev/badge/github.com/xiaoqidun/idkey)](https://pkg.go.dev/github.com/xiaoqidun/idkey)
Golang Argon2id 密码hash和验证
# 安装方法
go get -u github.com/xiaoqidun/idkey
# 使用方法
```go
// 生成argon2id hash密码
hash := idkey.Encode([]byte("admin"), nil)
// 进行argon2id hash验证
verify := idkey.Verify([]byte("admin"), hash)
```
