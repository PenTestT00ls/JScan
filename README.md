# JS敏感信息检测工具 - jsFinder

## 工具简介
jsFinder是一个专门用于检测JavaScript文件中敏感信息的工具，支持认证扫描功能。

## 使用方法

### 基本语法
```bash
python jsFinder.py [选项] <目标URL>
```

### 参数说明

#### 必需参数
- `url` - 要扫描的目标URL

#### 可选参数

| 参数 | 缩写 | 说明 |
|------|------|------|
| `--help` | `-h` | 显示帮助信息 |
| `--output` | `-o` | 输出文件路径 |
| `--timeout` | `-t` | 请求超时时间(秒) |
| `--user-agent` |  | 自定义User-Agent |
| `--max-js-files` |  | 最大扫描JS文件数量 |

#### 认证相关参数
| 参数 | 说明 |
|------|------|
| `--cookies` | Cookie字符串，格式: "name=value; name2=value2" |
| `--cookies-file` | Cookie文件路径(.json或.txt) |
| `--auth-token` | Bearer认证令牌 |
| `--headers-file` | 自定义请求头JSON文件 |

#### 登录相关参数
| 参数 | 说明 |
|------|------|
| `--login-url` | 登录页面URL |
| `--username` | 登录用户名 |
| `--password` | 登录密码 |
| `--username-field` | 用户名表单字段名 |
| `--password-field` | 密码表单字段名 |

## 使用示例

### 基本扫描
```bash
python jsFinder.py https://example.com
```

### 带认证的扫描
```bash
python jsFinder.py --cookies "session=abc123; token=xyz789" https://example.com
```

### 自动登录扫描
```bash
python jsFinder.py --login-url https://example.com/login --username admin --password admin123 --username-field username --password-field password https://example.com
```

### 自定义输出和超时
```bash
python jsFinder.py -o results.txt -t 30 https://example.com
```

## 功能特性
- ✅ 支持JavaScript文件中的敏感信息检测
- ✅ 支持多种认证方式
- ✅ 支持自动登录功能
- ✅ 可自定义请求头
- ✅ 支持Cookie文件导入
- ✅ 可设置最大扫描文件数量限制

## 注意事项
- 请确保有合法的授权才能对目标进行扫描
- 建议在生产环境中谨慎使用
- 遵守相关法律法规和道德规范
