# jsFinder - JavaScript文件链接提取与敏感信息检测工具

jsFinder是一个功能强大的安全工具，专门用于从网站中提取JavaScript文件链接，并智能检测JS文件中的敏感信息泄露。

## 功能特性

### 🔍 核心功能
- **JavaScript链接提取**：从HTML页面中自动发现和提取JavaScript文件链接
- **子域名发现**：基于提取的链接自动发现相关子域名
- **深度扫描**：支持深度扫描模式，递归发现更多链接

### 🔒 敏感信息检测（新增）
- **智能检测**：自动检测JS文件中的6类敏感信息
- **误报控制**：内置验证逻辑，减少误报率
- **上下文显示**：显示敏感信息所在的代码上下文
- **安全输出**：敏感值自动屏蔽显示，保护信息安全

### 📊 支持的敏感信息类型
1. **密码**（password） - 各种密码字段
2. **API密钥**（api_key） - API密钥和访问令牌
3. **令牌**（token） - JWT令牌、访问令牌等
4. **AWS密钥**（aws_keys） - AWS访问密钥和秘密密钥
5. **数据库凭证**（database_creds） - 数据库连接信息
6. **私钥**（private_keys） - 加密私钥

## 安装要求

```bash
pip install -r requirements.txt
```

### 依赖包
- `requests` - HTTP请求库
- `beautifulsoup4` - HTML解析库
- `urllib3` - URL处理库

## 使用方法

### 基本用法

```bash
# 扫描单个网站
python jsFinder.py -u https://example.com

# 扫描网站并启用深度模式
python jsFinder.py -u https://example.com -d

# 从文件读取URL列表进行扫描
python jsFinder.py -f urls.txt
```

### 敏感信息检测

```bash
# 启用敏感信息检测
python jsFinder.py -u https://example.com -s

# 限制扫描的JS文件数量
python jsFinder.py -u https://example.com -s --max-js-files 10

# 保存敏感信息检测结果到文件
python jsFinder.py -u https://example.com -s --sensitive-output results.txt

# 使用文件列表进行敏感信息检测
python jsFinder.py -f urls.txt -s --sensitive-output results.txt
```

### 完整参数说明

```bash
usage: jsFinder.py [-h] [-u URL] [-c COOKIE] [-f FILE]
                   [-ou OUTPUTURL] [-os OUTPUTSUBDOMAIN] [-j]   
                   [-d] [-s]
                   [--sensitive-output SENSITIVE_OUTPUT]        
                   [--max-js-files MAX_JS_FILES]

选项:
  -h, --help            显示帮助信息
  -u URL, --url URL     目标网站URL
  -c COOKIE, --cookie COOKIE
                        网站Cookie（用于认证）
  -f FILE, --file FILE  包含URL或JS文件链接的文件
  -ou OUTPUTURL, --outputurl OUTPUTURL
                        URL输出文件名
  -os OUTPUTSUBDOMAIN, --outputsubdomain OUTPUTSUBDOMAIN        
                        子域名输出文件名
  -j, --js              在JS文件中查找链接
  -d, --deep            深度查找模式
  -s, --sensitive       启用敏感信息检测  
  --sensitive-output SENSITIVE_OUTPUT
                        敏感信息检测结果输出文件
  --max-js-files MAX_JS_FILES
                        敏感信息检测的最大JS文件数量（默认20）

示例: python jsFinder.py -u http://www.baidu.com -s
```

## 使用示例

### 示例1：基本网站扫描

```bash
python jsFinder.py -u https://target.com
```

输出：
```
url:https://target.com
Find 15 URL:
https://target.com/js/app.js
https://target.com/js/utils.js
https://cdn.target.com/lib/jquery.min.js
...

Find 3 Subdomain:
cdn.target.com
api.target.com
static.target.com
```

### 示例2：敏感信息检测

```bash
python jsFinder.py -u https://target.com -s --sensitive-output scan_results.txt
```

输出：
```
url:https://target.com
Find 15 URL:
...

============================================================
开始敏感信息检测...
============================================================
[+] 发现 8 个JS文件，开始敏感信息检测...

[1/8] 分析JS文件: https://target.com/js/app.js
[!] 发现敏感信息!
    PASSWORD: 2 处
    API_KEY: 1 处

...

[!] 敏感信息检测报告
================================================================================
总计发现敏感信息的JS文件: 3 个
总计敏感信息条目: 7 处

JS文件: https://target.com/js/config.js
------------------------------------------------------------
PASSWORD (2 处):
  - 行号: 45
    隐藏值: db_**********pass
    完整值: db_admin_password
    上下文: var dbConfig = { host: "localhost", user: "admin", password: "db_admin_password" };

[+] 敏感信息检测结果已保存到: scan_results.txt
```

## 输出格式

### URL和子域名输出
- 控制台显示所有发现的URL和子域名
- 可选保存到指定文件

### 敏感信息检测报告
- **按JS文件分组**：每个文件单独显示检测结果
- **分类统计**：显示每类敏感信息的数量
- **详细信息**：包含行号、屏蔽值、完整值和上下文
- **安全显示**：敏感值自动屏蔽，保护信息安全

## 技术原理

### 链接提取算法
1. 使用BeautifulSoup解析HTML页面
2. 提取所有`<script>`标签的src属性
3. 使用正则表达式从JS内容中提取URL
4. 处理相对URL，转换为绝对URL

### 敏感信息检测
1. **模式匹配**：使用正则表达式匹配敏感字段
2. **上下文验证**：验证字段后是否真的包含敏感信息
3. **智能分类**：根据模式特征自动分类敏感信息
4. **结果聚合**：按文件和类型组织检测结果

### 误报控制机制
- 验证敏感字段后的实际内容
- 排除常见误报模式
- 提供上下文信息供人工验证

## 最佳实践

### 扫描策略
1. **循序渐进**：先进行基本扫描，再启用敏感信息检测
2. **数量控制**：使用`--max-js-files`参数控制扫描范围
3. **结果验证**：结合人工验证确保检测准确性

### 安全注意事项
1. **授权扫描**：仅在获得授权的情况下扫描目标网站
2. **结果保护**：妥善保管检测结果，防止敏感信息泄露
3. **合规使用**：遵守相关法律法规和道德准则

## 故障排除

### 常见问题

**Q: 扫描时没有发现任何URL**
A: 检查目标网站是否可访问，或尝试使用`-c`参数添加Cookie

**Q: 敏感信息检测没有结果**
A: 目标JS文件可能不包含敏感信息，或需要调整检测参数

**Q: 遇到SSL证书错误**
A: 工具已禁用SSL验证，如仍有问题请检查网络连接

### 性能优化
- 使用`--max-js-files`限制扫描数量提高效率
- 深度扫描模式会增加扫描时间，谨慎使用
- 大文件扫描可能需要较长时间

## 更新日志

### v2.0 (最新)
- ✅ 新增敏感信息检测功能
- ✅ 智能误报控制机制
- ✅ 详细的检测报告输出
- ✅ 安全的值屏蔽显示

### v1.0
- ✅ 基础URL提取功能
- ✅ 子域名发现
- ✅ 深度扫描模式


## 许可证

本项目采用MIT许可证。

## 免责声明

本工具仅用于安全研究和授权测试。使用者应遵守相关法律法规，对使用本工具造成的任何后果负责。