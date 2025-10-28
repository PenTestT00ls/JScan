PS D:\NetSafety\jsFinder> python .\jsFinder.py -h
usage: jsFinder.py [-h] [-o OUTPUT] [-t TIMEOUT] [--user-agent USER_AGENT] [--max-js-files MAX_JS_FILES]
                   [--cookies COOKIES] [--cookies-file COOKIES_FILE] [--auth-token AUTH_TOKEN]
                   [--headers-file HEADERS_FILE] [--login-url LOGIN_URL] [--username USERNAME] [--password PASSWORD]
                   [--username-field USERNAME_FIELD] [--password-field PASSWORD_FIELD]
                   url

JS敏感信息检测工具 - 支持认证扫描

positional arguments:
  url                   要扫描的目标URL

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        输出文件路径
  -t TIMEOUT, --timeout TIMEOUT
                        请求超时时间(秒)
  --user-agent USER_AGENT
                        自定义User-Agent
  --max-js-files MAX_JS_FILES
                        最大扫描JS文件数量
  --cookies COOKIES     Cookie字符串，格式: "name=value; name2=value2"
  --cookies-file COOKIES_FILE
                        Cookie文件路径(.json或.txt)
  --auth-token AUTH_TOKEN
                        Bearer认证令牌
  --headers-file HEADERS_FILE
                        自定义请求头JSON文件
  --login-url LOGIN_URL
                        登录页面URL
  --username USERNAME   登录用户名
  --password PASSWORD   登录密码
  --username-field USERNAME_FIELD
                        用户名表单字段名
  --password-field PASSWORD_FIELD
                        密码表单字段名
