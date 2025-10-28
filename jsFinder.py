#!/usr/bin/env python3
"""
JS敏感信息检测工具 - 支持认证扫描和增强JS提取
"""

import requests
import re
import json
import time
import urllib.parse
from typing import List, Dict, Tuple
import argparse
import sys
import os

class JSSensitiveInfoDetector:
    def __init__(self, timeout=10, user_agent=None, cookies=None, headers=None, auth_token=None):
        self.timeout = timeout
        self.session = requests.Session()
        
        # 设置请求头
        default_headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        if headers:
            default_headers.update(headers)
        
        self.session.headers.update(default_headers)
        
        # 设置Cookie
        if cookies:
            if isinstance(cookies, str):
                self.session.headers.update({'Cookie': cookies})
            elif isinstance(cookies, dict):
                self.session.cookies.update(cookies)
        
        # 设置认证令牌
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
        
        # 定义敏感信息正则表达式模式
        self.sensitive_patterns = {
            'password': [
                r'password\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'pwd\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'pass\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'password\s*:\s*([^\s,]+)',
                r'passwd\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'psw\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'login_password\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'user_password\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'admin_password\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'api_key': [
                r'api[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'apikey\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'api[_-]?secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'app[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'app[_-]?secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'client[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'client[_-]?secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'service[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'secret': [
                r'secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'secret[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'client_secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'app_secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'private[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'shared[_-]?secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'encryption[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'token': [
                r'token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'access[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'auth[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'refresh[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'bearer[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'session[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'csrf[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'xsrf[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'security[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'auth': [
                r'authorization\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'auth\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'authentication\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'login\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'credential\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'basic[_-]?auth\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'jwt': [
                r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                r'eyJhbGciOiJ[^\s\']+',
            ],
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'aws[_-]?secret[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'aws[_-]?session[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'cloud_keys': [
                # Google Cloud
                r'AIza[0-9A-Za-z_-]{35}',
                r'ya29\.[0-9A-Za-z_-]+',
                # Azure
                r'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}',
                # DigitalOcean
                r'dop_v1_[a-f0-9]{64}',
                # Stripe
                r'sk_live_[0-9a-zA-Z]{24}',
                r'pk_live_[0-9a-zA-Z]{24}',
                r'sk_test_[0-9a-zA-Z]{24}',
                r'pk_test_[0-9a-zA-Z]{24}',
                # Slack
                r'xox[abprs]-[0-9a-zA-Z]{10,48}',
                # GitHub
                r'gh[oprs]_[0-9a-zA-Z]{36}',
                r'github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}',
            ],
            'database_url': [
                r'mongodb[+]srv://[^\s\'"]+',
                r'postgresql://[^\s\'"]+',
                r'mysql://[^\s\'"]+',
                r'redis://[^\s\'"]+',
                r'sqlserver://[^\s\'"]+',
                r'oracle://[^\s\'"]+',
                r'jdbc:[^\s\'"]+',
                r'database[_-]?url\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'connection[_-]?string\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'db[_-]?url\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'email_credentials': [
                r'smtp[_-]?password\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'email[_-]?pass\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'mail[_-]?password\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'smtp[_-]?user\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'smtp[_-]?username\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'mail[_-]?user\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'private_key': [
                r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
                r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                r'-----BEGIN PRIVATE KEY-----',
                r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
            ],
            'oauth': [
                r'oauth[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'oauth[_-]?secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'oauth[_-]?consumer[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'oauth[_-]?consumer[_-]?secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'webhook': [
                r'webhook[_-]?url\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'discord[_-]?webhook\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'slack[_-]?webhook\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'teams[_-]?webhook\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'social_media': [
                r'facebook[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'twitter[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'instagram[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'linkedin[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'google[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'payment': [
                r'stripe[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'paypal[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'braintree[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'credit[_-]?card\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'payment[_-]?token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
            'config': [
                r'config\s*[=:]\s*{[\s\S]*?}',
                r'configuration\s*[=:]\s*{[\s\S]*?}',
                r'env\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'environment\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'debug\s*[=:]\s*[\'"](true|false)[\'"]',
                r'production\s*[=:]\s*[\'"](true|false)[\'"]',
            ],
            'url_endpoints': [
                r'endpoint\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'base[_-]?url\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'api[_-]?url\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'service[_-]?url\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'backend[_-]?url\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'graphql[_-]?endpoint\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            ],
    
            'ip_addresses_private': [
                r'(?:10|127|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.\d{1,3}\.\d{1,3}',
                r'localhost',
                r'0\.0\.0\.0',
            ],
            'sensitive_comments': [
                r'//\s*(TODO|FIXME|HACK|XXX|BUG)\s*:.*$',
                r'/\*.*?(TODO|FIXME|HACK|XXX|BUG).*?\*/',
                r'#\s*(TODO|FIXME|HACK|XXX|BUG)\s*:.*$',
            ],
            'file_paths': [
                r'/[a-zA-Z0-9_\-./]*\.(key|pem|crt|cer|pfx|p12|p7b)',
                r'/[a-zA-Z0-9_\-./]*\.(env|config|conf|ini|properties)',
                r'/[a-zA-Z0-9_\-./]*\.(log|txt|csv|json|xml)',
            ]
        }

    def extract_js_paths(self, html_content: str, base_url: str) -> List[str]:
        """
        从HTML内容中提取JS文件路径并拼接完整URL
        """
        js_patterns = [
            # <script> 标签中的src属性
            r'<script[^>]*?src\s*=\s*["\']?([^"\'\s>]*?\.js(?:\?[^"\'\s>]*)?)["\']?[^>]*>',
            
            # <link> 标签中的href属性 - 更宽松的匹配
            r'<link[^>]*?href\s*=\s*["\']?([^"\'\s>]*?\.js(?:\?[^"\'\s>]*)?)["\']?[^>]*?rel\s*=\s*["\']?prefetch["\']?[^>]*>',
            r'<link[^>]*?rel\s*=\s*["\']?prefetch["\']?[^>]*?href\s*=\s*["\']?([^"\'\s>]*?\.js(?:\?[^"\'\s>]*)?)["\']?[^>]*>',
            
            r'<link[^>]*?href\s*=\s*["\']?([^"\'\s>]*?\.js(?:\?[^"\'\s>]*)?)["\']?[^>]*?rel\s*=\s*["\']?preload["\']?[^>]*>',
            r'<link[^>]*?rel\s*=\s*["\']?preload["\']?[^>]*?href\s*=\s*["\']?([^"\'\s>]*?\.js(?:\?[^"\'\s>]*)?)["\']?[^>]*>',
            
            r'<link[^>]*?href\s*=\s*["\']?([^"\'\s>]*?\.js(?:\?[^"\'\s>]*)?)["\']?[^>]*?rel\s*=\s*["\']?modulepreload["\']?[^>]*>',
            r'<link[^>]*?rel\s*=\s*["\']?modulepreload["\']?[^>]*?href\s*=\s*["\']?([^"\'\s>]*?\.js(?:\?[^"\'\s>]*)?)["\']?[^>]*>',
            
            # 通用href匹配（兜底）
            r'href\s*=\s*["\']?([^"\'\s>]*?\.js(?:\?[^"\'\s>]*)?)["\']?',
            
            # ES6 import 语句
            r'import\s+(?:\w+\s+from\s+)?["\']([^"\']*\.js)["\']',
            r'import\s*\(["\']([^"\']*\.js)["\']\)',
            
            # CommonJS require
            r'require\s*\(\s*["\']([^"\']*\.js)["\']\s*\)',
            
            # src属性 (通用)
            r'src\s*=\s*["\']?([^"\'\s>]*?\.js(?:\?[^"\'\s>]*)?)["\']?',
        ]
        
        js_urls = []
        
        for pattern in js_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                js_path = match.group(1).strip()
                if not js_path or not js_path.endswith('.js'):
                    continue
                    
                # 清理路径中的多余字符
                js_path = js_path.split(' ')[0].split('>')[0]
                
                # 拼接完整URL
                full_url = self.build_full_url(js_path, base_url)
                if full_url and full_url not in js_urls:
                    js_urls.append(full_url)
                    print(f"[+] 提取到JS路径: {js_path} -> {full_url}")
        
        return js_urls

    def build_full_url(self, js_path: str, base_url: str) -> str:
        """
        根据相对路径构建完整URL
        """
        if not js_path or js_path.startswith(('javascript:', 'data:')):
            return None
        
        # 如果已经是完整URL，直接返回
        if js_path.startswith(('http://', 'https://')):
            return js_path
        
        # 处理双斜杠开头的URL
        if js_path.startswith('//'):
            scheme = urllib.parse.urlparse(base_url).scheme
            return f"{scheme}:{js_path}" if scheme else f"https:{js_path}"
        
        # 处理绝对路径
        if js_path.startswith('/'):
            return urllib.parse.urljoin(base_url, js_path)
        
        # 处理相对路径
        if not js_path.startswith(('http://', 'https://', '/', '//')):
            return urllib.parse.urljoin(base_url, js_path)
        
        return None

    def debug_html_content(self, html_content: str, base_url: str):
        """调试HTML内容，找出所有可能的JS链接"""
        print("[*] 开始调试HTML内容...")
        
        # 查找所有包含js的字符串
        js_related_patterns = [
            r'href\s*=\s*[^>]*\.js[^>]*',
            r'src\s*=\s*[^>]*\.js[^>]*',
            r'<link[^>]*>',
            r'<script[^>]*>',
        ]
        
        found_count = 0
        for pattern in js_related_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                content = match.group(0)
                print(f"[调试] 找到可能包含JS的标签: {content}")
                
                # 尝试从这些内容中提取JS路径
                if 'href' in content and '.js' in content:
                    href_match = re.search(r'href\s*=\s*["\']?([^"\'\s>]*\.js[^"\'\s>]*)', content, re.IGNORECASE)
                    if href_match:
                        js_path = href_match.group(1)
                        full_url = self.build_full_url(js_path, base_url)
                        print(f"[调试] 从href提取: {js_path} -> {full_url}")
                        found_count += 1
                
                if 'src' in content and '.js' in content:
                    src_match = re.search(r'src\s*=\s*["\']?([^"\'\s>]*\.js[^"\'\s>]*)', content, re.IGNORECASE)
                    if src_match:
                        js_path = src_match.group(1)
                        full_url = self.build_full_url(js_path, base_url)
                        print(f"[调试] 从src提取: {js_path} -> {full_url}")
                        found_count += 1
        
        if found_count == 0:
            print("[调试] 未找到任何包含JS的标签")

    def load_cookies_from_file(self, file_path: str):
        """从文件加载Cookie"""
        try:
            if file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    cookies_dict = json.load(f)
                    self.session.cookies.update(cookies_dict)
            else:
                with open(file_path, 'r') as f:
                    cookie_str = f.read().strip()
                    self.session.headers.update({'Cookie': cookie_str})
            print(f"[+] 从文件加载Cookie: {file_path}")
        except Exception as e:
            print(f"[-] 加载Cookie文件失败: {e}")

    def login_with_credentials(self, login_url: str, username: str, password: str, 
                             username_field='username', password_field='password',
                             extra_data=None):
        """使用用户名密码登录"""
        try:
            login_data = {
                username_field: username,
                password_field: password
            }
            
            if extra_data:
                login_data.update(extra_data)
            
            print(f"[*] 尝试登录: {login_url}")
            response = self.session.post(login_url, data=login_data, timeout=self.timeout)
            
            if response.status_code == 200:
                print("[+] 登录请求成功")
                if "login" not in response.url.lower() and "error" not in response.text.lower():
                    print("[+] 登录可能成功")
                    return True
                else:
                    print("[-] 登录可能失败")
                    return False
            else:
                print(f"[-] 登录请求失败: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[-] 登录过程中出错: {e}")
            return False

    def extract_js_links(self, url: str) -> List[str]:
        """从网页中提取所有JS链接（增强版）"""
        js_links = []
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            print(f"[+] 访问成功: {url} (HTTP {response.status_code})")
            
            # 检查是否被重定向到登录页面
            if any(keyword in response.url.lower() for keyword in ['login', 'signin', 'auth']):
                print("[-] 被重定向到登录页面，可能认证失败")
                return []
            
            # 使用增强的提取函数
            js_links = self.extract_js_paths(response.text, response.url)
            
            # 如果没有找到JS链接，尝试调试模式
            if not js_links:
                print("[-] 未找到JS文件链接，尝试调试模式...")
                self.debug_html_content(response.text, response.url)
            
            print(f"[+] 从 {url} 中提取到 {len(js_links)} 个JS文件链接")
            
        except requests.RequestException as e:
            print(f"[-] 无法访问 {url}: {e}")
        except Exception as e:
            print(f"[-] 提取JS链接时出错: {e}")
            
        return js_links

    def fetch_js_content(self, js_url: str) -> str:
        """获取JS文件内容（使用认证会话）"""
        try:
            response = self.session.get(js_url, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"[-] 无法获取JS文件 {js_url}: {e}")
            return ""

    def detect_sensitive_info(self, js_content: str) -> Dict[str, List[str]]:
        """检测JS内容中的敏感信息"""
        findings = {}
        
        for category, patterns in self.sensitive_patterns.items():
            category_findings = []
            for pattern in patterns:
                matches = re.finditer(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    if match.groups():
                        value = match.group(1)
                    else:
                        value = match.group(0)
                    
                    if value and len(value) > 3 and value not in [v['full_value'] for v in category_findings]:
                        if len(value) > 8:
                            masked_value = value[:4] + '*' * (len(value) - 8) + value[-4:]
                        else:
                            masked_value = value[:2] + '*' * (len(value) - 2)
                        
                        category_findings.append({
                            'full_value': value,
                            'masked_value': masked_value,
                            'position': f"第{match.start()}字符附近"
                        })
            
            if category_findings:
                findings[category] = category_findings
        
        return findings

    def scan_website(self, url: str, output_file: str = None, max_js_files: int = 50):
        """主扫描函数"""
        print(f"[*] 开始扫描: {url}")
        print(f"[*] 认证状态: {'已认证' if self.session.cookies else '未认证'}")
        
        print("[*] 提取JS文件链接中...")
        js_links = self.extract_js_links(url)
        
        if not js_links:
            print("[-] 未找到JS文件链接")
            return
        
        # 限制扫描的JS文件数量
        if len(js_links) > max_js_files:
            print(f"[!] 发现 {len(js_links)} 个JS文件，限制扫描前 {max_js_files} 个")
            js_links = js_links[:max_js_files]
        
        all_findings = {}
        scanned_count = 0
        error_count = 0
        
        for i, js_url in enumerate(js_links, 1):
            print(f"\n[{i}/{len(js_links)}] 分析: {js_url}")
            
            content = self.fetch_js_content(js_url)
            if not content:
                error_count += 1
                continue
            
            scanned_count += 1
            findings = self.detect_sensitive_info(content)
            
            if findings:
                all_findings[js_url] = findings
                print(f"[!] 发现敏感信息!")
                for category, values in findings.items():
                    print(f"    {category.upper()}: {len(values)} 处")
            else:
                print("[+] 未发现敏感信息")
            
            time.sleep(0.5)
        
        # 输出扫描统计
        print(f"\n[*] 扫描完成: 成功扫描 {scanned_count}/{len(js_links)} 个JS文件")
        if error_count > 0:
            print(f"[-] 无法访问 {error_count} 个JS文件")
        
        # 输出结果
        self.print_results(all_findings, output_file)

    def print_results(self, findings: Dict, output_file: str = None):
        """打印和保存结果"""
        output_lines = []
        
        if not findings:
            print("\n[*] 扫描完成，未发现敏感信息")
            return
        
        print("\n" + "="*80)
        print("[!] 敏感信息检测报告")
        print("="*80)
        
        total_findings = sum(len(categories) for categories in findings.values())
        output_lines.append(f"总计发现敏感信息的JS文件: {len(findings)} 个")
        output_lines.append(f"总计敏感信息条目: {total_findings} 处\n")
        
        for js_url, categories in findings.items():
            output_lines.append(f"\nJS文件: {js_url}")
            output_lines.append("-" * 60)
            
            for category, values in categories.items():
                output_lines.append(f"\n{category.upper()} ({len(values)} 处):")
                for value_info in values:
                    output_lines.append(f"  - 位置: {value_info['position']}")
                    output_lines.append(f"    隐藏值: {value_info['masked_value']}")
                    output_lines.append(f"    完整值: {value_info['full_value']}")
            
            output_lines.append("\n")
        
        # 输出到控制台
        for line in output_lines:
            print(line)
        
        # 保存到文件
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write("\n".join(output_lines))
                print(f"\n[+] 结果已保存到: {output_file}")
            except Exception as e:
                print(f"[-] 保存文件失败: {e}")

    

def main():
    parser = argparse.ArgumentParser(description='JS敏感信息检测工具 - 支持认证扫描')
    parser.add_argument('url', help='要扫描的目标URL')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='请求超时时间(秒)')
    parser.add_argument('--user-agent', help='自定义User-Agent')
    parser.add_argument('--max-js-files', type=int, default=50, help='最大扫描JS文件数量')
    
    # 认证相关参数
    parser.add_argument('--cookies', help='Cookie字符串，格式: "name=value; name2=value2"')
    parser.add_argument('--cookies-file', help='Cookie文件路径(.json或.txt)')
    parser.add_argument('--auth-token', help='Bearer认证令牌')
    parser.add_argument('--headers-file', help='自定义请求头JSON文件')
    
    # 登录相关参数
    parser.add_argument('--login-url', help='登录页面URL')
    parser.add_argument('--username', help='登录用户名')
    parser.add_argument('--password', help='登录密码')
    parser.add_argument('--username-field', default='username', help='用户名表单字段名')
    parser.add_argument('--password-field', default='password', help='密码表单字段名')
    
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    # 处理请求头
    headers = {}
    if args.headers_file:
        try:
            with open(args.headers_file, 'r') as f:
                headers = json.load(f)
        except Exception as e:
            print(f"[-] 加载请求头文件失败: {e}")
            sys.exit(1)
    
    # 创建检测器实例
    detector = JSSensitiveInfoDetector(
        timeout=args.timeout,
        user_agent=args.user_agent,
        cookies=args.cookies,
        headers=headers,
        auth_token=args.auth_token
    )
    
    # 从文件加载Cookie
    if args.cookies_file:
        detector.load_cookies_from_file(args.cookies_file)
    
    # 执行登录
    if args.login_url and args.username and args.password:
        success = detector.login_with_credentials(
            args.login_url,
            args.username,
            args.password,
            args.username_field,
            args.password_field
        )
        if not success:
            print("[-] 登录失败，继续尝试扫描...")
    
    
    
    try:
        detector.scan_website(args.url, args.output, args.max_js_files)
    except KeyboardInterrupt:
        print("\n[!] 用户中断扫描")
        sys.exit(1)
    except Exception as e:
        print(f"[-] 扫描过程中出错: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()