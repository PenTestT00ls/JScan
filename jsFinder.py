#!/usr/bin/env python"
# coding: utf-8
# By Threezh1
# https://threezh1.github.io/

import requests, argparse, sys, re, json
from requests.packages import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import List, Dict, Tuple, Optional

class SmartSensitiveInfoDetector:
    """智能敏感信息检测器 - 解决误报问题"""
    
    def __init__(self):
        # 定义敏感信息模式，包含上下文验证
        self.sensitive_patterns = {
            'password': {
                'patterns': [
                    # 密码字段 - 需要验证后面跟着的是否是真正的密码值
                    r'password\s*[=:]\s*["\']([^"\']+)["\']',
                    r'pwd\s*[=:]\s*["\']([^"\']+)["\']',
                    r'pass\s*[=:]\s*["\']([^"\']+)["\']',
                    r'password\s*:\s*([^\s,]+)',
                    r'passwd\s*[=:]\s*["\']([^"\']+)["\']',
                    r'psw\s*[=:]\s*["\']([^"\']+)["\']',
                    r'login_password\s*[=:]\s*["\']([^"\']+)["\']',
                    r'user_password\s*[=:]\s*["\']([^"\']+)["\']',
                    r'admin_password\s*[=:]\s*["\']([^"\']+)["\']',
                ],
                'validator': self._validate_password
            },
            'api_key': {
                'patterns': [
                    r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
                    r'apikey\s*[=:]\s*["\']([^"\']+)["\']',
                    r'api[_-]?secret\s*[=:]\s*["\']([^"\']+)["\']',
                    r'app[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
                    r'app[_-]?secret\s*[=:]\s*["\']([^"\']+)["\']',
                    r'client[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
                    r'client[_-]?secret\s*[=:]\s*["\']([^"\']+)["\']',
                    r'service[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
                ],
                'validator': self._validate_api_key
            },
            'token': {
                'patterns': [
                    r'token\s*[=:]\s*["\']([^"\']+)["\']',
                    r'access[_-]?token\s*[=:]\s*["\']([^"\']+)["\']',
                    r'auth[_-]?token\s*[=:]\s*["\']([^"\']+)["\']',
                    r'refresh[_-]?token\s*[=:]\s*["\']([^"\']+)["\']',
                    r'bearer[_-]?token\s*[=:]\s*["\']([^"\']+)["\']',
                    r'session[_-]?token\s*[=:]\s*["\']([^"\']+)["\']',
                ],
                'validator': self._validate_token
            },
            'jwt': {
                'patterns': [
                    r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                    r'eyJhbGciOiJ[^\s\']+',
                ],
                'validator': self._validate_jwt
            },
            'aws_keys': {
                'patterns': [
                    r'AKIA[0-9A-Z]{16}',
                    r'aws[_-]?access[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
                    r'aws[_-]?secret[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
                ],
                'validator': self._validate_aws_key
            },
            'database_url': {
                'patterns': [
                    r'mongodb[+]srv://[^\s\'\"]+',
                    r'postgresql://[^\s\'\"]+',
                    r'mysql://[^\s\'\"]+',
                    r'redis://[^\s\'\"]+',
                    r'database[_-]?url\s*[=:]\s*["\']([^"\']+)["\']',
                ],
                'validator': self._validate_database_url
            }
        }
    
    def _validate_password(self, value: str, context: str) -> bool:
        """验证密码值是否真实"""
        # 排除常见的测试值、占位符和空值
        fake_passwords = ['', 'password', 'pass', 'pwd', '123456', 'test', 'demo', 
                         'changeme', 'admin', 'user', 'secret', 'none', 'null',
                         'undefined', '********', '******']
        
        if not value or len(value) < 3:
            return False
        
        if value.lower() in fake_passwords:
            return False
        
        # 检查是否是合理的密码格式（至少包含字母和数字，长度大于6）
        if len(value) >= 6 and (any(c.isalpha() for c in value) and any(c.isdigit() for c in value)):
            return True
        
        # 检查是否是哈希值（通常以$开头或包含特殊字符）
        if value.startswith('$') or any(c in value for c in ['$', '*', '@', '#']):
            return True
        
        return False
    
    def _validate_api_key(self, value: str, context: str) -> bool:
        """验证API密钥格式"""
        if not value or len(value) < 10:
            return False
        
        # API密钥通常较长且包含字母数字
        if len(value) >= 20 and any(c.isalpha() for c in value) and any(c.isdigit() for c in value):
            return True
        
        # 检查是否是已知的API密钥格式
        if re.match(r'^[a-zA-Z0-9_-]{20,}$', value):
            return True
        
        return False
    
    def _validate_token(self, value: str, context: str) -> bool:
        """验证令牌格式"""
        if not value or len(value) < 10:
            return False
        
        # 令牌通常较长
        if len(value) >= 20:
            return True
        
        # 检查是否是十六进制格式
        if re.match(r'^[a-fA-F0-9]{32,}$', value):
            return True
        
        return False
    
    def _validate_jwt(self, value: str, context: str) -> bool:
        """验证JWT格式"""
        # JWT格式验证
        parts = value.split('.')
        if len(parts) != 3:
            return False
        
        # 检查每个部分是否包含有效的base64字符
        import base64
        try:
            for part in parts:
                base64.urlsafe_b64decode(part + '===')
            return True
        except:
            return False
    
    def _validate_aws_key(self, value: str, context: str) -> bool:
        """验证AWS密钥格式"""
        # AWS访问密钥ID格式
        if re.match(r'^AKIA[0-9A-Z]{16}$', value):
            return True
        
        # AWS秘密访问密钥格式
        if len(value) >= 40 and any(c.isalpha() for c in value) and any(c.isdigit() for c in value):
            return True
        
        return False
    
    def _validate_database_url(self, value: str, context: str) -> bool:
        """验证数据库URL格式"""
        # 检查是否包含数据库连接信息
        if any(db in value.lower() for db in ['mongodb', 'postgresql', 'mysql', 'redis']):
            # 检查是否包含认证信息
            if '://' in value and ('@' in value or 'password' in value.lower()):
                return True
        
        return False
    
    def detect_sensitive_info(self, content: str) -> Dict[str, List[Dict]]:
        """检测敏感信息，包含上下文验证"""
        findings = {}
        
        for category, config in self.sensitive_patterns.items():
            category_findings = []
            
            for pattern in config['patterns']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    if match.groups():
                        value = match.group(1)
                    else:
                        value = match.group(0)
                    
                    # 获取匹配周围的上下文（前后50个字符）
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end]
                    
                    # 使用验证器检查是否是真正的敏感信息
                    if config['validator'](value, context):
                        # 计算行号
                        line_number = content[:match.start()].count('\n') + 1
                        
                        # 创建屏蔽值用于显示
                        if len(value) > 8:
                            masked_value = value[:4] + '*' * (len(value) - 8) + value[-4:]
                        else:
                            masked_value = value[:2] + '*' * (len(value) - 2)
                        
                        category_findings.append({
                            'full_value': value,
                            'masked_value': masked_value,
                            'line_number': line_number,
                            'position': match.start(),
                            'context': context.strip()
                        })
            
            if category_findings:
                findings[category] = category_findings
        
        return findings

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -u http://www.baidu.com -s")
    parser.add_argument("-u", "--url", help="The website")
    parser.add_argument("-c", "--cookie", help="The website cookie")
    parser.add_argument("-f", "--file", help="The file contains url or js")
    parser.add_argument("-ou", "--outputurl", help="Output file name. ")
    parser.add_argument("-os", "--outputsubdomain", help="Output file name. ")
    parser.add_argument("-j", "--js", help="Find in js file", action="store_true")
    parser.add_argument("-d", "--deep",help="Deep find", action="store_true")
    
    # 新增参数：敏感信息检测
    parser.add_argument("-s", "--sensitive", help="Enable sensitive information detection", action="store_true")
    parser.add_argument("--sensitive-output", help="Output file for sensitive information findings")
    parser.add_argument("--max-js-files", type=int, default=20, help="Maximum number of JS files to analyze for sensitive info")
    
    return parser.parse_args()

# Regular expression comes from https://github.com/GerbenJavado/LinkFinder
def extract_URL(JS):
	pattern_raw = r"""
	  (?:"|')                               # Start newline delimiter
	  (
	    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
	    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
	    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
	    |
	    ((?:/|\.\./|\./)                    # Start with /,../,./
	    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
	    [^"'><,;|()]{1,})                   # Rest of the characters can't be
	    |
	    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
	    [a-zA-Z0-9_\-/]{1,}                 # Resource name
	    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
	    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
	    |
	    ([a-zA-Z0-9_\-]{1,}                 # filename
	    \.(?:php|asp|aspx|jsp|json|
	         action|html|js|txt|xml)             # . + extension
	    (?:\?[^"|']{0,}|))                  # ? mark with parameters
	  )
	  (?:"|')                               # End newline delimiter
	"""
	pattern = re.compile(pattern_raw, re.VERBOSE)
	result = re.finditer(pattern, str(JS))
	if result == None:
		return None
	js_url = []
	return [match.group().strip('"').strip("'") for match in result
		if match.group() not in js_url]

# Get the page source
def Extract_html(URL):
	header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
	"Cookie": args.cookie}
	try:
		raw = requests.get(URL, headers = header, timeout=3, verify=False)
		raw = raw.content.decode("utf-8", "ignore")
		return raw
	except:
		return None

# Handling relative URLs
def process_url(URL, re_URL):
	black_url = ["javascript:"]	# Add some keyword for filter url.
	URL_raw = urlparse(URL)
	ab_URL = URL_raw.netloc
	host_URL = URL_raw.scheme
	if re_URL[0:2] == "//":
		result = host_URL  + ":" + re_URL
	elif re_URL[0:4] == "http":
		result = re_URL
	elif re_URL[0:2] != "//" and re_URL not in black_url:
		if re_URL[0:1] == "/":
			result = host_URL + "://" + ab_URL + re_URL
		else:
			if re_URL[0:1] == ".":
				if re_URL[0:2] == "..":
					result = host_URL + "://" + ab_URL + re_URL[2:]
				else:
					result = host_URL + "://" + ab_URL + re_URL[1:]
			else:
				result = host_URL + "://" + ab_URL + "/" + re_URL
	else:
		result = URL
	return result

def find_last(string,str):
	positions = []
	last_position=-1
	while True:
		position = string.find(str,last_position+1)
		if position == -1:break
		last_position = position
		positions.append(position)
	return positions

def find_by_url(url, js = False):
	if js == False:
		try:
			print("url:" + url)
		except:
			print("Please specify a URL like https://www.baidu.com")
		html_raw = Extract_html(url)
		if html_raw == None: 
			print("Fail to access " + url)
			return None
		#print(html_raw)
		html = BeautifulSoup(html_raw, "html.parser")
		html_scripts = html.findAll("script")
		script_array = {}
		script_temp = ""
		js_file_urls = []  # 新增：存储JavaScript文件URL
		for html_script in html_scripts:
			script_src = html_script.get("src")
			if script_src == None:
				script_temp += html_script.get_text() + "\n"
			else:
				purl = process_url(url, script_src)
				script_array[purl] = Extract_html(purl)
				# 新增：将JavaScript文件URL添加到结果中
				js_file_urls.append(purl)
		script_array[url] = script_temp
		allurls = []
		for script in script_array:
			#print(script)
			temp_urls = extract_URL(script_array[script])
			if len(temp_urls) == 0: continue
			for temp_url in temp_urls:
				allurls.append(process_url(script, temp_url)) 
		# 新增：将JavaScript文件URL添加到allurls中
		allurls.extend(js_file_urls)
		result = []
		for singerurl in allurls:
			url_raw = urlparse(url)
			domain = url_raw.netloc
			positions = find_last(domain, ".")
			miandomain = domain
			if len(positions) > 1:miandomain = domain[positions[-2] + 1:]
			#print(miandomain)
			suburl = urlparse(singerurl)
			subdomain = suburl.netloc
			#print(singerurl)
			if miandomain in subdomain or subdomain.strip() == "":
				if singerurl.strip() not in result:
					result.append(singerurl)
		return result
	return sorted(set(extract_URL(Extract_html(url)))) or None


def find_subdomain(urls, mainurl):
	url_raw = urlparse(mainurl)
	domain = url_raw.netloc
	miandomain = domain
	positions = find_last(domain, ".")
	if len(positions) > 1:miandomain = domain[positions[-2] + 1:]
	subdomains = []
	for url in urls:
		suburl = urlparse(url)
		subdomain = suburl.netloc
		#print(subdomain)
		if subdomain.strip() == "": continue
		if miandomain in subdomain:
			if subdomain not in subdomains:
				subdomains.append(subdomain)
	return subdomains

def find_by_url_deep(url):
	html_raw = Extract_html(url)
	if html_raw == None: 
		print("Fail to access " + url)
		return None
	html = BeautifulSoup(html_raw, "html.parser")
	html_as = html.findAll("a")
	links = []
	for html_a in html_as:
		src = html_a.get("href")
		if src == "" or src == None: continue
		link = process_url(url, src)
		if link not in links:
			links.append(link)
	if links == []: return None
	print("ALL Find " + str(len(links)) + " links")
	urls = []
	i = len(links)
	for link in links:
		temp_urls = find_by_url(link)
		if temp_urls == None: continue
		print("Remaining " + str(i) + " | Find " + str(len(temp_urls)) + " URL in " + link)
		for temp_url in temp_urls:
			if temp_url not in urls:
				urls.append(temp_url)
		i -= 1
	return urls

	
def find_by_file(file_path, js=False):
	with open(file_path, "r") as fobject:
		links = fobject.read().split("\n")
	if links == []: return None
	print("ALL Find " + str(len(links)) + " links")
	urls = []
	i = len(links)
	for link in links:
		if js == False:
			temp_urls = find_by_url(link)
		else:
			temp_urls = find_by_url(link, js=True)
		if temp_urls == None: continue
		print(str(i) + " Find " + str(len(temp_urls)) + " URL in " + link)
		for temp_url in temp_urls:
			if temp_url not in urls:
				urls.append(temp_url)
		i -= 1
	
	# 如果启用了敏感信息检测且没有找到URL，但文件包含JS文件链接，直接返回这些链接
	if args.sensitive and not urls:
		js_urls = []
		for link in links:
			if link.strip() and (link.lower().endswith('.js') or '.js?' in link.lower()):
				js_urls.append(link.strip())
		if js_urls:
			print(f"[+] 发现 {len(js_urls)} 个JS文件链接，直接用于敏感信息检测")
			return js_urls
	
	return urls

def giveresult(urls, domian):
	if urls == None:
		return None
	print("Find " + str(len(urls)) + " URL:")
	content_url = ""
	content_subdomain = ""
	for url in urls:
		content_url += url + "\n"
		print(url)
	subdomains = find_subdomain(urls, domian)
	print("\nFind " + str(len(subdomains)) + " Subdomain:")
	for subdomain in subdomains:
		content_subdomain += subdomain + "\n"
		print(subdomain)
	if args.outputurl != None:
		with open(args.outputurl, "a", encoding='utf-8') as fobject:
			fobject.write(content_url)
		print("\nOutput " + str(len(urls)) + " urls")
		print("Path:" + args.outputurl)
	if args.outputsubdomain != None:
		with open(args.outputsubdomain, "a", encoding='utf-8') as fobject:
			fobject.write(content_subdomain)
		print("\nOutput " + str(len(subdomains)) + " subdomains")
		print("Path:" + args.outputsubdomain)

	# 如果启用了敏感信息检测，执行敏感信息扫描
	if args.sensitive:
		print("\n" + "="*60)
		print("开始敏感信息检测...")
		print("="*60)
		sensitive_scan(urls)

def sensitive_scan(urls):
	"""执行敏感信息检测"""
	detector = SmartSensitiveInfoDetector()
	all_findings = {}
	js_urls = []
	
	# 从URL列表中筛选出JS文件
	for url in urls:
		if url.lower().endswith('.js') or '.js?' in url.lower():
			js_urls.append(url)
	
	if not js_urls:
		print("[-] 未发现JS文件，无法进行敏感信息检测")
		return
	
	print(f"[+] 发现 {len(js_urls)} 个JS文件，开始敏感信息检测...")
	
	# 限制扫描的JS文件数量
	if len(js_urls) > args.max_js_files:
		print(f"[!] JS文件数量超过限制，仅扫描前 {args.max_js_files} 个文件")
		js_urls = js_urls[:args.max_js_files]
	
	# 扫描每个JS文件
	for i, js_url in enumerate(js_urls, 1):
		print(f"\n[{i}/{len(js_urls)}] 分析JS文件: {js_url}")
		
		try:
			# 获取JS文件内容
			headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
			if args.cookie:
				headers["Cookie"] = args.cookie
			
			response = requests.get(js_url, headers=headers, timeout=10, verify=False)
			if response.status_code != 200:
				print(f"[-] 无法访问JS文件: HTTP {response.status_code}")
				continue
			
			js_content = response.text
			if len(js_content) < 100:
				print("[-] JS文件内容过短，跳过检测")
				continue
			
			# 检测敏感信息
			findings = detector.detect_sensitive_info(js_content)
			
			if findings:
				all_findings[js_url] = findings
				print(f"[!] 发现敏感信息!")
				for category, values in findings.items():
					print(f"    {category.upper()}: {len(values)} 处")
			else:
				print("[+] 未发现敏感信息")
			
		except Exception as e:
			print(f"[-] 分析JS文件时出错: {e}")
			continue
	
	# 输出敏感信息检测结果
	if all_findings:
		print_sensitive_results(all_findings)
	else:
		print("\n[*] 敏感信息检测完成，未发现敏感信息")

def print_sensitive_results(all_findings):
	"""打印敏感信息检测结果"""
	print("\n" + "="*80)
	print("[!] 敏感信息检测报告")
	print("="*80)
	
	total_files = len(all_findings)
	total_findings = sum(len(categories) for categories in all_findings.values())
	
	print(f"总计发现敏感信息的JS文件: {total_files} 个")
	print(f"总计敏感信息条目: {total_findings} 处\n")
	
	output_lines = []
	
	for js_url, categories in all_findings.items():
		output_lines.append(f"\nJS文件: {js_url}")
		output_lines.append("-" * 60)
		
		for category, values in categories.items():
			output_lines.append(f"\n{category.upper()} ({len(values)} 处):")
			for value_info in values:
				output_lines.append(f"  - 行号: {value_info['line_number']}")
				output_lines.append(f"    隐藏值: {value_info['masked_value']}")
				output_lines.append(f"    完整值: {value_info['full_value']}")
				output_lines.append(f"    上下文: {value_info['context'][:100]}...")
				output_lines.append("")
		
		output_lines.append("\n")
	
	# 输出到控制台
	for line in output_lines:
		print(line)
	
	# 保存到文件
	if args.sensitive_output:
		try:
			with open(args.sensitive_output, 'w', encoding='utf-8') as f:
				f.write("\n".join(output_lines))
			print(f"\n[+] 敏感信息检测结果已保存到: {args.sensitive_output}")
		except Exception as e:
			print(f"[-] 保存敏感信息检测结果失败: {e}")

if __name__ == "__main__":
	urllib3.disable_warnings()
	args = parse_args()
	if args.file == None:
		if args.deep is not True:
			urls = find_by_url(args.url)
			giveresult(urls, args.url)
		else:
			urls = find_by_url_deep(args.url)
			giveresult(urls, args.url)
	else:
		if args.js is not True:
			urls = find_by_file(args.file)
			if urls:
				giveresult(urls, urls[0])
			else:
				print("[-] 未发现任何URL")
		else:
			urls = find_by_file(args.file, js = True)
			if urls:
				giveresult(urls, urls[0])
			else:
				print("[-] 未发现任何URL")
