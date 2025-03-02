<h1 id="avu4T">Webshell： </h1>
蚁剑 v2.1.25  冰蝎 3/4/魔改  cs v4.7  哥斯拉 v4.0.1

<h1 id="BH31Y">信息收集工具：</h1>
<h3 id="yCmPC">DirSearch魔改 v0.4.3 </h3>
项目地址：[https://github.com/maurosoria/dirsearch](https://github.com/maurosoria/dirsearch)

> Web 路径扫描仪
>

使用时候可以自动安装未配置的模块`pip install -r requirements.txt`

```plain
用法: dirsearch.py [-u|--url] 目标 [-e|--extensions] 扩展名 [选项]

选项:
  --version             显示程序版本号并退出
  -h, --help            显示帮助信息并退出

  必选项:
    -u URL, --url=URL   目标 URL，可以使用多个标志
    -l PATH, --urls-file=PATH
                        URL 列表文件
    --stdin             从标准输入读取 URL
    --cidr=CIDR         目标 CIDR
    --raw=PATH          从文件加载原始 HTTP 请求 (使用 '--scheme' 标志设置方案)
    --nmap-report=PATH  从 nmap 报告加载目标 (确保在 nmap 扫描时使用 -sV 标志以获取全面结果)
    -s SESSION_FILE, --session=SESSION_FILE
                        会话文件
    --config=PATH       配置文件路径 (默认: 'DIRSEARCH_CONFIG' 环境变量，若不存在则为 'config.ini')

  字典设置:
    -w WORDLISTS, --wordlists=WORDLISTS
                        字典文件或包含字典的目录（用逗号分隔）
    -e EXTENSIONS, --extensions=EXTENSIONS
                        扩展名列表，用逗号分隔 (例如: php,asp)
    -f, --force-extensions
                        将扩展名添加到每个字典条目的末尾。默认情况下，dirsearch 只会将 %EXT% 关键字替换为扩展名
    -O, --overwrite-extensions
                        用你选择的扩展名覆盖字典中的其他扩展名 (通过 `-e` 选择)
    --exclude-extensions=EXTENSIONS
                        排除扩展名列表，用逗号分隔 (例如: asp,jsp)
    --remove-extensions
                        移除路径中的扩展名 (例如: admin.php -> admin)
    --prefixes=PREFIXES
                        在所有字典条目前添加自定义前缀，用逗号分隔
    --suffixes=SUFFIXES
                        在所有字典条目后添加自定义后缀，忽略目录（用逗号分隔）
    -U, --uppercase     大写字典
    -L, --lowercase     小写字典
    -C, --capital       首字母大写字典

  一般设置:
    -t THREADS, --threads=THREADS
                        线程数
    --async             启用异步模式
    -r, --recursive     递归暴力破解
    --deep-recursive    对每个目录深度执行递归扫描 (例如: api/users -> api/)
    --force-recursive   对每个找到的路径进行递归暴力破解，而不仅仅是目录
    -R DEPTH, --max-recursion-depth=DEPTH
                        最大递归深度
    --recursion-status=CODES
                        执行递归扫描的有效状态码，支持范围（用逗号分隔）
    --subdirs=SUBDIRS   扫描给定 URL 的子目录（用逗号分隔）
    --exclude-subdirs=SUBDIRS
                        排除递归扫描中的指定子目录（用逗号分隔）
    -i CODES, --include-status=CODES
                        包含的状态码，用逗号分隔，支持范围（例如: 200,300-399）
    -x CODES, --exclude-status=CODES
                        排除的状态码，支持范围（例如: 301,500-599）
    --exclude-sizes=SIZES
                        排除响应大小，支持用逗号分隔（例如: 0B,4KB）
    --exclude-text=TEXTS
                        排除响应的文本，可以使用多个标志
    --exclude-regex=REGEX
                        排除匹配正则表达式的响应
    --exclude-redirect=STRING
                        如果重定向 URL 匹配该正则表达式（或文本），则排除响应（例如: '/index.html'）
    --exclude-response=PATH
                        排除与该页面响应相似的响应，路径作为输入（例如: 404.html）
    --skip-on-status=CODES
                        遇到这些状态码时跳过目标，支持范围
    --min-response-size=LENGTH
                        最小响应长度
    --max-response-size=LENGTH
                        最大响应长度
    --max-time=SECONDS  扫描的最大运行时间
    --exit-on-error     遇到错误时退出

  请求设置:
    -m METHOD, --http-method=METHOD
                        HTTP 请求方法 (默认: GET)
    -d DATA, --data=DATA
                        HTTP 请求数据
    --data-file=PATH    包含 HTTP 请求数据的文件
    -H HEADERS, --header=HEADERS
                        HTTP 请求头，可以使用多个标志
    --headers-file=PATH
                        包含 HTTP 请求头的文件
    -F, --follow-redirects
                        跟踪 HTTP 重定向
    --random-agent      为每个请求选择一个随机 User-Agent
    --auth=CREDENTIAL   认证凭证（例如: 用户名:密码 或 Bearer Token）
    --auth-type=TYPE    认证类型（basic, digest, bearer, ntlm, jwt）
    --cert-file=PATH    客户端证书文件
    --key-file=PATH     客户端证书私钥文件（未加密）
    --user-agent=USER_AGENT
                        自定义用户代理
    --cookie=COOKIE     自定义 Cookie

  连接设置:
    --timeout=TIMEOUT   连接超时
    --delay=DELAY       请求之间的延迟
    -p PROXY, --proxy=PROXY
                        代理 URL (HTTP/SOCKS)，可以使用多个标志
    --proxies-file=PATH
                        包含代理服务器的文件
    --proxy-auth=CREDENTIAL
                        代理认证凭证
    --replay-proxy=PROXY
                        使用找到的路径重放的代理
    --tor               使用 Tor 网络作为代理
    --scheme=SCHEME     如果 URL 中没有方案，或者是原始请求，使用该方案（默认: 自动检测）
    --max-rate=RATE     每秒最大请求数
    --retries=RETRIES   请求失败时的重试次数
    --ip=IP             服务器 IP 地址
    --interface=NETWORK_INTERFACE
                        使用的网络接口

  高级设置:
    --crawl             在响应中爬取新路径

  输出设置:
    --full-url          输出完整的 URL（在安静模式下自动启用）
    --redirects-history
                        显示重定向历史
    --no-color          无颜色输出
    -q, --quiet-mode    安静模式

  输出设置:
    -o PATH/URL, --output=PATH/URL
                        输出文件或 MySQL/PostgreSQL URL（格式: scheme://[用户名:密码@]主机[:端口]/数据库名）
    --format=FORMAT     报告格式（可用格式: simple, plain, json, xml, md, csv, html, sqlite, mysql, postgresql）
    --log=PATH          日志文件

```

<h3 id="JelKV">one for all v0.4.5</h3>
项目地址：[https://github.com/shmilylty/OneForAll](https://github.com/shmilylty/OneForAll)

> OneForAll是一款功能强大的子域收集工具
>

```plain
NAME
    oneforall.py - OneForAll帮助信息

SYNOPSIS
    oneforall.py COMMAND | --target=TARGET <flags>

DESCRIPTION
    OneForAll是一款功能强大的子域收集工具

    Example:
        python3 oneforall.py version
        python3 oneforall.py --target example.com run
        python3 oneforall.py --target ./domains.txt run
        python3 oneforall.py --target example.com --valid None run
        python3 oneforall.py --target example.com --brute True run
        python3 oneforall.py --target example.com --port small run
        python3 oneforall.py --target example.com --format csv run
        python3 oneforall.py --target example.com --dns False run
        python3 oneforall.py --target example.com --req False run
        python3 oneforall.py --target example.com --takeover False run
        python3 oneforall.py --target example.com --show True run

    Note:
        参数alive可选值True，False分别表示导出存活，全部子域结果
        参数port可选值有'default', 'small', 'large', 详见config.py配置
        参数format可选格式有'rst', 'csv', 'tsv', 'json', 'yaml', 'html',
                          'jira', 'xls', 'xlsx', 'dbf', 'latex', 'ods'
        参数path默认None使用OneForAll结果目录生成路径

ARGUMENTS
    TARGET
        单个域名或者每行一个域名的文件路径(必需参数)

FLAGS
    --brute=BRUTE
        使用爆破模块(默认False)
    --dns=DNS
        DNS解析子域(默认True)
    --req=REQ
        HTTP请求子域(默认True)
    --port=PORT
        请求验证子域的端口范围(默认只探测80端口)
    --valid=VALID
        只导出存活的子域结果(默认False)
    --format=FORMAT
        结果保存格式(默认csv)
    --path=PATH
        结果保存路径(默认None)
    --takeover=TAKEOVER
        检查子域接管(默认False)
```

<h3 id="WKokP">dddd v2.0.1</h3>
项目地址：[https://github.com/SleepingBag945/dddd](https://github.com/SleepingBag945/dddd)

> dddd是一款使用简单的批量信息收集,供应链漏洞探测工具，旨在优化红队工作流，减少伤肝的机械性操作。支持从Hunter、Fofa批量拉取目标
>

```plain
     _       _       _       _
  __| |   __| |   __| |   __| |
 / _` |  / _ `|  / _` |  / _` |
 \__,_|  \__,_|  \__,_|  \__,_|
_|"""""|_|"""""|_|"""""|_|"""""|
"`-0-0-'"`-0-0-'"`-0-0-`"`-0-0-'
dddd.version: 2.0.1

dddd是一款使用简单的批量信息收集,供应链漏洞探测工具。旨在优化红队工作流，减少伤肝、枯燥、乏味的机械性操作。

Usage:
  dddd64.exe [flags]

Flags:
扫描目标:
   -t, -target string  被扫描的目标。 192.168.0.1 192.168.0.0/16 192.168.0.1:80 baidu.com:80 file.txt(一行一个) result.txt(fscan/dddd)

端口扫描:
   -p, -port string              端口设置。 默认扫描Top1000
   -st, -scan-type string        端口扫描方式 | "-st tcp"设置TCP扫描 | "-st syn"设置SYN扫描 (default "tcp")
   -tst, -tcp-scan-threads int   TCP扫描线程 | Windows/Mac默认1000线程 Linux默认4000 (default 1000)
   -sst, -syn-scan-threads int   SYN扫描线程 (default 10000)
   -mp, -masscan-path string     指定masscan程序路径 | SYN扫描依赖 (default "masscan")
   -pmc, -ports-max-count int    IP端口数量阈值 | 当一个IP的端口数量超过此值，此IP将会被抛弃 (default 300)
   -pst, -port-scan-timeout int  TCP端口扫描超时(秒) (default 6)

主机发现:
   -Pn                  禁用主机发现功能(icmp,tcp)
   -nip, -no-icmp-ping  当启用主机发现功能时，禁用ICMP主机发现功能
   -tp, -tcp-ping       当启用主机发现功能时，启用TCP主机发现功能

协议识别:
   -tc, -nmap-threads int   Nmap协议识别线程 (default 500)
   -nto, -nmap-timeout int  Nmap协议识别超时时间(秒) (default 5)

探索子域名:
   -sd, -subdomain                     开启子域名枚举，默认关闭
   -nsb, -no-subdomain-brute           关闭子域名爆破
   -ns, -no-subfinder                  关闭被动子域名枚举
   -sbt, -subdomain-brute-threads int  子域名爆破线程数量 (default 150)
   -ld, -local-domain                  允许域名解析到局域网
   -ac, -allow-cdn                     允许扫描带CDN的资产 | 默认略过
   -nhb, -no-host-bind                 禁用域名绑定资产探测

WEB探针配置:
   -wt, -web-threads int   Web探针线程,根据网络环境调整 (default 200)
   -wto, -web-timeout int  Web探针超时时间,根据网络环境调整 (default 10)
   -nd, -no-dir            关闭主动Web指纹探测

HTTP代理配置:
   -proxy string                 HTTP代理
   -pt, -proxy-test              启动前测试HTTP代理 (default true)
   -ptu, -proxy-test-url string  测试HTTP代理的url，需要url返回200 (default "https://www.baidu.com")

网络空间搜索引擎:
   -hunter                            从hunter中获取资产,开启此选项后-t参数变更为需要在hunter中搜索的关键词
   -hps, -hunter-page-size int        Hunter查询每页资产条数 (default 100)
   -hmpc, -hunter-max-page-count int  Hunter 最大查询页数 (default 10)
   -lpm, -low-perception-mode         Hunter低感知模式 | 从Hunter直接取响应判断指纹，直接进入漏洞扫描阶段
   -oip                               从网络空间搜索引擎中以IP:Port的形式拉取资产，而不是Domain(IP):Port
   -fofa                              从Fofa中获取资产,开启此选项后-t参数变更为需要在fofa中搜索的关键词
   -fmc, -fofa-max-count int          Fofa 查询资产条数 Max:10000 (default 100)
   -quake                             从Quake中获取资产,开启此选项后-t参数变更为需要在quake中搜索的关键词
   -qmc, -quake-max-count int         Quake 查询资产条数 (default 100)

输出:
   -o, -output string        结果输出文件 (default "result.txt")
   -ot, -output-type string  结果输出格式 text,json (default "text")
   -ho, -html-output string  html漏洞报告的名称

漏洞探测:
   -npoc                          关闭漏洞探测,只进行信息收集
   -poc, -poc-name string         模糊匹配Poc名称
   -ni, -no-interactsh            禁用Interactsh服务器，排除反连模版
   -gpt, -golang-poc-threads int  GoPoc运行线程 (default 50)
   -ngp, -no-golang-poc           关闭Golang Poc探测
   -dgp, -disable-general-poc     禁用无视指纹的漏洞映射
   -et, -exclude-tags string      通过tags排除模版 | 多个tags请用,连接
   -s, -severity string           只允许指定严重程度的模板运行 | 多参数用,连接 | 允许的值: info,low,medium,high,critical,unknown

配置文件:
   -acf, -api-config-file string      API配置文件 (default "config/api-config.yaml")
   -nt, -nuclei-template string       指定存放Nuclei Poc的文件夹路径 (default "config/pocs")
   -wy, -workflow-yaml string         指定存放workflow.yaml (指纹=>漏洞映射) 的路径 (default "config/workflow.yaml")
   -fy, -finger-yaml string           指定存放finger.yaml (指纹配置) 的路径 (default "config/finger.yaml")
   -dy, -dir-yaml string              主动指纹数据库路径 (default "config/dir.yaml")
   -swl, -subdomain-word-list string  子域名字典文件路径 (default "config/subdomains.txt")

爆破密码配置:
   -up, -username-password string        设置爆破凭证，设置后将禁用内置字典 | 凭证格式 'admin : password'
   -upf, -username-password-file string  设置爆破凭证文件(一行一个)，设置后将禁用内置字典 | 凭证格式 'admin : password'

审计日志 | 敏感环境必备:
   -a                                开启审计日志，记录程序运行日志，收发包详细信息，避免背黑锅。
   -alf, -audit-log-filename string  审计日志文件名称 (default "audit.log")
```

<h3 id="ThQsT">Layer v5.0（子域名挖掘机）</h3>
项目地址：[https://github.com/euphrat1ca/LayerDomainFinder](https://github.com/euphrat1ca/LayerDomainFinder)

<h3 id="gCD2o">EHole 3.1</h3>
项目地址：[https://github.com/EdgeSecurityTeam/EHole](https://github.com/EdgeSecurityTeam/EHole)

> EHole是一款对资产中重点系统指纹识别的工具，在红队作战中，信息收集是必不可少的环节，如何才能从大量的资产中提取有用的系统(如OA、VPN、Weblogic...)。EHole旨在帮助红队人员在信息收集期间能够快速从C段、大量杂乱的资产中精准定位到易被攻击的系统，从而实施进一步攻击。
>

```plain
     ______    __         ______
    / ____/___/ /___ ____/_  __/__  ____ _____ ___
   / __/ / __  / __ `/ _ \/ / / _ \/ __ `/ __ `__ \
  / /___/ /_/ / /_/ /  __/ / /  __/ /_/ / / / / / /
 /_____/\__,_/\__, /\___/_/  \___/\__,_/_/ /_/ /_/ v3.1
                         /____/ https://forum.ywhack.com  By:shihuang

    EHole是一款对资产中重点系统指纹识别的工具，在红队作战中，信息收集
是必不可少的环节，如何才能从大量的资产中提取有用的系统(如OA、VPN、Web
logic...)。EHole旨在帮助红队人员在信息收集期间能够快速从C段、大量杂乱
的资产中精准定位到易被攻击的系统，从而实施进一步攻击。

Usage:
  ehole [command]

Available Commands:
  finger      ehole的指纹识别模块
  fofaext     ehole的fofa提取模块
  help        Help about any command

Flags:
      --config string   config file (default is $HOME/.ehole.yaml)
  -h, --help            help for ehole
  -t, --toggle          Help message for toggle
```

<h3 id="nlofw">URlfinder</h3>
项目地址：[https://github.com/pingc0y/URLFinder](https://github.com/pingc0y/URLFinder)

> URLFinder是一款快速、全面、易用的页面信息提取工具用于分析页面中的js与url,查找隐藏在其中的敏感信息或未授权api接口
>

```plain
         __   __   ___ _           _
 /\ /\  /__\ / /  / __(_)_ __   __| | ___ _ __
/ / \ \/ \/// /  / _\ | | '_ \ / _` |/ _ \ '__|
\ \_/ / _  \ /___ /   | | | | | (_| |  __/ |
 \___/\/ \_\____\/    |_|_| |_|\__,_|\___|_|

By: pingc0y
Update: 2023.9.9 | 已是最新版本
Github: https://github.com/pingc0y/URLFinder

Usage: URLFinder [-a user-agent] [-b baseurl] [-c cookie] [-d domainName] [-f urlFile] [-ff urlFile one]  [-h help]  [-i configFile]  [-m mode] [-max maximum] [-o outFile]  [-s Status] [-t thread] [-time timeout] [-u url] [-x proxy] [-z fuzz]

Options:
  -a string
        set user-agent
        设置user-agent请求头
  -b string
        set baseurl
        设置baseurl路径
  -c string
        set cookie
        设置cookie
  -d string
        set domainName
        指定获取的域名,支持正则表达式
  -f string
        set urlFile
        批量抓取url,指定文件路径
  -ff string
        set urlFile one
        与-f区别：全部抓取的数据,视为同一个url的结果来处理（只打印一份结果 | 只会输出一份结果）
  -h    this help
        帮助信息
  -i    set configFile
        加载yaml配置文件（不存在时,会在当前目录创建一个默认yaml配置文件）
  -m int
        set mode
        抓取模式
           1 normal
             正常抓取（默认）
           2 thorough
             深入抓取（默认url深入一层,js深入三层,-i可以自定义）
           3 security
             安全深入抓取（过滤delete,remove等敏感路由.-i可自定义）  (default 1)
  -max int
        set maximum
        最大抓取链接数 (default 99999)
  -o string
        set outFile
        结果导出到csv、json、html文件,需指定导出文件目录,可填写完整文件名只导出一种类型（.代表当前目录）
  -s string
        set Status
        显示指定状态码,all为显示全部（多个状态码用,隔开）
  -t int
        set Thread
        设置线程数（默认50） (default 50)
  -time int
        set Timeout
        设置超时时间（默认5,单位秒） (default 5)
  -u string
        set Url
        目标URL
  -x string
        set Proxy
        设置代理,格式: http://username:password@127.0.0.1:8809
  -z int
        set Fuzz
        对404链接进行fuzz(只对主域名下的链接生效,需要与 -s 一起使用）
           1 decreasing
             目录递减fuzz
           2 2combination
             2级目录组合fuzz（适合少量链接使用）
           3 3combination
             3级目录组合fuzz（适合少量链接使用）
```

<h3 id="wi19q">Search_Viewer_V4.2</h3>
项目地址：[https://github.com/G3et/Search_Viewer](https://github.com/G3et/Search_Viewer)

<h3 id="w0qnI">Golin </h3>
项目地址：[https://github.com/selinuxG/Golin](https://github.com/selinuxG/Golin)

> 主机存活探测、漏洞扫描、子域名扫描、端口扫描、各类服务数据库爆破、poc扫描、xss扫描、webtitle探测、web指纹识别、web敏感信息泄露、web目录浏览、web文件下载、等保安全风险问题风险自查等； 弱口令/未授权访问：40余种； WEB组件识别：300余种； 漏洞扫描：XSS、任意文件访问、任意命令执行、敏感信息泄露、默认账户密码...； 资产扫描：扫描存活主机->判断存活端口->识别协议/组件->基于组件协议进行弱口令、漏洞扫描->输出报告； 键盘记录器。
>

<h3 id="xHn9N">enscan v1.1.1</h3>
项目地址：[https://github.com/wgpsec/ENScan_GO](https://github.com/wgpsec/ENScan_GO)

```plain

███████╗███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
█████╗  ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
██╔══╝  ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

Built At: 2024-12-24 08:28:18 +0000
Go Version: go1.22.1 linux/amd64
Author: keac
Build SHA: d345c9dedeaa047b58c6a1fad4d21c5e2be153a2
Version: v1.1.1

https://github.com/wgpsec/ENScan_GO

工具仅用于信息收集，请勿用于非法用途
开发人员不承担任何责任，也不对任何滥用或损坏负责.
Usage of enscan-v1.1.1-windows-amd64.exe:
  -api
        API模式运行
  -branch
        查询分支机构（分公司）信息
  -branch-filter string
        提供一个正则表达式，名称匹配该正则的分支机构和子公司会被跳过
  -debug
        是否显示debug详细信息
  -deep int
        递归搜索n层公司 (default 1)
  -delay int
        每个请求延迟（S）-1为随机延迟1-5S
  -f string
        批量查询，文本按行分隔
  -field string
        获取字段信息 eg icp
  -hold
        是否查询控股公司
  -i string
        公司PID
  -invest float
        投资比例 eg 100
  -is-branch
        深度查询分支机构信息（数量巨大）
  -is-group
        查询关键词为集团
  -is-pid
        批量查询文件是否为公司PID
  -is-show
        是否展示信息输出 (default true)
  -json
        json导出
  -n string
        关键词 eg 小米
  -no-merge
        开启后查询文件将单独导出
  -out-dir string
        结果输出的文件夹位置(默认为outs)
  -out-type string
        导出的文件后缀 默认xlsx (default "xlsx")
  -out-update string
        导出指定范围文件，自更新
  -proxy string
        设置代理
  -supplier
        是否查询供应商信息
  -timeout int
        每个请求默认1（分钟）超时 (default 1)
  -type string
        查询渠道，可多选 (default "aqc")
  -v    版本信息
```

<h1 id="qebhJ">漏洞检测工具：</h1>
<h3 id="lzXEn">OA漏洞利用工具</h3>
项目地址：[https://github.com/R4gd0ll/I-Wanna-Get-All](https://github.com/R4gd0ll/I-Wanna-Get-All)

> 集成漏洞系统包括：用友、泛微、蓝凌、万户、致远、通达、帆软、金蝶、金和、红帆、宏景、浪潮、普元、亿赛通、海康威视、飞企互联、大华DSS、jeecg-boot集成memshell功能：用友NC、用友U8C、亿赛通、帆软channel、jeecgboot注入内存马。目前集成385漏洞，包括nday、1day（未公开poc）
>

<h3 id="bit6Y">Exp-Tools_v1.3.1(OA综合)</h3>
项目地址：[https://github.com/cseroad/Exp-Tools](https://github.com/cseroad/Exp-Tools)

> 该工具使用了ExpDemo-JavaFX项目，保留了核心的数据包请求接口，使用jdk1.8环境开发。目前编写了oa、设备、框架、产品等多个系列，对相关漏洞进行复现和分析，极力避免exp的误报和有效性。截止到目前为止，已实现了用友、泛微、蓝凌、万户、帆软报表、致远、通达、红帆、金和、金蝶、广联达、华天动力总共12个OA。 全部是命令执行、文件上传类的漏洞，包括前台和后台。
>
> java -javaagent:Exp-Tools-1.3.1-encrypted.jar -jar Exp-Tools-1.3.1-encrypted.jar
>

<h3 id="zQ6Gp">ShiroAttack4.7</h3>
项目地址：[https://github.com/SummerSec/ShiroAttack2](https://github.com/SummerSec/ShiroAttack2)、

> shiro反序列化漏洞综合利用,包含（回显执行命令/注入内存马）修复原版中NoCC的问题
>

<h3 id="YSOns">WeblogicTool1.3</h3>
项目地址：[https://github.com/KimJun1010/WeblogicTool](https://github.com/KimJun1010/WeblogicTool)



> WeblogicTool，GUI漏洞利用工具，支持漏洞检测、命令执行、内存马注入、密码解密等（深信服深蓝实验室天威战队强力驱动）
>

<h3 id="iCsum">SpringBoot</h3>
项目地址：[https://github.com/AabyssZG/SpringBoot-Scan](https://github.com/AabyssZG/SpringBoot-Scan)

> 针对SpringBoot的开源渗透框架，以及Spring相关高危漏洞利用工具
>

<h3 id="ciQPF">thinkphp_gui_tools-2.4.2</h3>
项目地址：[https://github.com/bewhale/thinkphp_gui_tools](https://github.com/bewhale/thinkphp_gui_tools)

> ThinkPHP漏洞综合利用工具, 图形化界面, 命令执行, 一键getshell, 批量检测, 日志遍历, session包含,宝塔绕过
>

<h3 id="MX8jx">heapdump_tool</h3>
项目地址：[https://github.com/wyzxxz/heapdump_tool](https://github.com/wyzxxz/heapdump_tool)

> heapdump敏感信息查询工具，例如查找 spring heapdump中的密码明文，AK,SK等
>

<h3 id="VkuyW">Struts2全版本漏洞检测工具19.32</h3>
项目地址：[https://github.com/abc123info/Struts2VulsScanTools](https://github.com/abc123info/Struts2VulsScanTools)

> About1、点击“检测漏洞”，会自动检测该URL是否存在S2-001、S2-005、S2-009、S2-013、S2-016、S2-019、S2-020/021、S2-032、S2-037、DevMode、S2-045/046、S2-052、S2-048、S2-053、S2-057、S2-061、S2相关log4j2十余种漏洞。
>
>  2、“批量验证”，（为防止批量geshell，此功能已经删除，并不再开发）。 
>
> 3、S2-020、S2-021仅提供漏洞扫描功能，因漏洞利用exp很大几率造成网站访问异常，本程序暂不提供。
>
>  4、对于需要登录的页面，请勾选“设置全局Cookie值”，并填好相应的Cookie，程序每次发包都会带上Cookie。 5、作者对不同的struts2漏洞测试语句做了大量修改，执行
>

<h3 id="crJTA">hyacinth-v2.0(java框架漏洞检测)</h3>
项目地址：[https://github.com/pureqh/Hyacinth](https://github.com/pureqh/Hyacinth)

> 其中包含Struts2、Fastjson、Weblogic（xml）、Shiro、Log4j、Jboss、SpringCloud、等漏洞检测利用模块，及免杀webshell生成模块 Bypass、以及一些小工具模块等，由于图形化比较简明易懂，所以也不需要使用说明吧 。本项目的部分payload进行了一些混淆，具备一定过waf能力，有空会更新所有的payload
>

<h3 id="RC5rk">hikvisionv</h3>
项目地址：[https://github.com/MInggongK/Hikvision-](https://github.com/MInggongK/Hikvision-)

> Hikvision综合漏洞利用工具
>

<h3 id="yrLrm">dahua</h3>
项目地址：[https://github.com/lz520520/railgun](https://github.com/lz520520/railgun)

> dahua综合漏洞利用工具
>

<h3 id="Nhztz">ruoyi_vulnscan</h3>
项目地址：[https://github.com/steveopen1/ruoyi_vulnscan](https://github.com/steveopen1/ruoyi_vulnscan)

> ruuoyi_vulnscan 是一款基于 Python 和 Tkinter 开发的图形化界面工具，用于检测若依 Vue 框架应用程序中的常见漏洞。该工具提供了多种漏洞检测模块，包括 Swagger 检测、Druid 检测、文件下载漏洞检测、SQL 注入检测、定时任务漏洞检测和任意密码修改漏洞检测等，同时支持全面检测和扫描停止、结果清空等操作。
>

<h3 id="c83hi">SpringExploitGUI_v1.4</h3>
项目地址：[https://github.com/charonlight/SpringExploitGUI](https://github.com/charonlight/SpringExploitGUI)

> 一款Spring综合漏洞的利用工具，工具支持多个Spring相关漏洞的检测以及利用
>

<h3 id="vwQgo">TomcatPass</h3>
项目地址：[https://github.com/tpt11fb/AttackTomcat](https://github.com/tpt11fb/AttackTomcat)

> Tomcat常见漏洞GUI利用工具。CVE-2017-12615 PUT文件上传漏洞、tomcat-pass-getshell 弱认证部署war包、弱口令爆破、CVE-2020-1938 Tomcat AJP文件读取/包含
>

<h3 id="yleGU">NacosExploitGUI_v4.0</h3>
项目地址：[https://github.com/charonlight/NacosExploitGUI](https://github.com/charonlight/NacosExploitGUI)

> Nacos漏洞综合利用GUI工具，集成了默认口令漏洞、SQL注入漏洞、身份认证绕过漏洞、反序列化漏洞的检测及其利用
>



<h3 id="FER6g">TongdaOATool_V1.6</h3>
项目地址：[https://github.com/xiaokp7/TongdaOATool](https://github.com/xiaokp7/TongdaOATool)

> 通达OA漏洞检测工具
>

<h3 id="j0xnV">swagger-exp-knife4j</h3>
项目地址：[https://github.com/cws001/swagger-exp-knife4j](https://github.com/cws001/swagger-exp-knife4j)

> 日常渗透过程中，经常会碰到Spring Boot搭建的微服务，当发现接口文档泄露时，手工测试API接口未授权工作量较大，于是参考了工具 [springboot-exp]:[https://github.com/lijiejie/swagger-exp](https://github.com/lijiejie/swagger-exp) 的原理，开发了一款基 于Knife4j 的 Swagger 接口自动化测试未授权工具，较其他自动化测试工具而言，本工具增加了参数支持，优化了用户体验，改进了Swagger测试界面，并且支持自定义设置全局请求头参数。工具适用于 windos、linux ，适用于 Swagger API v2、v3。
>

```plain
  ____                                     _____
/ ___|_      ____ _  __ _  __ _  ___ _ __| ____|_  ___ __
\___ \ \ /\ / / _` |/ _` |/ _` |/ _ \ '__|  _| \ \/ / '_ \
 ___) \ V  V / (_| | (_| | (_| |  __/ |  | |___ >  <| |_) |
|____/ \_/\_/ \__,_|\__, |\__, |\___|_|  |_____/_/\_\ .__/
                    |___/ |___/                     |_|

 _  __      _  __      _  _   _     +-------+
| |/ /_ __ (_)/ _| ___| || | (_)    + v1.1  +
| ' /| '_ \| | |_ / _ \ || |_| |    +-------+
| . \| | | | |  _|  __/__   _| |
|_|\_\_| |_|_|_|  \___|  |_|_/ |
                           |__/


参数：
    -u  --url       指定 Swagger 相关URL
    -c  --chrome    本地打开chrome禁用CORS，打开 Knife4j 界面

用法:
    只打开Knife4j 进行分析：             python3 swagger-exp-knife4j.py -c
    扫描所有API集，分析接口是否存在未授权：  python3 swagger-exp-knife4j.py -u http://example.com/swagger-resources
    扫描一个API集，分析接口是否存在未授权：  python3 swagger-exp-knife4j.py -u http://example.com/v2/api-docs
    扫描一个API集，爬取api-doc打开Chrome：python3 swagger-exp-knife4j.py -u http://example.com/swagger-ui.html

注意：
    1、Knife4j 界面里一定要在 '个性化设置' 手动勾选 HOST 刷新页面,才能进行正常测试。
    2、部分 HTTPS 网站测试时报错Network Error，可在个性化设置 HOST 处加上协议号，如 https://example.com
```

<h3 id="OZjIB">XXL-JOB漏洞利用工具v1.5</h3>
项目地址：[https://github.com/charonlight/xxl-jobExploitGUI](https://github.com/charonlight/xxl-jobExploitGUI)

> 工具支持检测xxl-job多种常见漏洞，并且支持多种利用方式。工具提供直观友好的图像化界面，用户能够轻松进行操作和管理。支持空间测绘、批量扫描功能，用户可以同时对多个目标进行漏洞检测，极大地提高了扫描效率。还支持暂停扫描、终止扫描、自定义多线程扫描、自定义请求头、内置随机User-Agent头、http代理、socks代理、扫描结果导出为表格等等功能。
>

<h3 id="aJxVz">Frchannel</h3>
项目地址：[https://github.com/7wkajk/Frchannel](https://github.com/7wkajk/Frchannel)

> 帆软bi反序列漏洞利用工具
>
> 1、新增反序列化利用链
>
> 2、新增数据库连接解密功能
>
> 3、修复ssl证书问题
>

<h3 id="Wn3D3">FrchannelPlus</h3>
项目地址：[https://github.com/BambiZombie/FrchannelPlus](https://github.com/BambiZombie/FrchannelPlus)

> 帆软bi反序列化漏洞利用工具，将原版的冰蝎内存马换成了哥斯拉，增加了suo5内存马
>

<h1 id="ztRu0">渗透测试工具：</h1>
<h3 id="geJrF">fscan_v2.00</h3>
项目地址：[https://github.com/shadow1ng/fscan](https://github.com/shadow1ng/fscan)

```plain
┌──────────────────────────────────────────────┐
│    ___                              _        │
│   / _ \     ___  ___ _ __ __ _  ___| | __    │
│  / /_\/____/ __|/ __| '__/ _` |/ __| |/ /    │
│ / /_\\_____\__ \ (__| | | (_| | (__|   <     │
│ \____/     |___/\___|_|  \__,_|\___|_|\_\    │
└──────────────────────────────────────────────┘
      Fscan Version: 2.0.0

flag needs an argument: -h
Usage of fscan.exe:
  -c string
        指定要执行的系统命令(支持ssh和wmiexec)
  -cookie string
        设置HTTP请求Cookie
  -dns
        启用dnslog进行漏洞验证
  -domain string
        指定域名(仅用于SMB协议)
  -eh string
        排除指定主机范围,支持CIDR格式,如: 192.168.1.1/24
  -f string
        指定输出格式 (txt/json/csv) (default "txt")
  -full
        启用完整POC扫描(如测试shiro全部100个key)
  -h string
        指定目标主机,支持以下格式:
          - 单个IP: 192.168.11.11
          - IP范围: 192.168.11.11-255
          - 多个IP: 192.168.11.11,192.168.11.12
  -hash string
        指定要破解的Hash值
  -hashf string
        从文件中读取Hash字典
  -hf string
        从文件中读取目标主机列表
  -json
        以JSON格式输出结果
  -lang string
        指定界面语言 (zh:中文, en:英文, ja:日文, ru:俄文) (default "zh")
  -local
        启用本地信息收集模式
  -log string
        日志输出级别(ALL/SUCCESS/ERROR/INFO/DEBUG) (default "SUCCESS")
  -m string
        指定扫描模式:
        预设模式:
          - All: 全量扫描
          - Basic: 基础扫描(Web/FTP/SSH等)
          - Database: 数据库扫描
          - Web: Web服务扫描
          - Service: 常见服务扫描
          - Vul: 漏洞扫描
          - Port: 端口扫描
          - ICMP: 存活探测
          - Local: 本地信息
        单项扫描:
          - web/db: mysql,redis等
          - service: ftp,ssh等
          - vul: ms17010等 (default "All")
  -no
        禁止保存扫描结果
  -nobr
        禁用密码暴力破解
  -nocolor
        禁用彩色输出显示
  -noredis
        禁用Redis安全检测
  -np
        禁用主机存活探测
  -num int
        设置POC扫描并发数 (default 20)
  -o string
        指定结果输出文件名 (default "result.txt")
  -p string
        指定扫描端口,支持以下格式:
        格式:
          - 单个: 22
          - 范围: 1-65535
          - 多个: 22,80,3306
        预设组:
          - main: 常用端口组
          - service: 服务端口组
          - db: 数据库端口组
          - web: Web端口组
          - all: 全部端口
        示例: -p main, -p 80,443, -p 1-1000 (default "21,22,23,80,81,110,135,139,143,389,443,445,502,873,993,995,1433,1521,3306,5432,5672,6379,7001,7687,8000,8005,8009,8080,8089,8443,9000,9042,9092,9200,10051,11211,15672,27017,61616")
  -path string
        指定FCG/SMB远程文件路径
  -pg
        开启进度条显示
  -ping
        使用系统ping命令替代ICMP探测
  -pocname string
        指定要使用的POC名称,如: -pocname weblogic
  -pocpath string
        指定自定义POC文件路径
  -portf string
        从文件中读取端口列表
  -proxy string
        设置HTTP代理服务器
  -pwd string
        指定单个密码
  -pwda string
        在默认密码列表基础上添加自定义密码
  -pwdf string
        从文件中读取密码字典
  -retry int
        设置最大重试次数 (default 3)
  -rf string
        指定Redis写入的SSH公钥文件
  -rs string
        指定Redis写入的计划任务内容
  -sc string
        指定MS17漏洞利用的shellcode
  -silent
        启用静默扫描模式(减少屏幕输出)
  -skip
        跳过端口指纹识别
  -socks5 string
        设置Socks5代理(用于TCP连接,将影响超时设置)
  -sshkey string
        指定SSH私钥文件路径(默认为id_rsa)
  -t int
        设置扫描线程数 (default 60)
  -time int
        设置连接超时时间(单位:秒) (default 3)
  -top int
        仅显示指定数量的存活主机 (default 10)
  -u string
        指定目标URL
  -uf string
        从文件中读取URL列表
  -user string
        指定单个用户名
  -usera string
        在默认用户列表基础上添加自定义用户名
  -userf string
        从文件中读取用户名字典
  -wmi
        启用WMI协议扫描
  -wt int
        设置Web请求超时时间(单位:秒) (default 5)
```

<h3 id="IKgcY">sqlmap_v1.9.2</h3>
项目地址：[https://sqlmap.org/](https://sqlmap.org/)

```plain
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.9.2.15#dev}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

Usage: sqlmap.py [options]

Options:
  -h, --help            Show basic help message and exit
  -hh                   Show advanced help message and exit
  --version             Show program's version number and exit
  -v VERBOSE            Verbosity level: 0-6 (default 1)

  Target:
    At least one of these options has to be provided to define the
    target(s)

    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")
    -g GOOGLEDORK       Process Google dork results as target URLs

  Request:
    These options can be used to specify how to connect to the target URL

    --data=DATA         Data string to be sent through POST (e.g. "id=1")
    --cookie=COOKIE     HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
    --random-agent      Use randomly selected HTTP User-Agent header value
    --proxy=PROXY       Use a proxy to connect to the target URL
    --tor               Use Tor anonymity network
    --check-tor         Check to see if Tor is used properly

  Injection:
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)
    --dbms=DBMS         Force back-end DBMS to provided value

  Detection:
    These options can be used to customize the detection phase

    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (1-3, default 1)

  Techniques:
    These options can be used to tweak testing of specific SQL injection
    techniques

    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")

  Enumeration:
    These options can be used to enumerate the back-end database
    management system information, structure and data contained in the
    tables

    -a, --all           Retrieve everything
    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user
    --current-db        Retrieve DBMS current database
    --passwords         Enumerate DBMS users password hashes
    --dbs               Enumerate DBMS databases
    --columns           Enumerate DBMS database table columns
    --schema            Enumerate DBMS schema
    --dump              Dump DBMS database table entries
    --dump-all          Dump all DBMS databases tables entries
    -D DB               DBMS database to enumerate
    -T TBL              DBMS database table(s) to enumerate
    -C COL              DBMS database table column(s) to enumerate

  Operating system access:
    These options can be used to access the back-end database management
    system underlying operating system

    --os-shell          Prompt for an interactive operating system shell
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC

  General:
    These options can be used to set some general working parameters

    --batch             Never ask for user input, use the default behavior
    --flush-session     Flush session files for current target

  Miscellaneous:
    These options do not fit into any other category

    --wizard            Simple wizard interface for beginner users
```


<h3 id="uWZRh">xray(第一次使用需要自己配置一下)</h3>
官方文档：[https://xtls.github.io/](https://xtls.github.io/)



<h3 id="qTWvD">EZ(第一次使用需要自己配置一下，证书)</h3>
项目地址：[https://github.com/m-sec-org/EZ](https://github.com/m-sec-org/EZ)

证书下载地址：[https://msec.nsfocus.com](https://msec.nsfocus.com)（每次仅能申请 1 个月使用期）

<h3 id="VuIW9">nuclei</h3>
项目地址：[https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

```plain
                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.3.9

                projectdiscovery.io
Nuclei is a fast, template based vulnerability scanner focusing
on extensive configurability, massive extensibility and ease of use.

Usage:
  nuclei.exe [flags]

Flags:
TARGET:
   -u, -target string[]          target URLs/hosts to scan
   -l, -list string              path to file containing a list of target URLs/hosts to scan (one per line)
   -eh, -exclude-hosts string[]  hosts to exclude to scan from the input list (ip, cidr, hostname)
   -resume string                resume scan using resume.cfg (clustering will be disabled)
   -sa, -scan-all-ips            scan all the IP's associated with dns record
   -iv, -ip-version string[]     IP version to scan of hostname (4,6) - (default 4)

TARGET-FORMAT:
   -im, -input-mode string        mode of input file (list, burp, jsonl, yaml, openapi, swagger) (default "list")
   -ro, -required-only            use only required fields in input format when generating requests
   -sfv, -skip-format-validation  skip format validation (like missing vars) when parsing input file

TEMPLATES:
   -nt, -new-templates                    run only new templates added in latest nuclei-templates release
   -ntv, -new-templates-version string[]  run new templates added in specific version
   -as, -automatic-scan                   automatic web scan using wappalyzer technology detection to tags mapping
   -t, -templates string[]                list of template or template directory to run (comma-separated, file)
   -turl, -template-url string[]          template url or list containing template urls to run (comma-separated, file)
   -ai, -prompt string                    generate and run template using ai prompt
   -w, -workflows string[]                list of workflow or workflow directory to run (comma-separated, file)
   -wurl, -workflow-url string[]          workflow url or list containing workflow urls to run (comma-separated, file)
   -validate                              validate the passed templates to nuclei
   -nss, -no-strict-syntax                disable strict syntax check on templates
   -td, -template-display                 displays the templates content
   -tl                                    list all available templates
   -tgl                                   list all available tags
   -sign                                  signs the templates with the private key defined in NUCLEI_SIGNATURE_PRIVATE_KEY env variable
   -code                                  enable loading code protocol-based templates
   -dut, -disable-unsigned-templates      disable running unsigned templates or templates with mismatched signature
   -esc, -enable-self-contained           enable loading self-contained templates
   -egm, -enable-global-matchers          enable loading global matchers templates
   -file                                  enable loading file templates

FILTERING:
   -a, -author string[]               templates to run based on authors (comma-separated, file)
   -tags string[]                     templates to run based on tags (comma-separated, file)
   -etags, -exclude-tags string[]     templates to exclude based on tags (comma-separated, file)
   -itags, -include-tags string[]     tags to be executed even if they are excluded either by default or configuration
   -id, -template-id string[]         templates to run based on template ids (comma-separated, file, allow-wildcard)
   -eid, -exclude-id string[]         templates to exclude based on template ids (comma-separated, file)
   -it, -include-templates string[]   path to template file or directory to be executed even if they are excluded either by default or configuration
   -et, -exclude-templates string[]   path to template file or directory to exclude (comma-separated, file)
   -em, -exclude-matchers string[]    template matchers to exclude in result
   -s, -severity value[]              templates to run based on severity. Possible values: info, low, medium, high, critical, unknown
   -es, -exclude-severity value[]     templates to exclude based on severity. Possible values: info, low, medium, high, critical, unknown
   -pt, -type value[]                 templates to run based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -ept, -exclude-type value[]        templates to exclude based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -tc, -template-condition string[]  templates to run based on expression condition

OUTPUT:
   -o, -output string            output file to write found issues/vulnerabilities
   -sresp, -store-resp           store all request/response passed through nuclei to output directory
   -srd, -store-resp-dir string  store all request/response passed through nuclei to custom directory (default "output")
   -silent                       display findings only
   -nc, -no-color                disable output content coloring (ANSI escape codes)
   -j, -jsonl                    write output in JSONL(ines) format
   -irr, -include-rr -omit-raw   include request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only) [DEPRECATED use -omit-raw] (default true)
   -or, -omit-raw                omit request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only)
   -ot, -omit-template           omit encoded template in the JSON, JSONL output
   -nm, -no-meta                 disable printing result metadata in cli output
   -ts, -timestamp               enables printing timestamp in cli output
   -rdb, -report-db string       nuclei reporting database (always use this to persist report data)
   -ms, -matcher-status          display match failure status
   -me, -markdown-export string  directory to export results in markdown format
   -se, -sarif-export string     file to export results in SARIF format
   -je, -json-export string      file to export results in JSON format
   -jle, -jsonl-export string    file to export results in JSONL(ine) format
   -rd, -redact string[]         redact given list of keys from query parameter, request header and body

CONFIGURATIONS:
   -config string                        path to the nuclei configuration file
   -tp, -profile string                  template profile config file to run
   -tpl, -profile-list                   list community template profiles
   -fr, -follow-redirects                enable following redirects for http templates
   -fhr, -follow-host-redirects          follow redirects on the same host
   -mr, -max-redirects int               max number of redirects to follow for http templates (default 10)
   -dr, -disable-redirects               disable redirects for http templates
   -rc, -report-config string            nuclei reporting module configuration file
   -H, -header string[]                  custom header/cookie to include in all http request in header:value format (cli, file)
   -V, -var value                        custom vars in key=value format
   -r, -resolvers string                 file containing resolver list for nuclei
   -sr, -system-resolvers                use system DNS resolving as error fallback
   -dc, -disable-clustering              disable clustering of requests
   -passive                              enable passive HTTP response processing mode
   -fh2, -force-http2                    force http2 connection on requests
   -ev, -env-vars                        enable environment variables to be used in template
   -cc, -client-cert string              client certificate file (PEM-encoded) used for authenticating against scanned hosts
   -ck, -client-key string               client key file (PEM-encoded) used for authenticating against scanned hosts
   -ca, -client-ca string                client certificate authority file (PEM-encoded) used for authenticating against scanned hosts
   -sml, -show-match-line                show match lines for file templates, works with extractors only
   -ztls                                 use ztls library with autofallback to standard one for tls13 [Deprecated] autofallback to ztls is enabled by default
   -sni string                           tls sni hostname to use (default: input domain name)
   -dka, -dialer-keep-alive value        keep-alive duration for network requests.
   -lfa, -allow-local-file-access        allows file (payload) access anywhere on the system
   -lna, -restrict-local-network-access  blocks connections to the local / private network
   -i, -interface string                 network interface to use for network scan
   -at, -attack-type string              type of payload combinations to perform (batteringram,pitchfork,clusterbomb)
   -sip, -source-ip string               source ip address to use for network scan
   -rsr, -response-size-read int         max response size to read in bytes
   -rss, -response-size-save int         max response size to read in bytes (default 1048576)
   -reset                                reset removes all nuclei configuration and data files (including nuclei-templates)
   -tlsi, -tls-impersonate               enable experimental client hello (ja3) tls randomization
   -hae, -http-api-endpoint string       experimental http api endpoint

INTERACTSH:
   -iserver, -interactsh-server string  interactsh server url for self-hosted instance (default: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)
   -itoken, -interactsh-token string    authentication token for self-hosted interactsh server
   -interactions-cache-size int         number of requests to keep in the interactions cache (default 5000)
   -interactions-eviction int           number of seconds to wait before evicting requests from cache (default 60)
   -interactions-poll-duration int      number of seconds to wait before each interaction poll request (default 5)
   -interactions-cooldown-period int    extra time for interaction polling before exiting (default 5)
   -ni, -no-interactsh                  disable interactsh server for OAST testing, exclude OAST based templates

FUZZING:
   -ft, -fuzzing-type string           overrides fuzzing type set in template (replace, prefix, postfix, infix)
   -fm, -fuzzing-mode string           overrides fuzzing mode set in template (multiple, single)
   -fuzz                               enable loading fuzzing templates (Deprecated: use -dast instead)
   -dast                               enable / run dast (fuzz) nuclei templates
   -dts, -dast-server                  enable dast server mode (live fuzzing)
   -dtr, -dast-report                  write dast scan report to file
   -dtst, -dast-server-token string    dast server token (optional)
   -dtsa, -dast-server-address string  dast server address (default "localhost:9055")
   -dfp, -display-fuzz-points          display fuzz points in the output for debugging
   -fuzz-param-frequency int           frequency of uninteresting parameters for fuzzing before skipping (default 10)
   -fa, -fuzz-aggression string        fuzzing aggression level controls payload count for fuzz (low, medium, high) (default "low")
   -cs, -fuzz-scope string[]           in scope url regex to be followed by fuzzer
   -cos, -fuzz-out-scope string[]      out of scope url regex to be excluded by fuzzer

UNCOVER:
   -uc, -uncover                  enable uncover engine
   -uq, -uncover-query string[]   uncover search query
   -ue, -uncover-engine string[]  uncover search engine (shodan,censys,fofa,shodan-idb,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow,google) (default shodan)
   -uf, -uncover-field string     uncover fields to return (ip,port,host) (default "ip:port")
   -ul, -uncover-limit int        uncover results to return (default 100)
   -ur, -uncover-ratelimit int    override ratelimit of engines with unknown ratelimit (default 60 req/min) (default 60)

RATE-LIMIT:
   -rl, -rate-limit int               maximum number of requests to send per second (default 150)
   -rld, -rate-limit-duration value   maximum number of requests to send per second (default 1s)
   -rlm, -rate-limit-minute int       maximum number of requests to send per minute (DEPRECATED)
   -bs, -bulk-size int                maximum number of hosts to be analyzed in parallel per template (default 25)
   -c, -concurrency int               maximum number of templates to be executed in parallel (default 25)
   -hbs, -headless-bulk-size int      maximum number of headless hosts to be analyzed in parallel per template (default 10)
   -headc, -headless-concurrency int  maximum number of headless templates to be executed in parallel (default 10)
   -jsc, -js-concurrency int          maximum number of javascript runtimes to be executed in parallel (default 120)
   -pc, -payload-concurrency int      max payload concurrency for each template (default 25)
   -prc, -probe-concurrency int       http probe concurrency with httpx (default 50)

OPTIMIZATIONS:
   -timeout int                     time to wait in seconds before timeout (default 10)
   -retries int                     number of times to retry a failed request (default 1)
   -ldp, -leave-default-ports       leave default HTTP/HTTPS ports (eg. host:80,host:443)
   -mhe, -max-host-error int        max errors for a host before skipping from scan (default 30)
   -te, -track-error string[]       adds given error to max-host-error watchlist (standard, file)
   -nmhe, -no-mhe                   disable skipping host from scan based on errors
   -project                         use a project folder to avoid sending same request multiple times
   -project-path string             set a specific project path (default "C:\\Users\\HP\\AppData\\Local\\Temp")
   -spm, -stop-at-first-match       stop processing HTTP requests after the first match (may break template/workflow logic)
   -stream                          stream mode - start elaborating without sorting the input
   -ss, -scan-strategy value        strategy to use while scanning(auto/host-spray/template-spray) (default auto)
   -irt, -input-read-timeout value  timeout on input read (default 3m0s)
   -nh, -no-httpx                   disable httpx probing for non-url input
   -no-stdin                        disable stdin processing

HEADLESS:
   -headless                        enable templates that require headless browser support (root user on Linux will disable sandbox)
   -page-timeout int                seconds to wait for each page in headless mode (default 20)
   -sb, -show-browser               show the browser on the screen when running templates with headless mode
   -ho, -headless-options string[]  start headless chrome with additional options
   -sc, -system-chrome              use local installed Chrome browser instead of nuclei installed
   -lha, -list-headless-action      list available headless actions

DEBUG:
   -debug                     show all requests and responses
   -dreq, -debug-req          show all sent requests
   -dresp, -debug-resp        show all received responses
   -p, -proxy string[]        list of http/socks5 proxy to use (comma separated or file input)
   -pi, -proxy-internal       proxy all internal requests
   -ldf, -list-dsl-function   list all supported DSL function signatures
   -tlog, -trace-log string   file to write sent requests trace log
   -elog, -error-log string   file to write sent requests error log
   -version                   show nuclei version
   -hm, -hang-monitor         enable nuclei hang monitoring
   -v, -verbose               show verbose output
   -profile-mem string        generate memory (heap) profile & trace files
   -vv                        display templates loaded for scan
   -svd, -show-var-dump       show variables dump for debugging
   -vdl, -var-dump-limit int  limit the number of characters displayed in var dump (default 255)
   -ep, -enable-pprof         enable pprof debugging server
   -tv, -templates-version    shows the version of the installed nuclei-templates
   -hc, -health-check         run diagnostic check up

UPDATE:
   -up, -update                      update nuclei engine to the latest released version
   -ut, -update-templates            update nuclei-templates to latest released version
   -ud, -update-template-dir string  custom directory to install / update nuclei-templates
   -duc, -disable-update-check       disable automatic nuclei/templates update check

STATISTICS:
   -stats                    display statistics about the running scan
   -sj, -stats-json          display statistics in JSONL(ines) format
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default 5)
   -mp, -metrics-port int    port to expose nuclei metrics on (default 9092)
   -hps, -http-stats         enable http status capturing (experimental)

CLOUD:
   -auth                           configure projectdiscovery cloud (pdcp) api key (default true)
   -tid, -team-id string           upload scan results to given team id (optional) (default "none")
   -cup, -cloud-upload             upload scan results to pdcp dashboard [DEPRECATED use -dashboard]
   -sid, -scan-id string           upload scan results to existing scan id (optional)
   -sname, -scan-name string       scan name to set (optional)
   -pd, -dashboard                 upload / view nuclei results in projectdiscovery cloud (pdcp) UI dashboard
   -pdu, -dashboard-upload string  upload / view nuclei results file (jsonl) in projectdiscovery cloud (pdcp) UI dashboard

AUTHENTICATION:
   -sf, -secret-file string[]  path to config file containing secrets for nuclei authenticated scan
   -ps, -prefetch-secrets      prefetch secrets from the secrets file


EXAMPLES:
Run nuclei on single host:
        $ nuclei -target example.com

Run nuclei with specific template directories:
        $ nuclei -target example.com -t http/cves/ -t ssl

Run nuclei against a list of hosts:
        $ nuclei -list hosts.txt

Run nuclei with a JSON output:
        $ nuclei -target example.com -json-export output.json

Run nuclei with sorted Markdown outputs (with environment variables):
        $ MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclei_report/

Additional documentation is available at: https://docs.nuclei.sh/getting-started/running
```

<h3 id="EuOem">DudeSuite v1.1.4.1</h3>
项目地址：[https://github.com/x364e3ab6/DudeSuite/releases/tag/v1.1.4.1](https://github.com/x364e3ab6/DudeSuite/releases/tag/v1.1.4.1)

> 单兵作战渗透测试工具
>

<h3 id="qpLDq">railgun</h3>
项目地址：[https://github.com/lz520520/railgun](https://github.com/lz520520/railgun)

> Railgun为一款GUI界面的渗透工具，将部分人工经验转换为自动化，集成了渗透过程中常用到的一些功能，目前集成了端口扫描、端口爆破、web指纹扫描、漏洞扫描、漏洞利用以及编码转换功能，后续会持续更新。
>

