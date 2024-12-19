// 指定需要在原有配置文件上删除的字段
const remove = ["proxy-groups", "rules", "rule-providers"];
const loadReg = "^(?!.*试用).*(美国|日本|新加坡|香港)";
const IPLCReg = "^(?!.*试用).*(专线|IPLC|CN2)";
const SSRReg = "^(?!.*试用).*(SSR)";
const ipv6Reg = "^(?!.*试用).*(ipv6)";
const USReg = "^(?!.*试用).*(🇺🇸 美国 )";

// 指定需要需要追加的 YAML 配置，注意缩进  🇺🇸 美国 20
// 在数组中，使用 `_PROXY_NAME` 指代所有的 Proxy Name
// 在 Rule Provider 中的 URL 中，使用 `_PROVIDER_PROXY|` 指代规则文件代理 URL
const append = `
proxy-groups:
  - name: 🔰 节点选择
    type: select
    proxies: [DIRECT, _PROXY_NAME,⚖️ 负载均衡-散列,⚖️ 负载均衡-轮询,⚖️ SSR轮询,⚖️ IPLC轮询,⚖️ US轮询]
  - name: ⚖️ 负载均衡-散列
    type: load-balance
    url: http://www.google.com/generate_204
    interval: 86400
    strategy: consistent-hashing
    proxies:
      - _PROXY_NAME
  - name: ⚖️ 负载均衡-轮询
    type: load-balance
    url: http://www.google.com/generate_204
    interval: 86400
    strategy: round-robin
    proxies:
      - _PROXY_NAME
  - name: ⚖️ SSR轮询
    type: load-balance
    url: http://www.google.com/generate_204
    interval: 86400
    tolerance: 150 # 允许的偏差，节点之间延迟差小于该值不切换 非必要
    strategy: round-robin
    proxies:
      - _SSR_NAME
  - name: ⚖️ ipv6轮询
    type: load-balance
    url: http://www.google.com/generate_204
    interval: 86400
    tolerance: 150 # 允许的偏差，节点之间延迟差小于该值不切换 非必要
    strategy: round-robin
    proxies:
      - _ipv6_NAME      
  - name: ⚖️ IPLC轮询
    type: load-balance
    url: http://www.google.com/generate_204
    interval: 86400
    tolerance: 150 # 允许的偏差，节点之间延迟差小于该值不切换 非必要
    strategy: round-robin
    proxies:
      - _IPLC_NAME      
  - name: ⚖️ US轮询
    type: load-balance
    url: http://www.google.com/generate_204
    interval: 86400
    tolerance: 150 # 允许的偏差，节点之间延迟差小于该值不切换 非必要
    strategy: round-robin
    proxies:
      - _US_NAME 
rules:
  - SRC-IP-CIDR,10.0.1.236/32,🇺🇸 美国 2081,no-resolve
  - MATCH,🔰 节点选择


rule-providers:
  reject:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|reject.txt
    path: ./ruleset/reject.yaml
    interval: 86400
  icloud:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|icloud.txt
    path: ./ruleset/icloud.yaml
    interval: 86400
  apple:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|apple.txt
    path: ./ruleset/apple.yaml
    interval: 86400
  google:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|google.txt
    path: ./ruleset/google.yaml
    interval: 86400
  proxy:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|proxy.txt
    path: ./ruleset/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|direct.txt
    path: ./ruleset/direct.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|private.txt
    path: ./ruleset/private.yaml
    interval: 86400
  gfw:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|gfw.txt
    path: ./ruleset/gfw.yaml
    interval: 86400
  greatfire:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|greatfire.txt
    path: ./ruleset/greatfire.yaml
    interval: 86400
  tld-not-cn:
    type: http
    behavior: domain
    url: _PROVIDER_PROXY|tld-not-cn.txt
    path: ./ruleset/tld-not-cn.yaml
    interval: 86400
  telegramcidr:
    type: http
    behavior: ipcidr
    url: _PROVIDER_PROXY|telegramcidr.txt
    path: ./ruleset/telegramcidr.yaml
    interval: 86400
  cncidr:
    type: http
    behavior: ipcidr
    url: _PROVIDER_PROXY|cncidr.txt
    path: ./ruleset/cncidr.yaml
    interval: 86400
  lancidr:
    type: http
    behavior: ipcidr
    url: _PROVIDER_PROXY|lancidr.txt
    path: ./ruleset/lancidr.yaml
    interval: 86400
  applications:
    type: http
    behavior: classical
    url: _PROVIDER_PROXY|applications.txt
    path: ./ruleset/applications.yaml
    interval: 86400

`;

export default { remove, append,loadReg,IPLCReg,SSRReg,ipv6Reg,USReg};
