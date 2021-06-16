package proxypanel

import "encoding/json"

type Response struct {
	Status  string          `json:"status"`
	Code    int             `json:"code"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}
type V2rayNodeInfo struct {
	ID            int    `json:"id"`
	IsUDP         bool   `json:"is_udp"`
	SpeedLimit    uint64 `json:"speed_limit"`
	ClientLimit   int    `json:"client_limit"`
	PushPort      int    `json:"push_port"`
	Secret        string `json:"secret"`
	Key           string `json:"key"`
	Cert          string `json:"pem"`
	V2License     string `json:"v2_license"`
	V2AlterID     int    `json:"v2_alter_id"`
	V2Port        int    `json:"v2_port"`
	V2Method      string `json:"v2_method"`
	V2Net         string `json:"v2_net"`
	V2Type        string `json:"v2_type"`
	V2Host        string `json:"v2_host"`
	V2Path        string `json:"v2_path"`
	V2TLS         bool   `json:"v2_tls"`
	V2Cdn         bool   `json:"v2_cdn"`
	V2TLSProvider string `json:"v2_tls_provider"`
	RedirectUrl   string `json:"redirect_url"`
}

type TrojanNodeInfo struct {
	ID          int    `json:"id"`
	IsUDP       bool   `json:"is_udp"`
	SpeedLimit  uint64 `json:"speed_limit"`
	ClientLimit int    `json:"client_limit"`
	PushPort    int    `json:"push_port"`
	TorjanPort  int    `json:"trojan_port"`
	Secret      string `json:"secret"`
	License     string `json:"license"`
}

// "id": 2,
// "method": "aes-256-cfb",
// "protocol": "origin",
// "obfs": "plain",
// "obfs_param": "",
// "is_udp": 1,
// "speed_limit": 6555555,
// "client_limit": 1,
// "single": 0,
// "port": "", // 只在单端口模式使用
// "passwd": "", // 只在单端口模式使用
// "push_port": 8081
type SSRNodeInfo struct {
	ID          int    `json:"id"`
	Method      string `json:"method"`
	Obfs        string `json:"obfs"`
	ObfsParam   string `json:"obfs_param"`
	IsUDP       bool   `json:"is_udp"`
	SpeedLimit  uint64 `json:"speed_limit"`
	ClientLimit int    `json:"client_limit"`
	Single      int    `json:"single"`
	Port        int    `json:"port"`
	Passwd      string `json:"passwd"`
	PushPort    int    `json:"push_port"`
}
type V2rayUser struct {
	UID        int    `json:"uid"`
	VmessUID   string `json:"vmess_uid"`
	SpeedLimit uint64 `json:"speed_limit"`
}
type TrojanUser struct {
	UID        int    `json:"uid"`
	Password   string `json:"password"`
	SpeedLimit uint64 `json:"speed_limit"`
}

// "uid": 1,
// "port": 10000,
// "passwd": "@123",
// "method": "aes-256-cfb",
// "protocol": "origin",
// "obfs": "plain",
// "obfs_param": "",
// "speed_limit": 134217728,
// "enable": 1
type SSRUser struct {
	UID        int    `json:"uid"`
	Port       int    `json:"port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Protocol   string `json:"protocol"`
	Obfs       string `json:"obfs"`
	ObfsParam  string `json:"obfs_param"`
	SpeedLimit uint64 `json:"speed_limit"`
}

// Node status report  节点心跳信息
type NodeStatus struct {
	CPU    string `json:"cpu"`
	Mem    string `json:"mem"`
	Net    string `json:"net"`
	Disk   string `json:"disk"`
	Uptime int    `json:"uptime"`
}

//节点在线信息
type NodeOnline struct {
	UID int    `json:"uid"`
	IP  string `json:"ip"`
}

//用户流量日志
type UserTraffic struct {
	UID      int `json:"uid"`
	Upload   int `json:"upload"`
	Download int `json:"download"`
}

//审计规则
//mode为all时，表示节点未设置任何审计规则，全部放行
//mode为reject时，表示节点设置了阻断规则，凡是匹配到阻断规则的请求都要拦截
//mode为allow时，表示节点设置了仅放行的白名单，凡是非白名单内的全部拦截，仅放行匹配了白名单规则的
type NodeRule struct {
	Mode  string         `json:"mode"`  //模式 all/reject()/allow
	Rules []NodeRuleItem `json:"rules"` //规则列表
}

//单条审计规则
type NodeRuleItem struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

// IllegalReport 用户触发审计规则记录
type IllegalReport struct {
	UID    int    `json:"uid"`
	RuleID int    `json:"rule_id"`
	Reason string `json:"reason"`
}

//上报伪装域名证书信息
type Certificate struct {
	Key string `json:"key"`
	Pem string `json:"pem"`
}
