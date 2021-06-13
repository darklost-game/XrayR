package proxypan

import "encoding/json"

type Response struct {
	Status  string          `json:"status"`
	Code    int             `json:"code"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
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
