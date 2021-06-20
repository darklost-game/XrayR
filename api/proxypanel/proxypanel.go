package proxypanel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/go-resty/resty/v2"
)

// APIClient create a api client to the panel.
type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	NodeType      string
	EnableVless   bool
	EnableXTLS    bool
	SpeedLimit    float64
	DeviceLimit   int
	LocalRuleList []api.DetectRule
}

// New creat a api instance
func New(apiConfig *api.Config) *APIClient {

	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetHostURL(apiConfig.APIHost)
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)

	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		EnableXTLS:    apiConfig.EnableXTLS,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
	}
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {

	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		//handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: fileScanner.Text(),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return make([]api.DetectRule, 0)
		}

		file.Close()
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(apiPath string) string {
	return c.APIHost + apiPath
}

func (c *APIClient) apiPath(path string) (string, error) {

	switch c.NodeType {
	case "V2ray":
		return "/api/v2ray/v1/" + path, nil
	case "Trojan":
		return "/api/trojan/v1/" + path, nil
	case "Shadowsocks":
		return "/api/web/v1/" + path, nil
		// return "api/vnet/v2" + path, nil
	default:
		return "", fmt.Errorf("Unsupported Node type: %s", c.NodeType)
	}
}

func (c *APIClient) createCommonRequest() *resty.Request {
	request := c.client.R()
	request.SetHeader("key", c.Key)
	request.SetHeader("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	return request
}
func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*Response, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %s", c.assembleURL(path), string(body), err)
	}
	response := res.Result().(*Response)

	if response.Code != 200 {
		res, _ := json.Marshal(&response)
		return nil, fmt.Errorf("response %s invalid", string(res))
	}
	return response, nil
}

// ParseV2rayNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseV2rayNodeResponse(data json.RawMessage) (*api.NodeInfo, error) {

	var TLStype string = ""
	var speedlimit uint64 = 0
	v2rayNodeInfo := new(V2rayNodeInfo)
	err := json.Unmarshal(data, &v2rayNodeInfo)
	if err != nil {
		return nil, fmt.Errorf("json unmarshal failed %s ", err.Error())
	}
	if c.SpeedLimit > 0 {
		speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedlimit = uint64(v2rayNodeInfo.SpeedLimit)
	}

	c.DeviceLimit = v2rayNodeInfo.ClientLimit

	if v2rayNodeInfo.V2TLS {
		if c.EnableXTLS {
			TLStype = "xtls"
		} else {
			TLStype = "tls"
		}
	}

	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              v2rayNodeInfo.V2Port,
		SpeedLimit:        speedlimit,
		AlterID:           v2rayNodeInfo.V2AlterID,
		TransportProtocol: v2rayNodeInfo.V2Net,
		EnableTLS:         v2rayNodeInfo.V2TLS,
		TLSType:           TLStype,
		Path:              v2rayNodeInfo.V2Path,
		Host:              v2rayNodeInfo.V2Host,
		EnableVless:       c.EnableVless,
	}

	return nodeinfo, nil
}

// ParseSSNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseSSNodeResponse(data json.RawMessage) (*api.NodeInfo, error) {

	var speedlimit uint64 = 0

	ssrNodeInfo := new(SSRNodeInfo)
	err := json.Unmarshal(data, &ssrNodeInfo)
	if err != nil {
		return nil, fmt.Errorf("json unmarshal failed %s ", err.Error())
	}
	if c.SpeedLimit > 0 {
		speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedlimit = uint64(ssrNodeInfo.SpeedLimit)
	}

	c.DeviceLimit = ssrNodeInfo.ClientLimit

	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              ssrNodeInfo.Port,
		SpeedLimit:        speedlimit,
		TransportProtocol: "tcp",
		CypherMethod:      ssrNodeInfo.Method,
	}

	return nodeinfo, nil
}

// ParseTrojanNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseTrojanNodeResponse(data json.RawMessage) (*api.NodeInfo, error) {

	var TLSType string
	var speedlimit uint64 = 0

	trojanNodeInfo := new(TrojanNodeInfo)
	err := json.Unmarshal(data, &trojanNodeInfo)
	if err != nil {
		return nil, fmt.Errorf("json unmarshal failed %s ", err.Error())
	}
	if c.SpeedLimit > 0 {
		speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedlimit = uint64(trojanNodeInfo.SpeedLimit)
	}

	c.DeviceLimit = trojanNodeInfo.ClientLimit

	if c.EnableXTLS {
		TLSType = "xtls"
	} else {
		TLSType = "tls"
	}

	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              trojanNodeInfo.TorjanPort,
		SpeedLimit:        speedlimit,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		TLSType:           TLSType,
	}

	return nodeinfo, nil
}

// GetNodeInfo will pull NodeInfo Config from sspanel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {

	path := fmt.Sprintf("node/%d", c.NodeID)
	apipath, err := c.apiPath(path)
	if err != nil {
		return nil, err
	}
	res, err := c.
		createCommonRequest().
		SetResult(&Response{}).
		Get(apipath)

	response, err := c.parseResponse(res, apipath, err)
	if err != nil {
		return nil, err
	}

	switch c.NodeType {
	case "V2ray":
		nodeInfo, err = c.ParseV2rayNodeResponse(response.Data)
	case "Trojan":
		nodeInfo, err = c.ParseTrojanNodeResponse(response.Data)
	case "Shadowsocks":
		nodeInfo, err = c.ParseSSNodeResponse(response.Data)
	default:
		return nil, fmt.Errorf("Unsupported Node type: %s", c.NodeType)
	}

	if err != nil {
		res, _ := json.Marshal(&response)
		return nil, fmt.Errorf("Parse node info failed: %s", string(res))
	}

	return nodeInfo, nil
}

// ParseV2rayNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseV2rayUserListResponse(data json.RawMessage) (*[]api.UserInfo, error) {

	var deviceLimit int = 0
	var speedlimit uint64 = 0
	v2rayUserList := make([]*V2rayUser, 0)
	if err := json.Unmarshal(data, &v2rayUserList); err != nil {
		return nil, fmt.Errorf("json unmarshal failed %s ", err.Error())
	}

	userList := make([]api.UserInfo, len(v2rayUserList))
	for i, user := range v2rayUserList {
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			// deviceLimit = user.DeviceLimit
		}
		if c.SpeedLimit > 0 {
			speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
		} else {
			speedlimit = uint64((user.SpeedLimit * 1000000) / 8)
		}
		userList[i] = api.UserInfo{
			UID:   user.UID,
			Email: user.VmessUID,
			UUID:  user.VmessUID,
			// Passwd:      user.Passwd,
			SpeedLimit:  speedlimit,
			DeviceLimit: deviceLimit,
			// Port:          user.Port,
			// Method:        user.Method,
			// Protocol:      user.Protocol,
			// ProtocolParam: user.ProtocolParam,
			// Obfs:          user.Obfs,
			// ObfsParam:     user.ObfsParam,
			// AlterID:		  user.AlterID,
		}
	}

	return &userList, nil
}

// ParseV2rayNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseTrojanUserListResponse(data json.RawMessage) (*[]api.UserInfo, error) {

	var deviceLimit int = 0
	var speedlimit uint64 = 0
	trojanUserList := make([]*TrojanUser, 0)
	if err := json.Unmarshal(data, &trojanUserList); err != nil {
		return nil, fmt.Errorf("json unmarshal failed %s ", err.Error())
	}

	userList := make([]api.UserInfo, len(trojanUserList))
	for i, user := range trojanUserList {
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			// deviceLimit = user.DeviceLimit
		}
		if c.SpeedLimit > 0 {
			speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
		} else {
			speedlimit = uint64((user.SpeedLimit * 1000000) / 8)
		}
		userList[i] = api.UserInfo{
			UID:   user.UID,
			Email: user.Password,
			UUID:  user.Password,
			// Passwd:      user.Passwd,
			SpeedLimit:  speedlimit,
			DeviceLimit: deviceLimit,
			// Port:          user.Port,
			// Method:        user.Method,
			// Protocol:      user.Protocol,
			// ProtocolParam: user.ProtocolParam,
			// Obfs:          user.Obfs,
			// ObfsParam:     user.ObfsParam,
			// AlterID:		  user.AlterID,
		}
	}

	return &userList, nil
}

// ParseV2rayNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseSSUserListResponse(data json.RawMessage) (*[]api.UserInfo, error) {

	var deviceLimit int = 0
	var speedlimit uint64 = 0
	ssrUserList := make([]*SSRUser, 0)
	if err := json.Unmarshal(data, &ssrUserList); err != nil {
		return nil, fmt.Errorf("json unmarshal failed %s ", err.Error())
	}

	userList := make([]api.UserInfo, len(ssrUserList))
	for i, user := range ssrUserList {
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			// deviceLimit = user.DeviceLimit
		}
		if c.SpeedLimit > 0 {
			speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
		} else {
			speedlimit = uint64((user.SpeedLimit * 1000000) / 8)
		}
		userList[i] = api.UserInfo{
			UID:   user.UID,
			Email: user.Password,
			// UUID:  user.VmessUID,
			Passwd:      user.Password,
			SpeedLimit:  speedlimit,
			DeviceLimit: deviceLimit,
			Port:        user.Port,
			Method:      user.Method,
			Protocol:    user.Protocol,
			// ProtocolParam: user.ProtocolParam,
			Obfs:      user.Obfs,
			ObfsParam: user.ObfsParam,
			// AlterID:		  user.AlterID,
		}
	}

	return &userList, nil
}

// GetUserList will pull user form sspanel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := fmt.Sprintf("userList/%d", c.NodeID)
	apipath, err := c.apiPath(path)
	if err != nil {
		return nil, err
	}
	res, err := c.
		createCommonRequest().
		SetResult(&Response{}).
		// SetQueryParam("updateTime", string(time.Now().u)).
		Get(apipath)

	response, err := c.parseResponse(res, apipath, err)
	if err != nil {
		return nil, err
	}
	var userList *[]api.UserInfo
	switch c.NodeType {
	case "V2ray":
		userList, err = c.ParseV2rayUserListResponse(response.Data)
	case "Trojan":
		userList, err = c.ParseTrojanUserListResponse(response.Data)
	case "Shadowsocks":
		userList, err = c.ParseSSUserListResponse(response.Data)
	default:
		return nil, fmt.Errorf("Unsupported Node type: %s", c.NodeType)
	}

	if err != nil {
		res, _ := json.Marshal(response)
		return nil, fmt.Errorf("Parse user list failed: %s", string(res))
	}
	return userList, nil
}

// ReportNodeStatus reports the node status to the sspanel
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {

	path := fmt.Sprintf("nodeStatus/%d", c.NodeID)
	apipath, err := c.apiPath(path)
	if err != nil {
		return err
	}

	body := NodeStatus{
		CPU: fmt.Sprintf("%.2f", nodeStatus.CPU),
		Mem: fmt.Sprintf("%.2f", nodeStatus.Mem),
		// Net:    fmt.Sprintf("%v↑ - %v↓", bytefmt.ByteSize(up/uint64(periodic)), bytefmt.ByteSize(down/uint64(periodic))),
		Disk:   fmt.Sprintf("%.2f", nodeStatus.Disk),
		Uptime: nodeStatus.Uptime,
	}
	res, err := c.
		createCommonRequest().
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetBody(body).
		SetResult(&Response{}).
		Post(apipath)

	_, err = c.parseResponse(res, apipath, err)
	if err != nil {
		return err
	}

	return nil
}

//ReportNodeOnlineUsers reports online user ip
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {

	body := make([]NodeOnline, len(*onlineUserList))
	for i, user := range *onlineUserList {
		body[i] = NodeOnline{UID: user.UID, IP: user.IP}
	}
	path := fmt.Sprintf("nodeOnline/%d", c.NodeID)
	apipath, err := c.apiPath(path)
	if err != nil {
		return err
	}

	res, err := c.
		createCommonRequest().
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetBody(body).
		SetResult(&Response{}).
		Post(apipath)

	_, err = c.parseResponse(res, apipath, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {

	body := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		body[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   int(traffic.Upload),
			Download: int(traffic.Download)}
	}

	path := fmt.Sprintf("userTraffic/%d", c.NodeID)
	apipath, err := c.apiPath(path)
	if err != nil {
		return err
	}

	res, err := c.
		createCommonRequest().
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetBody(body).
		SetResult(&Response{}).
		Post(apipath)

	_, err = c.parseResponse(res, apipath, err)
	if err != nil {
		return err
	}

	return nil
}

// GetNodeRule will pull the audit rule form sspanel
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	path := fmt.Sprintf("nodeRule/%d", c.NodeID)
	apipath, err := c.apiPath(path)
	if err != nil {
		return nil, err
	}
	res, err := c.
		createCommonRequest().
		SetResult(&Response{}).
		Get(apipath)

	response, err := c.parseResponse(res, apipath, err)
	if err != nil {
		return nil, err
	}

	if err != nil {
		res, _ := json.Marshal(response)
		return nil, fmt.Errorf("Parse user list failed: %s", string(res))
	}
	nodeRule := new(NodeRule)
	if err := json.Unmarshal(response.Data, &nodeRule); err != nil {
		return nil, fmt.Errorf("json unmarshal failed %s ", err.Error())
	}
	var ruleList = make([]api.DetectRule, 0)
	// 模式
	////第一种：mode为all时，表示节点未设置任何审计规则，全部放行
	////第二种：mode为reject时，表示节点设置了阻断规则，凡是匹配到阻断规则的请求都要拦截
	////第三种：mode为allow时，表示节点设置了仅放行的白名单，凡是非白名单内的全部拦截，仅放行匹配了白名单规则的
	if nodeRule.Mode == "reject" {
		var rules = nodeRule.Rules
		for _, r := range rules {
			// 审计规则类型：
			////reg-正则表达式、
			////domain-域名、ip-IP、
			////protocol-应用层协议（HTTP协议、FTP协议、TELNET协议、SFTP协议、BitTorrent协议、POP3协议、IMAP协议、SMTP协议、PPTP协议、L2TP协议）
			if r.Type == "reg" {
				ruleList = append(ruleList, api.DetectRule{
					ID:      r.ID,
					Pattern: r.Pattern,
				})
			}

		}

	}

	return &ruleList, nil
}

// ReportIllegal reports the user illegal behaviors
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	path := fmt.Sprintf("trigger/%d", c.NodeID)
	apipath, err := c.apiPath(path)
	if err != nil {
		return err
	}

	for _, r := range *detectResultList {
		body := IllegalReport{
			RuleID: r.RuleID,
			UID:    r.UID,
			Reason: "reject",
		}
		res, err := c.
			createCommonRequest().
			SetHeader("Content-Type", "application/json").
			SetHeader("Accept", "application/json").
			SetBody(body).
			SetResult(&Response{}).
			Post(apipath)

		_, err = c.parseResponse(res, apipath, err)
		if err != nil {
			return err
		}

	}

	return nil
}
