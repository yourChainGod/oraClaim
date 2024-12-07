package main

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-resty/resty/v2"
	srt "github.com/juzeon/spoofed-round-tripper"
	"github.com/tidwall/gjson"
)

var (
	logger         *log.Logger
	receiveAddress string
	successMutex   sync.Mutex
	failureMutex   sync.Mutex
)

func writeToFile(filename string, content string, mutex *sync.Mutex) {
	mutex.Lock()
	defer mutex.Unlock()

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("打开文件失败", "文件", filename, "错误", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(content + "\n"); err != nil {
		logger.Error("写入文件失败", "文件", filename, "错误", err)
	}
}

func recordSuccess(address, privateKey, amount string) {
	content := fmt.Sprintf("%s----%s----%s", address, privateKey, amount)
	writeToFile("领取成功.txt", content, &successMutex)
}

func recordFailure(address, privateKey, err string) {
	content := fmt.Sprintf("%s----%s----%s", address, privateKey, err)
	writeToFile("领取失败.txt", content, &failureMutex)
}

type Task struct {
	client     *resty.Request
	privateKey *ecdsa.PrivateKey
	address    string
}

type levelStyle struct {
	text  string
	color string
}

type keyValueStyle struct {
	keyColor   string
	valueColor string
}

func initLogger() *log.Logger {
	logColors := struct {
		Error     string
		Info      string
		Success   string
		Orange    string
		Purple    string
		SeaGreen  string
		Gold      string
		Pink      string
		Cyan      string
		LightBlue string
	}{
		Error:     "#FF4D4D", // 错误红
		Info:      "#4D94FF", // 信息蓝
		Success:   "#00CC66", // 成功绿
		Orange:    "#FFA500", // 橙色
		Purple:    "#9370DB", // 紫色
		SeaGreen:  "#20B2AA", // 浅绿宝石色
		Gold:      "#FFD700", // 金色
		Pink:      "#FF69B4", // 粉色
		Cyan:      "#00CED1", // 深青色
		LightBlue: "#66CCFF", // 浅蓝色
	}

	logLevels := map[log.Level]levelStyle{
		log.ErrorLevel: {"错误", logColors.Error},
		log.InfoLevel:  {"信息", logColors.Info},
		log.WarnLevel:  {"成功", logColors.Success},
	}

	logKeyStyles := map[string]keyValueStyle{
		"错误":   {logColors.Error, ""},
		"奖励":   {logColors.Orange, logColors.Purple},
		"状态":   {logColors.SeaGreen, logColors.Gold},
		"交易ID": {logColors.Pink, logColors.Cyan},
	}
	// 创建日志实例
	logger := log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller:    false,
		ReportTimestamp: true,
		TimeFormat:      "15:04:05",
		Level:           log.InfoLevel,
		Prefix:          "hdd.cm",
	})

	// 创建样式
	styles := log.DefaultStyles()

	// 设置日志级别样式
	for level, style := range logLevels {
		styles.Levels[level] = lipgloss.NewStyle().
			SetString(style.text).
			Padding(0, 1, 0, 1).
			Foreground(lipgloss.Color(style.color))
	}

	// 设置键值样式
	for key, style := range logKeyStyles {
		styles.Keys[key] = lipgloss.NewStyle().
			Foreground(lipgloss.Color(style.keyColor))

		if style.valueColor != "" {
			styles.Values[key] = lipgloss.NewStyle().
				Foreground(lipgloss.Color(style.valueColor))
		} else {
			styles.Values[key] = lipgloss.NewStyle()
		}
	}

	// 设置默认键样式
	styles.Key = lipgloss.NewStyle().
		Foreground(lipgloss.Color(logColors.LightBlue))

	logger.SetStyles(styles)
	os.Setenv("TZ", "Asia/Jakarta")

	return logger
}

func doTask(privateKeyStr string) {
	privateKey, err := crypto.HexToECDSA(privateKeyStr)
	if err != nil {
		logger.Error("私钥转换错误", err)
		recordFailure("12345", privateKeyStr, "私钥转换错误")
		return
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		logger.Error("公钥转换错误")
		recordFailure("12345", privateKeyStr, "公钥转换错误")
		return
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	tr, err := srt.NewSpoofedRoundTripper(
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithClientProfile(profiles.Chrome_131),
	)
	if err != nil {
		recordFailure(address, privateKeyStr, "创建客户端失败")
		return
	}
	client := resty.New().SetTransport(tr).
		SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36").
		R()

	task := &Task{
		client:     client,
		privateKey: privateKey,
		address:    address,
	}

	nonce, err := task.getNonce()
	if err != nil {
		logger.Error("获取Nonce", "地址", address, "错误", err)
		recordFailure(address, privateKeyStr, "获取Nonce失败")
		return
	}

	logined, err := task.verify(nonce)
	if err != nil {
		logger.Error("登录", "地址", address, "错误", err)
		recordFailure(address, privateKeyStr, "登录失败")
		return
	}
	if !logined {
		logger.Error("登录", "地址", address, "错误", "登录失败")
		recordFailure(address, privateKeyStr, "登录失败")
		return
	}
	has, _ := task.check()
	if !has {
		logger.Info("检查", "地址", address, "错误", "没有奖励")
		recordFailure(address, privateKeyStr, "没有奖励")
		return
	}

	claimed, _ := task.claimed()
	if claimed {
		logger.Info("检查", "地址", address, "错误", "已经领取过奖励")
		recordFailure(address, privateKeyStr, "已经领取过奖励")
		return
	}

	amount, _ := task.amount()

	nonce, _ = task.nonce()

	success, _ := task.claim(nonce)
	if !success {
		logger.Error("领取奖励失败", "地址", address, "错误", "领取失败")
		recordFailure(address, privateKeyStr, "领取失败")
		return
	}

	logger.Warn("领取奖励成功", "地址", address, "奖励", amount)
	recordSuccess(address, privateKeyStr, amount)
}

func (t *Task) getNonce() (string, error) {
	resp, err := t.client.Get("https://www.ora.io/api/auth/wallet/oauth/nonce?address=" + t.address)
	if err != nil {
		logger.Error("获取Nonce", "地址", t.address, "错误", err)
		return "", err
	}
	nonce := gjson.Get(resp.String(), "data").String()
	return nonce, nil
}

func (t *Task) verify(nonce string) (bool, error) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(nonce), nonce)
	signature, err := crypto.Sign(crypto.Keccak256Hash([]byte(msg)).Bytes(), t.privateKey)
	if err != nil {
		logger.Error("签名错误", "地址", t.address, "错误", err)
		return false, err
	}
	signature[64] += 27
	jsonData := map[string]string{
		"address":      t.address,
		"redirect_url": "https://foundation.ora.io/app/airdrop/",
		"signature":    hexutil.Encode(signature),
	}

	resp, err := t.client.
		SetHeader("Content-Type", "application/json").
		SetBody(jsonData).
		Post("https://www.ora.io/api/v2/auth/wallet/oauth/verify")

	if err != nil {
		logger.Error("登录", "地址", t.address, "错误", err)
		return false, err
	}
	token := gjson.Get(resp.String(), "token.token").String()
	t.client.SetHeader("authorization", "Bearer "+token)
	return true, nil
}

func (t *Task) check() (bool, error) {
	resp, err := t.client.Get("https://www.ora.io/api/user/airdrop/check")
	if err != nil {
		logger.Error("检查空投", "地址", t.address, "错误", err)
		return false, err
	}
	has := gjson.Get(resp.String(), "has").Bool()
	return has, nil
}

func (t *Task) amount() (string, error) {
	resp, err := t.client.Get("https://www.ora.io/api/user/airdrop/amount")
	if err != nil {
		logger.Error("获取空投金额", "地址", t.address, "错误", err)
		return "", err
	}
	amount := gjson.Get(resp.String(), "amount").Int()
	amountStr := fmt.Sprintf("%.4f", float64(amount)/1000000000000000000)
	return amountStr, nil
}

func (t *Task) claimed() (bool, error) {
	resp, err := t.client.Get("https://www.ora.io/api/user/airdrop/claimed")
	if err != nil {
		logger.Error("获取空投状态", "地址", t.address, "错误", err)
		return false, err
	}
	claimed := gjson.Get(resp.String(), "is_claimed").Bool()
	return claimed, nil
}

func (t *Task) nonce() (string, error) {
	json_data := map[string]string{
		"receive_address": receiveAddress,
	}
	resp, err := t.client.
		SetBody(json_data).
		Post("https://www.ora.io/api/user/airdrop/nonce")
	if err != nil {
		logger.Error("创建请求错误", "地址", t.address, "错误", err)
		return "", err
	}
	nonce := gjson.Get(resp.String(), "nonce").String()
	return nonce, nil
}

func (t *Task) claim(nonce string) (bool, error) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(nonce), nonce)
	signature, err := crypto.Sign(crypto.Keccak256Hash([]byte(msg)).Bytes(), t.privateKey)
	if err != nil {
		logger.Error("签名错误", "地址", t.address, "错误", err)
		return false, err
	}
	signature[64] += 27
	json_data := map[string]string{
		"receive_address": receiveAddress,
		"signature":       hexutil.Encode(signature),
	}
	resp, err := t.client.
		SetBody(json_data).
		Post("https://www.ora.io/api/user/airdrop/claim")
	if err != nil {
		logger.Error("创建请求错误", "地址", t.address, "错误", err)
		return false, err
	}
	success := gjson.Get(resp.String(), "success").Bool()
	return success, nil

}

func main() {
	logger = initLogger()
	var filePath string
	fmt.Print("请输入地址私钥文件路径:")
	fmt.Scanln(&filePath)
	var receive_address string
	fmt.Print("请输入接收地址:")
	fmt.Scanln(&receive_address)
	receiveAddress = strings.TrimSpace(receive_address)

	// 读取文件内容
	content, err := os.ReadFile(filePath)
	if err != nil {
		logger.Fatal("读取文件失败", "错误", err)
	}

	// 按行分割
	lines := strings.Split(string(content), "\n")
	validLines := make([]string, 0)
	for _, line := range lines {
		if line == "" {
			continue
		}
		validLines = append(validLines, line)
	}

	// 创建并发控制channel
	sem := make(chan struct{}, 10) // 限制5个并发
	var wg sync.WaitGroup

	// 处理每一行
	for _, line := range validLines {
		// 按----分割，获取私钥
		parts := strings.Split(line, "----")
		if len(parts) < 2 {
			logger.Error("无效的行格式", "行内容", line)
			continue
		}
		privateKey := strings.TrimSpace(parts[1])
		address := parts[0]

		wg.Add(1)
		go func(pk, addr string) {
			defer wg.Done()
			sem <- struct{}{}        // 获取信号量
			defer func() { <-sem }() // 释放信号量

			logger.Info("开始处理私钥", "地址", addr)
			doTask(pk)
			time.Sleep(time.Second * 2)
		}(privateKey, address)
	}

	// 等待所有任务完成
	wg.Wait()
	logger.Info("所有任务处理完成")
}
