package pkg

import (
	"archive/zip"
	"errors"
	"fmt"
	"github.com/antchfx/htmlquery"
	"github.com/schollz/progressbar/v3"
	"github.com/xuri/excelize/v2"
	"golang.org/x/net/html"
	"io"
	"regexp"
	"strconv"
	"strings"
)

func RsasInit() *RsasScanner {
	return &RsasScanner{}
}

func (RsasScanner *RsasScanner) AnalyseZip(zipFile string) bool {
	//var filenames []string
	print("解析zip: " + zipFile)
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return false
	}
	defer r.Close()
	var htmlAllVulnInfos []HtmlAllVulnInfo
	for _, f := range r.File {
		//println(f.Name)
		re := regexp.MustCompile(`host/.*?.html`)
		htmlFilename := re.FindAllString(f.Name, -1)
		if len(htmlFilename) >= 1 {

			htmlContent := GetHtmlContent(f)
			if htmlContent != "" {
				htmlAllVulnInfo := QueryHtmlInfo(htmlContent)
				//for _, vuln := range htmlAllVulnInfo.HtmlVulnInfos {
				//	fmt.Printf(vuln.Solution)
				//}
				htmlAllVulnInfos = append(htmlAllVulnInfos, htmlAllVulnInfo)
			}
		}

	}
	for _, eachHtmlVuln := range htmlAllVulnInfos {
		for _, eachVuln := range eachHtmlVuln.HtmlVulnInfos {
			RsasScanner.AllVulnInfos = append(RsasScanner.AllVulnInfos, eachVuln)
		}
	}

	return true
}

func MergeRsasVulnToExcel(zipFile string, outputFilename string) error {
	//print("执行中")
	if zipFile == "" {
		return errors.New("请输入压缩文件文件名, -h 弹出帮助菜单")
	}
	rsas := RsasInit()
	rsas.AnalyseZip(zipFile)
	rsas.GenerateXlsx(outputFilename)
	//fmt.Printf("%v", rsas.AllVulnInfos)

	return nil
}

func GetHtmlContent(filename *zip.File) string {
	//println("打印..")
	htmlContent, err := filename.Open()
	if err != nil {
		println("解析html有问题")
	}
	//io流转string
	if b, err := io.ReadAll(htmlContent); err == nil {
		return string(b)
	}
	return ""
}

func QueryHtmlInfo(content string) (htmlAllVulnInfo HtmlAllVulnInfo) {
	//var htmlAllVulnInfo  HtmlAllVulnInfo

	doc, err := htmlquery.Parse(strings.NewReader(content))
	if err != nil {
		println(err)
	}

	//println(htmlquery.InnerText(ip)) //ip
	ip := htmlquery.FindOne(doc, "//*[@id=\"content\"]/div[2]/table[2]/tbody/tr/td[1]/table/tbody/tr[1]/td")

	if strings.Contains(content, "非常安全（0分）") {
		println(htmlquery.InnerText(ip) + " 无漏洞")
	} else {
		vulnDetail := htmlquery.FindOne(doc, "//*[@id=\"vuln_list\"]/tbody")

		//ip := htmlquery.FindOne(doc, "//*[@id=\"content\"]/div[2]/table[2]/tbody/tr/td[1]/table/tbody/tr[1]/td")

		nodes := htmlquery.Find(vulnDetail, "//tr")
		htmlAllVulnInfo = FindVulnDetails(nodes, ip)
		//htmlVulnInfo.IpAddress = htmlquery.InnerText(ip)
		//htmlAllVulnInfo.HtmlVulnInfos = append(htmlAllVulnInfo.HtmlVulnInfos, htmlVulnInfo)
		vulnSolutionNode := htmlquery.FindOne(doc, "//*[@id=\"vul_detail\"]/table")
		solutionVulnInfos := FindVulnSolution(vulnSolutionNode)
		for _, solutionVulnInfo := range solutionVulnInfos {
			for i, htmlVulnInfo := range htmlAllVulnInfo.HtmlVulnInfos {
				if htmlVulnInfo.VulnInfos == solutionVulnInfo.VulnInfos {
					//println("找到解决方法：" + htmlVulnInfo.VulnInfos)

					htmlAllVulnInfo.HtmlVulnInfos[i].Solution = solutionVulnInfo.Solution
					htmlAllVulnInfo.HtmlVulnInfos[i].CVENumber = solutionVulnInfo.CVENumber
					htmlAllVulnInfo.HtmlVulnInfos[i].Details = solutionVulnInfo.Details
					htmlAllVulnInfo.HtmlVulnInfos[i].RiskLevel = solutionVulnInfo.RiskLevel

				}
			}
		}
	}

	return htmlAllVulnInfo
}

func FindVulnDetails(nodes []*html.Node, ip *html.Node) HtmlAllVulnInfo {
	var htmlAllVulnInfo HtmlAllVulnInfo
	var htmlVulnInfo HtmlVulnInfo
	filterFirstLine := false
	for _, node := range nodes {
		if !filterFirstLine {
			filterFirstLine = true
			continue
		}

		td := htmlquery.Find(node, "//td")
		htmlVulnInfo.IpAddress = htmlquery.InnerText(ip)
		htmlVulnInfo.Port = htmlquery.InnerText(td[0])
		htmlVulnInfo.Protocol = htmlquery.InnerText(td[1])
		htmlVulnInfo.Service = htmlquery.InnerText(td[2])
		if JudgeMutiVulnName(td[3]) {
			vulnInfos := AddMutiVulnName(td[3], htmlVulnInfo)
			for _, vulnInfo := range vulnInfos {
				htmlAllVulnInfo.HtmlVulnInfos = append(htmlAllVulnInfo.HtmlVulnInfos, vulnInfo)
			}
		} else {
			htmlVulnInfo.VulnInfos = htmlquery.InnerText(htmlquery.FindOne(td[3], "//span"))
			htmlVulnInfo.VulnInfos = strings.Replace(htmlVulnInfo.VulnInfos, "\r", "", -1)
			htmlVulnInfo.VulnInfos = strings.Replace(htmlVulnInfo.VulnInfos, "\n", "", -1)
			htmlVulnInfo.VulnInfos = strings.Replace(htmlVulnInfo.VulnInfos, " ", "", -1)
			versionDiv, _ := htmlquery.QueryAll(td[3], "//div/div")
			if len(versionDiv) == 0 {
				htmlVulnInfo.ServiceDetail = ""
			} else {
				//println("端口" + htmlVulnInfo.Port)
				//println(len(versionDiv))
				htmlVulnInfo.ServiceDetail = TrimString(htmlquery.InnerText(versionDiv[0]))

				//println("单漏洞版本号: " + htmlVulnInfo.ServiceDetail)
			}

			htmlVulnInfo.ServiceDetail = TrimString(htmlVulnInfo.ServiceDetail)
			htmlAllVulnInfo.HtmlVulnInfos = append(htmlAllVulnInfo.HtmlVulnInfos, htmlVulnInfo)
		}

		//for _, n := range td {
		//
		//	//text := strings.Replace(htmlquery.InnerText(n), "\r", "", -1)
		//	//text = strings.Replace(text, "\n", "", -1)
		//	//text = strings.Replace(text, " ", "", -1)
		//	println(text)
		//}
	}
	return htmlAllVulnInfo
}

func JudgeMutiVulnName(td *html.Node) bool {
	span := htmlquery.Find(td, "//span")
	if len(span) > 1 {
		return true
	}
	return false
}

func AddMutiVulnName(td *html.Node, vulnInfo HtmlVulnInfo) (vulnInfos []HtmlVulnInfo) {

	spans := htmlquery.Find(td, "//span")

	for i, span := range spans {
		eachVulnInfo := HtmlVulnInfo{
			IpAddress: vulnInfo.IpAddress,
			Port:      vulnInfo.Port,
			Service:   vulnInfo.Service,
			Protocol:  vulnInfo.Protocol,
		}
		//println("端口" + vulnInfo.Port)

		versionDiv, _ := htmlquery.QueryAll(td, "//ul/li["+strconv.Itoa(i+1)+"]/div/div") ///html/body/div/div[4]/div[4]/div[2]/table/tbody/tr[8]/td[4]/ul/li[1]/div/div
		if len(versionDiv) == 0 {

			eachVulnInfo.ServiceDetail = ""
		} else {

			eachVulnInfo.ServiceDetail = TrimString(htmlquery.InnerText(versionDiv[0]))
			//eachVulnInfo.ServiceDetail = htmlquery.SelectAttr(versionDiv, "class")
			//println("多漏洞 版本号:" + eachVulnInfo.ServiceDetail)
		}

		eachVulnInfo.VulnInfos = htmlquery.InnerText(span)
		eachVulnInfo.VulnInfos = strings.Replace(eachVulnInfo.VulnInfos, "\r", "", -1)
		eachVulnInfo.VulnInfos = strings.Replace(eachVulnInfo.VulnInfos, "\n", "", -1)
		eachVulnInfo.VulnInfos = strings.Replace(eachVulnInfo.VulnInfos, " ", "", -1)
		vulnInfos = append(vulnInfos, eachVulnInfo)
	}
	return
}

//先提取所有漏洞修复，再根据漏洞名称分配至每个漏洞内。
func FindVulnSolution(vulnSolutionNode *html.Node) (solutionVulninfos []HtmlVulnInfo) {
	var count int
	var solutionVulnInfo HtmlVulnInfo
	nodes := htmlquery.Find(vulnSolutionNode, "//tr")
	for _, node := range nodes {
		//匹配修复表格中漏洞名称
		trClass := htmlquery.SelectAttr(node, "data-id")
		if trClass != "" {
			vulnName := htmlquery.InnerText(htmlquery.FindOne(node, "//td//span"))
			vulnName = strings.Replace(vulnName, "\r", "", -1)
			vulnName = strings.Replace(vulnName, "\n", "", -1)
			vulnName = strings.Replace(vulnName, " ", "", -1)
			solutionVulnInfo.VulnInfos = vulnName
			//println(vulnName)
			//漏洞等级
			spanClass := htmlquery.FindOne(node, "//span")
			className := htmlquery.SelectAttr(spanClass, "class")
			if className != "" {
				className = strings.Split(className, "_")[2]
				solutionVulnInfo.RiskLevel = GetChineseRiskLevel(className)
				//println(solutionVulnInfo.RiskLevel)
			}
			count += 1
		}

		trsolutionClass := htmlquery.SelectAttr(node, "class")
		if trsolutionClass == "solution" || trsolutionClass == "solution hide" {
			trsolutionTable := htmlquery.FindOne(node, "//table")
			GetSolutionInfo(trsolutionTable, &solutionVulnInfo)
			count += 1
		}
		if count == 2 {
			count = 0
			solutionVulninfos = append(solutionVulninfos, solutionVulnInfo)
			solutionVulnInfo = HtmlVulnInfo{}
		}
	}
	return
}

func GetChineseRiskLevel(level string) (chineseLevel string) {
	if level == "low" {
		return "低"
	}
	if level == "middle" {
		return "中"
	}
	if level == "high" {
		return "高"
	}
	return "未定级"
}

func GetSolutionInfo(htmlTable *html.Node, solutionVulnInfo *HtmlVulnInfo) {
	tr := htmlquery.Find(htmlTable, "//tr")
	for _, line := range tr {
		th := htmlquery.FindOne(line, "//th")

		if htmlquery.InnerText(th) == "详细描述" {
			td := htmlquery.FindOne(line, "//td")
			text := htmlquery.InnerText(td)
			text = strings.Replace(text, "\r", "", -1)
			text = strings.Replace(text, "\n", "", -1)
			text = strings.Replace(text, " ", "", -1)
			solutionVulnInfo.Details = text
		}

		if htmlquery.InnerText(th) == "解决办法" {
			td := htmlquery.FindOne(line, "//td")
			text := htmlquery.InnerText(td)
			text = strings.Replace(text, "\r", "", -1)
			text = strings.Replace(text, "\n", "", -1)
			text = strings.Replace(text, " ", "", -1)
			solutionVulnInfo.Solution = text
		}
		if htmlquery.InnerText(th) == "CVE编号" {
			td := htmlquery.FindOne(line, "//td")
			text := htmlquery.InnerText(td)
			text = strings.Replace(text, "\r", "", -1)
			text = strings.Replace(text, "\n", "", -1)
			text = strings.Replace(text, " ", "", -1)
			solutionVulnInfo.CVENumber = text
		}
	}
	if solutionVulnInfo.CVENumber == "" {
		solutionVulnInfo.CVENumber = "无cve编号"
	}
}

func (RsasScanner RsasScanner) GenerateXlsx(output string) {
	filename := output + ".xlsx"

	line := len(RsasScanner.AllVulnInfos)
	bar := progressbar.Default(int64(line))
	excel := excelize.NewFile()
	excel.NewSheet("主机漏洞清单")
	excel.SetSheetRow("主机漏洞清单", "A1", &[]string{"序号", "漏洞名称", "风险等级", "漏洞描述", "整改建议", "IP地址", "端口", "协议", "服务", "漏洞CVE编号", "版本"})

	for i, infos := range RsasScanner.AllVulnInfos {
		bar.Add(1)
		axis := fmt.Sprintf("A%d", i+2)
		err := excel.SetSheetRow("主机漏洞清单", axis, &[]interface{}{
			i + 1,
			infos.VulnInfos,
			infos.RiskLevel,
			infos.Details,
			infos.Solution,
			infos.IpAddress,
			infos.Port,
			infos.Protocol,
			infos.Service,
			infos.CVENumber,
			infos.ServiceDetail,
		})
		if err != nil {
			println(err)
		}
	}

	excel.DeleteSheet("Sheet1")

	err := excel.SaveAs(filename)
	if err != nil {
		println(err.Error())
	} else {
		println("保存为：" + filename + ".xlsx")
	}
}

//
////检查是否有漏报情况
//func CheckVulnHasAssetInfo() {}
//
////根据基线规则匹配是否排除漏洞 true 为满足基线
//func JudgeWithBaseLine(vulnWithAsset VulnInfoWithAssetInfo) (bool, string) {
//
//	if JudgeNginx(vulnWithAsset) {
//		return true, "nginx版本为 " + vulnWithAsset.HtmlVulnInfo.ServiceDetail + " ,符合基线要求,暂不处理"
//	}
//	if JudgeTomcat(vulnWithAsset) {
//		return true, "tomcat版本为 " + vulnWithAsset.HtmlVulnInfo.ServiceDetail + " ,符合基线要求,暂不处理"
//	}
//	if JudgeSql(vulnWithAsset) {
//		return true, vulnWithAsset.HtmlVulnInfo.VulnInfos + " 为数据库漏洞,暂不处理"
//	}
//	if JudgeRedis(vulnWithAsset) {
//		return true, "redis版本为 " + vulnWithAsset.HtmlVulnInfo.ServiceDetail + " ,符合基线要求,暂不处理"
//	}
//	if JudgeRabbitMQ(vulnWithAsset) {
//		return true, "RabbitMQ版本为 " + vulnWithAsset.HtmlVulnInfo.ServiceDetail + " ,符合基线要求,暂不处理"
//	}
//	if JudgeOpenSSL(vulnWithAsset) {
//		return true, vulnWithAsset.HtmlVulnInfo.VulnInfos + " 为openssl漏洞,暂不处理"
//	}
//

//	if JudgeTls(vulnWithAsset) {
//		return true, vulnWithAsset.HtmlVulnInfo.VulnInfos + " 为ssl/tls漏洞,暂不处理"
//	}
//	return false, ""
//}
//
////检查ng基线 true为符合基线
//func JudgeNginx(vulnWithAsset VulnInfoWithAssetInfo) bool {
//	vulnBanner := strings.ToLower(vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//	if strings.Contains(vulnBanner, "nginx/") {
//		ngBanner := strings.Replace(vulnBanner, "nginx/", "", 1)
//		ngbaseInt, err := strconv.Atoi(strings.Replace(nginxVersion, ".", "", -1))
//		if err != nil {
//			println("nginx基线常量有问题: " + nginxVersion)
//			return false
//		}
//		ngBannerInt, err := strconv.Atoi(strings.Replace(ngBanner, ".", "", -1))
//		if err != nil {
//			println("nginx版本获取有问题！漏洞名称:" + vulnWithAsset.HtmlVulnInfo.VulnInfos + " ip: " + vulnWithAsset.HtmlVulnInfo.IpAddress + "ng信息: " + vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//			return false
//		}
//		ngBannerIntPrefix, err := strconv.Atoi(strings.Split(ngBanner, ".")[0] + strings.Split(ngBanner, ".")[1])
//		ngBaseIntPrefix, err := strconv.Atoi(strings.Split(nginxVersion, ".")[0] + strings.Split(nginxVersion, ".")[1])
//		if ngBannerInt >= ngbaseInt && ngBannerIntPrefix >= ngBaseIntPrefix {
//			return true
//		}
//	}
//
//	return false
//}
//
//func JudgeTomcat(vulnWithAsset VulnInfoWithAssetInfo) bool {
//	vulnBanner := strings.ToLower(vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//	if strings.Contains(vulnBanner, "tomcat/") {
//		tomcatBanner := strings.Replace(vulnBanner, "tomcat/", "", 1)
//		tomcatBanner = strings.Replace(tomcatBanner, ".tar", "", 1)
//		tomcatBanner = strings.Replace(tomcatBanner, " ", "", -1)
//		tomcatBaseInt, err := strconv.Atoi(strings.Replace(tomcatVersion, ".", "", -1))
//		if err != nil {
//			println("tomcat版本常量有问题: " + tomcatVersion)
//			return false
//		}
//		tomcatBannerInt, err := strconv.Atoi(strings.Replace(tomcatBanner, ".", "", -1))
//		if err != nil {
//			println("tomcat版本获取有问题！漏洞名称:" + vulnWithAsset.HtmlVulnInfo.VulnInfos + " ip: " + vulnWithAsset.HtmlVulnInfo.IpAddress + "ng信息: " + vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//			return false
//		}
//		tomcatBannerIntPrefix, err := strconv.Atoi(strings.Split(tomcatBanner, ".")[0] + strings.Split(tomcatBanner, ".")[1])
//		tomcatBaseIntPrefix, err := strconv.Atoi(strings.Split(tomcatVersion, ".")[0] + strings.Split(tomcatVersion, ".")[1])
//		if tomcatBannerInt >= tomcatBaseInt && tomcatBannerIntPrefix >= tomcatBaseIntPrefix {
//			return true
//		}
//	}
//	return false
//}
//
////数据库类型匹配到就不修复
//func JudgeSql(vulnWithAsset VulnInfoWithAssetInfo) bool {
//	vulnBanner := strings.ToLower(vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//	if strings.Contains(vulnBanner, "mysql/") {
//		return true
//	}
//	if strings.Contains(vulnBanner, "mariadb/") {
//		return true
//	}
//	if strings.Contains(vulnBanner, "mongodb/") {
//		return true
//	}
//
//	return false
//}
//
//func JudgeRedis(vulnWithAsset VulnInfoWithAssetInfo) bool {
//	vulnBanner := strings.ToLower(vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//	if strings.Contains(vulnBanner, "redis/") {
//		redisBanner := strings.Replace(vulnBanner, "redis/", "", 1)
//		redisBaseInt, err := strconv.Atoi(strings.Replace(redisVersion, ".", "", -1))
//		if err != nil {
//			println("redis版本常量有问题: " + redisVersion)
//			return false
//		}
//		redisBannerInt, err := strconv.Atoi(strings.Replace(redisBanner, ".", "", -1))
//		if err != nil {
//			println("redis版本获取有问题！漏洞名称:" + vulnWithAsset.HtmlVulnInfo.VulnInfos + " ip: " + vulnWithAsset.HtmlVulnInfo.IpAddress + "ng信息: " + vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//			return false
//		}
//		redisBannerIntPrefix, err := strconv.Atoi(strings.Split(redisBanner, ".")[0] + strings.Split(redisBanner, ".")[1])
//		redisBaseIntPrefix, err := strconv.Atoi(strings.Split(redisVersion, ".")[0] + strings.Split(redisVersion, ".")[1])
//		if redisBannerInt >= redisBaseInt && redisBannerIntPrefix >= redisBaseIntPrefix {
//			return true
//		}
//	}
//	return false
//
//}
//
//func JudgeRabbitMQ(vulnWithAsset VulnInfoWithAssetInfo) bool {
//	vulnBanner := strings.ToLower(vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//	if strings.Contains(vulnBanner, "rabbitmq/") {
//		rabbitmqBanner := strings.Replace(vulnBanner, "rabbitmq/", "", 1)
//		rabbitmqBaseInt, err := strconv.Atoi(strings.Replace(RabbitMQ, ".", "", -1))
//		if err != nil {
//			println("RabbitMQ版本常量有问题: " + RabbitMQ)
//			return false
//		}
//		rabbitmqBannerInt, err := strconv.Atoi(strings.Replace(rabbitmqBanner, ".", "", -1))
//		if err != nil {
//			println("RabbitMQ版本获取有问题！漏洞名称:" + vulnWithAsset.HtmlVulnInfo.VulnInfos + " ip: " + vulnWithAsset.HtmlVulnInfo.IpAddress + "ng信息: " + vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//			return false
//		}
//		rabbitmqBannerIntPrefix, err := strconv.Atoi(strings.Split(rabbitmqBanner, ".")[0] + strings.Split(rabbitmqBanner, ".")[1])
//		rabbitmqBaseIntPrefix, err := strconv.Atoi(strings.Split(RabbitMQ, ".")[0] + strings.Split(RabbitMQ, ".")[1])
//		if rabbitmqBannerInt >= rabbitmqBaseInt && rabbitmqBannerIntPrefix >= rabbitmqBaseIntPrefix {
//			return true
//		}
//	}
//	return false
//
//}
//
//func JudgeOpenSSL(vulnWithAsset VulnInfoWithAssetInfo) bool {
//	vulnBanner := strings.ToLower(vulnWithAsset.HtmlVulnInfo.ServiceDetail)
//	if strings.Contains(vulnBanner, "openssl/") && strings.Contains(strings.ToLower(vulnWithAsset.HtmlVulnInfo.VulnInfos), "openssl") {
//		return true
//	}
//	return false
//}
//
//func JudgeTls(vulnWithAsset VulnInfoWithAssetInfo) bool {
//	vulnName := strings.ToLower(vulnWithAsset.HtmlVulnInfo.VulnInfos)
//	if strings.Contains(vulnName, "ssl/tls") || strings.Contains(vulnName, "tlsclient") {
//		return true
//	}
//	return false
//}
