package pkg

type RsasScanner struct {
	Account      string
	Password     string
	AllVulnInfos []HtmlVulnInfo
	//AssetInfos   []AssetInfo
	//AssetExcel   string
	//ZipResult    string
	//VulnExcel    string
	//OldVulnExcel string
	//OutputFileName string
}

type HtmlAllVulnInfo struct {
	HtmlVulnInfos []HtmlVulnInfo
}

type VulnInfoWithAssetInfo struct {
	HtmlVulnInfo HtmlVulnInfo
	//AssetInfos   AssetInfo
}

//type AssetInfo struct {
//	productLine    string
//	DPlMNumber     string
//	IpAddress      string
//	Mail           string
//	AppName        string
//	ManagerName    string
//	DevEnvironment string
//	Ascription     string
//}

type HtmlVulnInfo struct {
	IpAddress     string
	Port          string
	Protocol      string
	Service       string
	VulnInfos     string
	RiskLevel     string
	Details       string
	Solution      string
	CVENumber     string
	ServiceDetail string
	Record        string
}

const nginxVersion = `1.18.0`
const tomcatVersion = `9.0.40`
const IIS = `10`
const mysql = `5.7.31`
const redisVersion = `6.0.8`
const dotNet = `4.8`
const RabbitMQ = `3.8.2`
