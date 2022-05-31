package cmd

import (
	"flag"
	"rsasZipToExcel/pkg"
)

func Runner() {
	//命令行
	var zipFile, outputFilename string

	flag.StringVar(&zipFile, "z", "", "-z 包含漏洞的zip文件")
	flag.StringVar(&outputFilename, "o", "", "-o 输出的文件名")

	flag.Parse()
	//拆分excel
	if outputFilename == "" {
		outputFilename = "output"
	}

	//解析zip
	err := pkg.MergeRsasVulnToExcel(zipFile, outputFilename)
	if err != nil {
		print(err.Error())
	}
	//匹配excel

	//合并输出
}

//同比上个月漏洞情况

//初始化rsas

//初始化yb

//读取配置 yaml？

//定时扫描

//触发发送？
