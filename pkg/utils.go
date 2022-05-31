package pkg

import (
	"regexp"
	"strings"
)

func writeToExcel() {}

func CheckRegexString(regString string, htmlContent string) (finding string) {
	re := regexp.MustCompile(regString)
	finding = re.FindString(htmlContent)

	return

}

func CheckColumnKey(columnName []string, m map[string]int, key string) string {
	if value, ok := m[key]; ok {
		//return utils.StringstripToSemicolon(columnName[value])
		return columnName[value]
	} else {
		return ""
	}
}

func TrimString(s string) string {
	s = strings.Replace(s, "\r", "", -1)
	s = strings.Replace(s, "\n", "", -1)
	s = strings.Replace(s, " ", "", -1)
	return s
}
