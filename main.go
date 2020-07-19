package main

import (
	//	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	//	"strconv"

	"bufio"
	"strings"

	_ "github.com/lib/pq"
	"github.com/xormplus/xorm"
)

var engine *xorm.Engine

const (
	tableVulcve = "vulcve"
)

func (*Vulnerability) TableName() string {
	return tableVulcve
}

type NvdCve struct {
	CVEDataType         string `json:"CVE_data_type"`
	CVEDataFormat       string `json:"CVE_data_format"`
	CVEDataVersion      string `json:"CVE_data_version"`
	CVEDataNumberOfCVEs string `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string `json:"CVE_data_timestamp"`
	CVEItems            []struct {
		Cve struct {
			DataType    string `json:"data_type"`
			DataFormat  string `json:"data_format"`
			DataVersion string `json:"data_version"`
			CVEDataMeta struct {
				ID       string `json:"ID"`
				ASSIGNER string `json:"ASSIGNER"`
			} `json:"CVE_data_meta"`
			Problemtype struct {
				ProblemtypeData []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"problemtype_data"`
			} `json:"problemtype"`
			References struct {
				ReferenceData []struct {
					URL       string        `json:"url"`
					Name      string        `json:"name"`
					Refsource string        `json:"refsource"`
					Tags      []interface{} `json:"tags"`
				} `json:"reference_data"`
			} `json:"references"`
			Description struct {
				DescriptionData []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
		} `json:"cve"`
		Configurations struct {
			CVEDataVersion string `json:"CVE_data_version"`
			Nodes          []struct {
				Operator string `json:"operator"`
				Children []struct {
					Operator string `json:"operator"`
					CpeMatch []struct {
						Vulnerable bool   `json:"vulnerable"`
						Cpe23URI   string `json:"cpe23Uri"`
					} `json:"cpe_match"`
				} `json:"children,omitempty"`
				CpeMatch []struct {
					Vulnerable            bool   `json:"vulnerable"`
					Cpe23URI              string `json:"cpe23Uri"`
					VersionStartIncluding string `json:"versionStartIncluding"`
					VersionStartExcluding string `json:"versionStartExcluding"`
					VersionEndExcluding   string `json:"versionEndExcluding"`
					VersionEndIncluding   string `json:"versionEndIncluding"`
				} `json:"cpe_match,omitempty"`
			} `json:"nodes"`
		} `json:"configurations"`
		Impact struct {
			BaseMetricV3 struct {
				CvssV3 struct {
					Version               string  `json:"version"`
					VectorString          string  `json:"vectorString"`
					AttackVector          string  `json:"attackVector"`
					AttackComplexity      string  `json:"attackComplexity"`
					PrivilegesRequired    string  `json:"privilegesRequired"`
					UserInteraction       string  `json:"userInteraction"`
					Scope                 string  `json:"scope"`
					ConfidentialityImpact string  `json:"confidentialityImpact"`
					IntegrityImpact       string  `json:"integrityImpact"`
					AvailabilityImpact    string  `json:"availabilityImpact"`
					BaseScore             float64 `json:"baseScore"`
					BaseSeverity          string  `json:"baseSeverity"`
				} `json:"cvssV3"`
				ExploitabilityScore float64 `json:"exploitabilityScore"`
				ImpactScore         float64 `json:"impactScore"`
			} `json:"baseMetricV3"`
			BaseMetricV2 struct {
				CvssV2 struct {
					Version               string  `json:"version"`
					VectorString          string  `json:"vectorString"`
					AccessVector          string  `json:"accessVector"`
					AccessComplexity      string  `json:"accessComplexity"`
					Authentication        string  `json:"authentication"`
					ConfidentialityImpact string  `json:"confidentialityImpact"`
					IntegrityImpact       string  `json:"integrityImpact"`
					AvailabilityImpact    string  `json:"availabilityImpact"`
					BaseScore             float64 `json:"baseScore"`
				} `json:"cvssV2"`
				Severity                string  `json:"severity"`
				ExploitabilityScore     float64 `json:"exploitabilityScore"`
				ImpactScore             float64 `json:"impactScore"`
				ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
				ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
				ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
				UserInteractionRequired bool    `json:"userInteractionRequired"`
			} `json:"baseMetricV2"`
		} `json:"impact"`
		PublishedDate    string `json:"publishedDate"`
		LastModifiedDate string `json:"lastModifiedDate"`
	} `json:"CVE_Items"`
}

type Vulnerability struct {
	Id               int             `xorm:"pk autoincr  'id'"`
	Name             string          `xorm:"VARCHAR(128) 'name'"`
	VulTitle         string          `xorm:"VARCHAR(255) 'vultitle'"`
	VulDesc          string          `xorm:"'vuldesc'"`
	VulNotice        string          `xorm:"vulnotice"`
	VulReflink       string          `xorm:"'vulreflink'"`
	VulEnt           string          `xorm:"'vulent'"`
	VulPat           string          `xorm:"'vulpat'"`
	Metadata         json.RawMessage `xorm:"'metadata'"`
	Advice           string          `xorm:"'advice'"`
	Must             int             `xorm:"'must'"`
	Severity         string          `xorm:"VARCHAR(128) 'severity'"`
	VulType          string          `xorm:"VARCHAR(128) 'vultype'"`
	Cnnvd            string          `xorm:"VARCHAR(128) 'cnnvd'"`
	PackageName      string          `xorm:"VARCHAR(255) 'package_name'"`
	Description      string          `xorm:"'description'"`
	Link             string          `xorm:"'link'"`
	FixedIn          string          `xorm:"'fixed_in'"`
	Affected         string          `xorm:"'affected'"`
	Namespace        string          `xorm:"VARCHAR(255) 'namespace'"`
	RemoteExecution  int             `xorm:"'remoteexecution'"`
	Critical         int             `xorm:"'critical'"`
	Hasfix           int             `xorm:"'hasfix'"`
	Hasexp           int             `xorm:"'hasexp'"`
	AttackVector     string          `xorm:"VARCHAR(255) 'attack_vector'"`
	AttackComplexity string          `xorm:"VARCHAR(255) 'attack_complexity'"`
}

type Result struct {
	CveDataType         string    `json:"CVE_data_type"`
	CveDataFormat       string    `json:"CVE_data_format"`
	CveDataVersion      string    `json:"CVE_data_version"`
	CveDataNumberOfCVEs string    `json:"CVE_data_numberOfCVEs"`
	CveItems            []CveItem `json:"CVE_Items"`
}
type CveItem struct {
	Cve              Cve            `json:"cve"`
	Configurations   Configurations `json:"configurations"`
	Impact           Impact         `json:"impact"`
	PublishedDate    string         `json:"publishedDate"`
	LastModifiedDate string         `json:"lastModifiedDate"`
}

//一级
type Cve struct {
	CveDataMeta CveDataMeta `json:"CVE_data_meta"`
	Affects     Affects     `affects`
	ProblemType ProblemType `problemtype`
	References  References  `references`
	Description Description `description`
}

//二级
type CveDataMeta struct {
	ID       string `json:"ID"`
	ASSIGNER string `json:"ASSIGNER"`
}

//二级
type Affects struct {
	Vendor Vendor `json:"vendor"`
}

//三级
type Vendor struct {
	VendorData []VendorDataItem `json:"vendor_data"`
}

//四级
type VendorDataItem struct {
	VendorName string  `json:"vendor_name"`
	Product    Product `json:"product"`
}

//五级
type Product struct {
	ProductData []ProductDataItem `json:"product_data"`
}

//六级
type ProductDataItem struct {
	ProductName string  `json:"product_name"`
	Version     Version `json:"version"`
}

//七级
type Version struct {
	VersionData []VersionDataItem `json:"version_data"`
}

//八级
type VersionDataItem struct {
	VersionValue    string `json:"version_value"`
	VersionAffected string `json:"version_affected"`
}

//二级
type ProblemType struct {
	ProblemtypeData []ProblemtypeDataItem `json:"problemtype_data"`
}

//三级
type ProblemtypeDataItem struct {
	Description []ProblemtypeDataItemDescription `json:"description"`
}

//四级
type ProblemtypeDataItemDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

//二级
type References struct {
	ReferenceData []ReferenceDataItem `json:"reference_data"`
}

//三级
type ReferenceDataItem struct {
	Url       string   `json:"url"`
	Name      string   `json:"name"`
	refsource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

//二级
type Description struct {
	DescriptionData []DescriptionDataItem `json:"description_data"`
}

//三级
type DescriptionDataItem struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

//一级
type Configurations struct {
	CveDataVersion string      `json:"cve_data_version"`
	Nodes          []NodesItem `json:"nodes"`
}

//二级
type NodesItem struct {
	Operator string `json:"operator"`
	Children []struct {
		Operator string         `json:"operator"`
		CpeMatch []CpeMatchItem `json:"cpe_match"`
	} `json:"children,omitempty"`
	CpeMatch []CpeMatchItem `json:"cpe_match"`
}

//三级
type CpeMatchItem struct {
	Vulnerable            bool   `json:"vulnerable"`
	Cpe23Uri              string `json:"cpe23Uri"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
}

//一级
type Impact struct {
	BaseMetricV3 BaseMetricV3 `json:"baseMetricV3"`
	BaseMetricV2 BaseMetricV2 `json:"baseMetricV2"`
}

//二级
type BaseMetricV3 struct {
	CvssV3              CvssV3  `json:"cvssV3"`
	ExploitabilityScore float32 `json:"exploitabilityScore"`
	ImpactScore         float32 `json:"impactScore"`
}

// type AutoGenerated struct {
// 	Acqusition []struct {
// 		Advisory string      `json:"advisory"`
// 		Cve      interface{} `json:"cve"`
// 		ID       string      `json:"id"`
// 		Specs    []string    `json:"specs"`
// 		V        string      `json:"v"`
// 	} `json:"acqusition"`
// }

//三级
type CvssV3 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float32 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

//二级
type BaseMetricV2 struct {
	CvssV2                  CvssV2  `json:"cvssV2"`
	Severity                string  `json:"severity"`
	ExploitabilityScore     float32 `json:"exploitabilityScore"`
	ImpactScore             float64 `json:"impactScore"`
	ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool    `json:"userInteractionRequired"`
}

//三级
type CvssV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float32 `json:"baseScore"`
}

type Cveconfig struct {
	ID       string         `json:"id"`
	CpeMatch []CpeMatchItem `json:"cpe_match"`
}

type CustomArry struct {
	CustomArr []Custom
}

type Custom struct {
	Name        string     `json:"name"`
	PackageName string     `json:"PackageName"`
	Description string     `json:"Description"`
	Severity    string     `json:"Severity"`
	Link        string     `json:"Link"`
	FixedID     string     `json:"FixedID"`
	Affected    []AFFected `json:"affected"`
	Namespace   string     `json:"Namespace"`
}
type AFFected struct {
	VersionValue    string `json:"version_value"`
	VersionAffected string `json:"version_affected"`
}
type TwistlockArry struct {
	twistArr []Twistlock
}

type Twistlock struct {
	Cve           string   `json:"cve"`
	Distro        string   `json:"distro"`
	DistroRelease string   `json:"distro_release"`
	Type          string   `json:"type"`
	Package       string   `json:"package"`
	Severity      string   `json:"severity"`
	Status        string   `json:"status"`
	Cvss          int      `json:"cvss"`
	Rules         []string `json:"rules"`
	Modified      int      `json:"modified"`
	LinkID        string   `json:"link_id"`
}

type Pythinsecure_full struct {
	AcqusiTionarr []Acqusition `json:"acqusition"`
}
type Acqusition struct {
	Advisory string      `json:"advisory"`
	Cve      interface{} `json:"cve"`
	ID       string      `json:"id"`
	Specs    []string    `json:"specs"`
	V        string      `json:"v"`
}

type AutoGenerated struct {
	Acqusition []struct {
		Advisory string      `json:"advisory"`
		Cve      interface{} `json:"cve"`
		ID       string      `json:"id"`
		Specs    []string    `json:"specs"`
		V        string      `json:"v"`
	} `json:"acqusition"`
}

// func test(nvdpath string) {

// 	nvdCve := NvdCve{}
// 	content, err := ReadFile(nvdpath) //读取nvd文件获取数据
// 	if err != nil {
// 		fmt.Println("读取文件失败")
// 		return
// 	}
// 	err = json.Unmarshal(content, &nvdCve)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	//fmt.Println(nvdCve.CVEItems[1])
// 	fmt.Printf("%+v", nvdCve.CVEItems[100])
// }

func main() {
	//ConnDB()
	// custompath := "E:\\customfile\\insecurefull.json"
	Pyth_path := "E:\\insecure_full.json"
	// for i := 2002; i <= 2019; i++ {
	// 	num := strconv.Itoa(i)
	// 	json_path := "E:\\nvd2007-2019\\nvdcve-1.1-" + num + ".json"
	// 	parseJsonData(Pyth_path)
	// }
	parseJsonData(Pyth_path)
	//json_path := "E:\\GoWork\\src\\test1\\1.json"
	//parseJsonData(json_path)
}

func ConnDB() {
	var err error
	engine, err = xorm.NewEngine("postgres", "host=db.dosec.cn port=6899 user=vludb password=5aeDeV2ML5W8pm3H dbname=vludb sslmode=disable")
	//engine.ShowSQL(true)
	if err != nil {
		log.Println(err)
	}
}
func InsertVulcve(vulData *Vulnerability) {

	var vulcve Vulnerability

	has, err := engine.Where("name=? and package_name=?", vulData.Name, vulData.PackageName).Get(&vulcve)

	if err != nil {

		fmt.Println("Get(vulcve)error:", err)
	}

	if has {
		return
	} else {
		_, err := engine.Insert(vulData)
		if err != nil {
			fmt.Println("err错误:", err)
		}

	}

}
func ReadFile(path string) (data []byte, err error) {
	jsonfile, err := os.OpenFile(path, os.O_RDONLY, 0644)
	defer jsonfile.Close()
	if err != nil {
		fmt.Println("打开文件失败")
		return
	}
	data, error := ioutil.ReadAll(jsonfile)
	if error != nil {
		return
	}
	return data, error

}

func tracefile(str string, path string) {
	fd, _ := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	//fd_time := time.Now().Format("2006-01-02 15:04:05")
	//fd_content := strings.Join([]string{"======", fd_time, "=====", str_content, "\n"}, "")

	buf := []byte(str)
	fd.Write(buf)
	fd.Close()
}
func parseJsonData(Pythonfile string) {

	//*********获取并解析nvd完成，找到关键数组
	cutFile, _ := os.Open(Pythonfile)
	defer cutFile.Close()
	cutScanner := bufio.NewScanner(cutFile)
	//	var twist TwistlockArry
	for cutScanner.Scan() {
		//	var twistlock = Twistlock{}
		lineText := cutScanner.Text()

		str := string(lineText)
		if strings.Index(str, "\"cve\":") != -1 && strings.Index(str, "null") == -1 {
			str = str + "\n"
			tracefile(str, "E:\\insecure_fullfixed.json")
		}
	}

}
