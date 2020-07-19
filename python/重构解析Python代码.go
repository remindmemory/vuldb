package main

import (
	"bufio"
	//	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	_ "github.com/lib/pq"
)

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
						Vulnerable            bool   `json:"vulnerable"`
						Cpe23URI              string `json:"cpe23Uri"`
						VersionStartIncluding string `json:"versionStartIncluding"`
						VersionStartExcluding string `json:"versionStartExcluding"`
						VersionEndExcluding   string `json:"versionEndExcluding"`
						VersionEndIncluding   string `json:"versionEndIncluding"`
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

type NvdData struct {
	CveDataType         string    `json:"CVE_data_type"`
	CveDataFormat       string    `json:"CVE_data_format"`
	CveDataVersion      string    `json:"CVE_data_version"`
	CveDataNumberOfCVEs string    `json:"CVE_data_numberOfCVEs"`
	CveDataTimestamp    string    `json:"CVE_data_timestamp"`
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
	DataType    string      `json:"data_type"`
	DataFormat  string      `json:"data_format"`
	DataVersion string      `json:"data_version"`
	CveDataMeta CveDataMeta `json:"CVE_data_meta"`
	ProblemType ProblemType `json:"problemtype"`
	References  References  `json:"references"`
	Description Description `json:"description"`
}

//二级
type CveDataMeta struct {
	ID       string `json:"ID"`
	ASSIGNER string `json:"ASSIGNER"`
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
	Operator    string         `json:"operator"`
	ChilDrenArr []Children     `json:"children,omitempty"`
	CpeMatch    []CpeMatchItem `json:"cpe_match"`
}
type Children struct {
	Operator string         `json:"operator"`
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

type Custom struct {
	Name        string     `json:"name"`
	PackageName string     `json:"PackageName"`
	Description string     `json:"Description"`
	Severity    string     `json:"Severity"`
	LinkArr     []LinkStr  `json:"Link"`
	FixedID     string     `json:"FixedID"`
	Affected    []AFFected `json:"affected"`
	Namespace   string     `json:"Namespace"`
}
type LinkStr struct {
	URL string `json:"url"`
}
type AFFected struct {
	VersionValue    string `json:"version_value"`
	VersionAffected string `json:"version_affected"`
}

type Typeofproduct struct {
	ProductArr []TypeOfProduct `json:"product"`
}

type TypeOfProduct struct {
	Product string `json:"product"`
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

func CompareArr(TypeofproductArr Typeofproduct, typeProduct TypeOfProduct) int {
	for _, eachItem := range TypeofproductArr.ProductArr {
		if eachItem.Product == typeProduct.Product {
			//	fmt.Println("产品已存在数组\n")
			return 0
		}
	}
	return 1
}

func GetInformation(str string) CveItem {
	NvdData := NvdData{}
	var json_path string
	string_slice := strings.Split(str, "-")
	json_path = "E:\\nvd2007-2019\\nvdcve-1.1-" + string_slice[1] + ".json"
	content, err := ReadFile(json_path) //读取nvd文件获取数据
	if err != nil {
		fmt.Println("读取文件失败")
		return CveItem{}
	}
	error := json.Unmarshal(content, &NvdData)
	if error != nil {
		fmt.Println("json解析失败:", error)
	}
	nvdCveItemData := NvdData.CveItems
	//var Cvename string
	for _, nvdCveItemDatavalue := range nvdCveItemData {
		if str == nvdCveItemDatavalue.Cve.CveDataMeta.ID {
			return nvdCveItemDatavalue
		}
	}
	return CveItem{}
}
func GetChildproductArr(NodesValue *NodesItem, TypeofproductArr Typeofproduct) Typeofproduct {
	var typeProduct TypeOfProduct
	for _, childArrvalue := range NodesValue.ChilDrenArr {
		for _, Childrenvalue := range childArrvalue.CpeMatch {
			string_slice := strings.Split(Childrenvalue.Cpe23Uri, ":")
			if Childrenvalue.Vulnerable == false || string_slice[5]=="-"{
				continue
			}
			typeProduct.Product = string_slice[4]
			if len(TypeofproductArr.ProductArr) < 1 { //数组个数小于1，直接打进去
				TypeofproductArr.ProductArr = append(TypeofproductArr.ProductArr, typeProduct)
			}
			if CompareArr(TypeofproductArr, typeProduct) == 1 { //typegate 为0的话表明已存在
				TypeofproductArr.ProductArr = append(TypeofproductArr.ProductArr, typeProduct)
			}
		}
	}
	return TypeofproductArr
}
func GetCpeMatchProductArr(NodesValue *NodesItem, TypeofproductArr Typeofproduct) Typeofproduct {
	typeProduct := TypeOfProduct{}
	for _, singleNodesValue := range NodesValue.CpeMatch {
		string_slice := strings.Split(singleNodesValue.Cpe23Uri, ":")
		if singleNodesValue.Vulnerable == false ||string_slice[5]=="-"{
			continue
		}
		//将额外的信息版本留
		typeProduct.Product = string_slice[4]
		if len(TypeofproductArr.ProductArr) < 1 { //数组个数小于1，直接打进去
			TypeofproductArr.ProductArr = append(TypeofproductArr.ProductArr, typeProduct)
		}
		if CompareArr(TypeofproductArr, typeProduct) == 1 { //typegate 为0的话表明已存在
			TypeofproductArr.ProductArr = append(TypeofproductArr.ProductArr, typeProduct)
		}
	}
	return TypeofproductArr
}
func GetProductArr(nvdCveItemData *CveItem) Typeofproduct {
	var TypeofproductArr Typeofproduct
	var childrensproduct Typeofproduct
	for _, NodesValue := range nvdCveItemData.Configurations.Nodes {
		if NodesValue.Operator == "AND" {
			childrensproduct = GetChildproductArr(&NodesValue, TypeofproductArr)
			for _, singleCpeMatchproduct := range childrensproduct.ProductArr {
				if CompareArr(TypeofproductArr, singleCpeMatchproduct) == 1 {
					TypeofproductArr.ProductArr = append(TypeofproductArr.ProductArr, singleCpeMatchproduct)
				}
			}
		}
		CpeMatchproduct := GetCpeMatchProductArr(&NodesValue, TypeofproductArr)
		for _, singleCpeMatchproduct := range CpeMatchproduct.ProductArr {
			if CompareArr(TypeofproductArr, singleCpeMatchproduct) == 1 {
				TypeofproductArr.ProductArr = append(TypeofproductArr.ProductArr, singleCpeMatchproduct)
			}
		}
	}
	return TypeofproductArr
}
func GetReference(nvdCveItemData *CveItem) []LinkStr {
	var custom Custom
	reference := nvdCveItemData.Cve.References.ReferenceData
	for _, referenceValue := range reference {
		singleLink := LinkStr{}
		singleLink.URL = referenceValue.Url
		custom.LinkArr = append(custom.LinkArr, singleLink)
	}
	return custom.LinkArr
}
func GetServerity(nvdCveItemData *CveItem) string {
	var Severity string
	if nvdCveItemData.Impact.BaseMetricV3.CvssV3.BaseSeverity == "" {
		Severity = nvdCveItemData.Impact.BaseMetricV2.Severity
	} else {
		Severity = nvdCveItemData.Impact.BaseMetricV3.CvssV3.BaseSeverity
	}
	return Severity
}
func GetChaffectArr(NodesValue *NodesItem, product string) []AFFected {
	affected := AFFected{}
	var Affectarr []AFFected

	for _, childArrvalue := range NodesValue.ChilDrenArr {
		for _, singlechildvalue := range childArrvalue.CpeMatch {
			string_slice := strings.Split(singlechildvalue.Cpe23Uri, ":")
			//将额外的信息版本留下
			if product != string_slice[4] || string_slice[5] == "-" {
				continue
			}
			if string_slice[6] == "*" || string_slice[6] == "-" {
				singlechildvalue.Cpe23Uri = string_slice[5]
			} else {
				singlechildvalue.Cpe23Uri = string_slice[5] + string_slice[6]
			}

			//********************************************************
			if singlechildvalue.VersionStartIncluding != "" { //首先判断只存在in  start数据
				affected.VersionValue = ">="
				affected.VersionAffected = singlechildvalue.VersionStartIncluding //Excluding的时候是小于	Including的时候是小于等于
				Affectarr = append(Affectarr, affected)
			}
			if singlechildvalue.VersionStartExcluding != "" { //只有ex start 数据
				affected.VersionValue = ">"
				affected.VersionAffected = singlechildvalue.VersionStartExcluding
				Affectarr = append(Affectarr, affected)
			}

			if singlechildvalue.VersionEndIncluding != "" { //只有in end数据
				affected.VersionValue = "<="
				affected.VersionAffected = singlechildvalue.VersionEndIncluding
				Affectarr = append(Affectarr, affected)
			}

			if singlechildvalue.VersionEndExcluding != "" { //只有Ex end数据
				affected.VersionValue = "<"
				affected.VersionAffected = singlechildvalue.VersionEndExcluding
				Affectarr = append(Affectarr, affected)
			}

			if singlechildvalue.VersionEndExcluding == "" && singlechildvalue.VersionEndIncluding == "" && singlechildvalue.VersionStartExcluding == "" && singlechildvalue.VersionStartIncluding == "" {
				affected.VersionValue = "="
				affected.VersionAffected = singlechildvalue.Cpe23Uri
				Affectarr = append(Affectarr, affected)
			}
		}
	}
	return Affectarr
}

func GetaffectArr(NodesValue *NodesItem, product string) []AFFected {
	var Affected []AFFected
	var affected AFFected
	for _, singleNodesValue := range NodesValue.CpeMatch {
		string_slice := strings.Split(singleNodesValue.Cpe23Uri, ":")
		if product != string_slice[4] || string_slice[5] == "-" {
			continue
		}

		if string_slice[6] == "*" || string_slice[6] == "-" {
			singleNodesValue.Cpe23Uri = string_slice[5]
		} else {
			singleNodesValue.Cpe23Uri = string_slice[5] + string_slice[6]
		}

		//********************************************************
		if singleNodesValue.VersionStartIncluding != "" { //首先判断只存在in  start数据
			affected.VersionValue = ">="
			affected.VersionAffected = singleNodesValue.VersionStartIncluding //Excluding的时候是小于	Including的时候是小于等于
			Affected = append(Affected, affected)
		}
		if singleNodesValue.VersionStartExcluding != "" { //只有ex start 数据
			affected.VersionValue = ">"
			affected.VersionAffected = singleNodesValue.VersionStartExcluding
			Affected = append(Affected, affected)
		}

		if singleNodesValue.VersionEndIncluding != "" { //只有in end数据
			affected.VersionValue = "<="
			affected.VersionAffected = singleNodesValue.VersionEndIncluding
			Affected = append(Affected, affected)
		}

		if singleNodesValue.VersionEndExcluding != "" { //只有Ex end数据
			affected.VersionValue = "<"
			affected.VersionAffected = singleNodesValue.VersionEndExcluding
			Affected = append(Affected, affected)
		}

		if singleNodesValue.VersionEndExcluding == "" && singleNodesValue.VersionEndIncluding == "" && singleNodesValue.VersionStartExcluding == "" && singleNodesValue.VersionStartIncluding == "" {
			affected.VersionValue = "="
			affected.VersionAffected = singleNodesValue.Cpe23Uri
			Affected = append(Affected, affected)
		}
	}

	return Affected
}
func GetCHILDaffectArr(nvdCveItemData *CveItem, product string) []AFFected {
	var AffectArr []AFFected
	for _, NodesValue := range nvdCveItemData.Configurations.Nodes {
		if NodesValue.Operator == "AND" {
			AffectArr = append(AffectArr, GetChaffectArr(&NodesValue, product)...)
		}
		AffectArr = append(AffectArr, GetaffectArr(&NodesValue, product)...)
	}
	return AffectArr
}
func writefile(custom *Custom, outputpath string) {

	Singlecustom, err := json.Marshal(custom)
	if err != nil {
		fmt.Println("失败原因：%s", err)
		return
	}
	if custom.Name == "" {
		fmt.Println(custom.Name)
	}
	strOfCustom := string(Singlecustom)
	AddEnter := strOfCustom + "\n"
	tracefile(AddEnter, outputpath)
}
func writeCveId(str string) {
	cvestr := str + "\n"
	tracefile(cvestr, "E:\\未找到的CVEid.txt")
}

func main() {
	custompath := "E:\\customfile\\RemakeCodeData.json"
	Pyth_path := "E:\\fixed.json"
	parseJsonData(Pyth_path, custompath)
}
func parseJsonData(Pythonfile string, outputpath string) {
	var nvdCveItemData CveItem
	cutFile, _ := os.Open(Pythonfile)
	defer cutFile.Close()
	cutScanner := bufio.NewScanner(cutFile)
	for cutScanner.Scan() { //循环读取每一行的cve
		custom := Custom{} //定义需要的结构体
		lineText := cutScanner.Text()
		var TypeofproductArr Typeofproduct         //定义产品数组
		stroffile := string(lineText)              //获取每一样的cve编号
		nvdCveItemData = GetInformation(stroffile) // 传入nvd文件寻找该cve是否存在
		if nvdCveItemData.Cve.CveDataMeta.ID == "" {
			writeCveId(stroffile)
			continue
		} //如果找到该结构体 进行赋值操作
		TypeofproductArr = GetProductArr(&nvdCveItemData)
		lenthoftype := len(TypeofproductArr.ProductArr)
		if stroffile == nvdCveItemData.Cve.CveDataMeta.ID { //首先要判断两个结构的cveid是否一致，如果一致进行寻找描述并赋值
			if lenthoftype == 0 {
				continue
			}
			for _, times := range TypeofproductArr.ProductArr {
				custom = Custom{}
				custom.Name = nvdCveItemData.Cve.CveDataMeta.ID
				custom.FixedID = ""
				custom.Severity = GetServerity(&nvdCveItemData)
				custom.Namespace = "custom:Python"
				custom.Description = nvdCveItemData.Cve.Description.DescriptionData[0].Value //因为描述数组只有一个元素，所以直接取里面的value就行了
				custom.LinkArr = GetReference(&nvdCveItemData)
				custom.PackageName = times.Product
				custom.Affected = GetCHILDaffectArr(&nvdCveItemData, times.Product)
				writefile(&custom, outputpath)
			}
		}
	}
}
