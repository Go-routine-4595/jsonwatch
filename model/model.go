package model

type IService interface {
	SendData(events []byte)
}

type FCTSDataModel struct {
	SiteCode    string                 `json:"site_code"`
	SensorId    string                 `json:"sensor_id"`
	DataSource  string                 `json:"data_source"`
	TimeStamp   string                 `json:"timestamp"`
	Value       string                 `json:"value"`
	Uom         string                 `json:"uom"`
	Quality     int                    `json:"quality"`
	Annotations map[string]interface{} `json:"annotations"`
}
