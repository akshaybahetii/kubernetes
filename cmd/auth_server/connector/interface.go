package connector

import "net/http"

//Connector for auth type to provide authentication feature.
type Connector interface {
	// ID returns the ID of the ConnectorConfig used to create the Connector.
	ID() string

	Handler() http.Handler
	//Setup configures connetor with config file parametes.
	Setup()
}
