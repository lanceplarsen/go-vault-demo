package models

import "time"

type Order struct {
	ID           int64     `json:"id"`
	CustomerName string    `json:"customerName"`
	ProductName  string    `json:"productName"`
	OrderDate    time.Time `json:"orderDate"`
}

type OrdersResp struct {
	Orders  []Order `json:"orders"`
}
