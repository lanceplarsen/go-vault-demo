package service

import (
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/lanceplarsen/go-vault-demo/client"
	"github.com/lanceplarsen/go-vault-demo/dao"
	"github.com/lanceplarsen/go-vault-demo/models"
)

type Order struct {
	Vault      *client.Vault
	Dao        *dao.Order
	Encyrption Transit
}

type Transit struct {
	Key   string
	Mount string
}

func (o *Order) GetOrders() (models.OrdersResp, error) {
	var eOrders []models.Order
	var dOrders []models.Order

	eOrders, err := o.Dao.FindAll()
	if err != nil {
		return models.OrdersResp{}, err
	}

	//Decrypt these. TODO Could use a batch decyrpt opp here
	for _, order := range eOrders {
		dOrder, err := o.Vault.Decrypt(fmt.Sprintf("%s/decrypt/%s", o.Encyrption.Mount, o.Encyrption.Key), order.CustomerName)
		if err != nil {
			log.Printf("Unable to decrypt order: %s", strconv.FormatInt(order.ID, 10))
		} else {
			sDec, _ := base64.StdEncoding.DecodeString(dOrder)
			order.CustomerName = string(sDec)
			dOrders = append(dOrders, order)
		}
	}

	//Create our response payload
	ordersResp := models.OrdersResp{}
	ordersResp.Orders = dOrders

	return ordersResp, nil
}

func (o *Order) CreateOrder(order models.Order) (models.Order, error) {
	//Get the unencrypted customer to send back to the API
	ucust := order.CustomerName

	//Add a timestamp
	order.OrderDate = time.Now()

	//Encrypt it
	encode := base64.StdEncoding.EncodeToString([]byte(order.CustomerName))
	cipher, err := o.Vault.Encrypt(fmt.Sprintf("%s/encrypt/%s", o.Encyrption.Mount, o.Encyrption.Key), encode)
	if err != nil {
		return order, err
	}
	order.CustomerName = cipher

	//Insert the order=
	order, err = o.Dao.Insert(order)

	//If the order was inserted successfully send back the unencrypted customer
	order.CustomerName = ucust

	return order, nil
}

func (o *Order) DeleteOrders() error {
	err := o.Dao.DeleteAll()
	return err
}
