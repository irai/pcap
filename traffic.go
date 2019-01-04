package filters

import (
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"github.com/irai/netfilter/netfilter/model"
	"strings"
	"time"
)

var (
	spxAuth string = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjE0MDAxIiwic3ViIjoiOWMzZDMxZTAtMDU5My00ZDAzLThhZTktYzE3ZGE4ZDJkOTQ0IiwiYXVkIjoiY2xpZW50SWQiLCJleHAiOjE0ODQ0NzY4NTcsImlhdCI6MTQ4NDQ3MzI1Nywibm9uY2UiOiJub3VuY2UiLCJlbWFpbCI6ImVtYWlsQGVtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZX0.p4qUa8i_PpMm11vUKMbF_Ksha5-Z8Jl5XnySSDaeFAzPl_sBMpErWoGw6pc0Pmto1S2Jz0RFKYE_gnxDsK-C6ciclrrxTviW-6ACldP0eGfCdDrmfaImYS-PffA31vG0uIRncO56xa2esUoMc5GPEfFurYP3FdTsnujUOqw9PDxrgYGXaFaSUGTd0iwBFU0CoYU05EcOh4oCnqCs0Jc73lb1HeoytdRHBxeb02_TF48O35UAC6ioXUIW04lh5oBCIa3ETEbNqMzsDSLvqEXhER1vmttHX45W6cLaav3OtecoPZejIrlqmlzNyOfbhE9jHoqPHnaUw9TZ2BKGR5YSPA"
)

func GetClients(hostname string, deviceId string) (clients []model.Client, err error) {
	aurl := fmt.Sprintf("http://%s:8080/traffic/v1/device/%s/client", hostname, deviceId)

	resp, err := get(aurl)
	if err != nil {
		log.Debug("TrafficProxy error in PostClients ", aurl, err)
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		break // let it flow to the end

	default:
		err := errors.New(fmt.Sprintf("Unexpected http code (%v) in GetClients", resp.StatusCode))
		log.WithFields(log.Fields{"http_statuscode": resp.StatusCode}).Error(err)
		return nil, err
	}

	// If 200
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// log.Info("response:", string(body))
	ret := []model.Client{}
	err = json.Unmarshal(body, &ret)
	if err != nil {
		log.Error("Error unmarshaling clients", err)
		return nil, err
	}

	clients = make([]model.Client, len(ret))
	for i := range ret {
		clients[i].MAC, _ = net.ParseMAC(ret[i].MAC.String())
		clients[i].IP = net.ParseIP(ret[i].IP.String())
		clients[i].Name = ret[i].Name
		clients[i].Filter = ret[i].Filter
	}

	return clients, nil
}

func PostClients(hostname string, deviceId string, clients []model.Client) error {
	aurl := fmt.Sprintf("http://%s:8080/traffic/v1/device/%s/client", hostname, deviceId)

	fields := url.Values{}
	for i, _ := range clients {
		// if clients[i].State != network.ClientStateFree {
		fields.Add("client_state", clients[i].State)
		fields.Add("client_mac", clients[i].MAC.String())
		fields.Add("client_ip", clients[i].IP.String())
		fields.Add("client_name", clients[i].Name)
		fields.Add("client_filter", clients[i].Filter)
		// }

	}
	resp, err := post(aurl, fields)
	if err != nil {
		log.Error("TrafficProxy error in PostClients ", aurl, err)
		return err
	}
	defer resp.Body.Close()

	return nil
}

func post(aurl string, data url.Values) (resp *http.Response, err error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	log.Debug("TrafficProxy POST", aurl, data)
	req, err := http.NewRequest("POST", aurl, strings.NewReader(data.Encode()))

	req.SetBasicAuth("spinifex", "pwd")
	// req.Header.Add("Authorization", p.SecurityProxy.Credentials.IdToken)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("spx-auth", spxAuth)

	// log.Info("Post URL:", aurl, data)

	resp, err = client.Do(req)

	return resp, err
}

func get(aurl string) (resp *http.Response, err error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	log.Debug("TrafficProxy GET", aurl)
	req, err := http.NewRequest("GET", aurl, nil)

	req.SetBasicAuth("spinifex", "pwd")
	// req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("spx-auth", spxAuth)

	resp, err = client.Do(req)

	return resp, err
}
