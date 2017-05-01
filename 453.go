package main

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net/http"
	"strconv"
	"time"
)

const endpoint string = "https://dns.google.com/resolve"

// A Response represents the JSON response object returned by the Google API.
type Response struct {
	Status     int32      `json:"Status"`
	TC         bool       `json:"TC"`
	RD         bool       `json:"RD"`
	RA         bool       `json:"RA"`
	AD         bool       `json:"AD"`
	CD         bool       `json:"CD"`
	Question   []Question `json:"Question"`
	Answer     []Answer   `json:"Answer"`
	Authority  []Answer   `json:"Authority"`
	Additional []Answer   `json:"Additional"`
	Comment    string     `json:"Comment"`
}

// A Question represents a DNS question part in the JSON response.
type Question struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

// An Answer represents a DNS answer part in the JSON response; it can be
// part of the answer, authority, or extra sections of the DNS response.
type Answer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

type handler struct{}

// ServeDNS handles DNS queries from clients.
func (_ handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	question := req.Question[0]
	qType, _ := dns.TypeToString[question.Qtype]

	// Set up HTTP request
	httpReq, _ := http.NewRequest("GET", endpoint, nil)

	// Set query parameters
	httpQuery := httpReq.URL.Query()
	httpQuery.Add("name", question.Name)
	httpQuery.Add("type", strconv.FormatUint(uint64(question.Qtype), 10))
	httpReq.URL.RawQuery = httpQuery.Encode()

	// Execute request
	httpRes, _ := http.DefaultClient.Do(httpReq)
	defer httpRes.Body.Close()

	// Unmarshal JSON response
	res := Response{}
	json.NewDecoder(httpRes.Body).Decode(&res)

	// Parse response
	msg := parse(&res, req)

	// Log request and time
	log.Printf("%s %s %dns\n", question.Name, qType, time.Now().Sub(start))

	// Return response
	w.WriteMsg(&msg)
}

// parse converts a `Response` from Google into a `dns.Msg`.
func parse(res *Response, req *dns.Msg) dns.Msg {
	// Parse questions
	questions := []dns.Question{}
	for _, q := range res.Question {
		questions = append(questions, dns.Question{
			Name:   q.Name,
			Qtype:  q.Type,
			Qclass: dns.ClassINET,
		})
	}

	// Parse answers
	answers := []dns.RR{}
	authorities := []dns.RR{}
	additionals := []dns.RR{}

	for _, a := range res.Answer {
		answers = append(answers, parseRR(&a))
	}
	for _, a := range res.Authority {
		authorities = append(authorities, parseRR(&a))
	}
	for _, a := range res.Additional {
		additionals = append(additionals, parseRR(&a))
	}

	// Construct response header
	header := dns.MsgHdr{
		Id:                 req.Id,
		Response:           true,
		Opcode:             dns.OpcodeQuery,
		Authoritative:      false,
		Truncated:          res.TC,
		RecursionDesired:   res.RD,
		RecursionAvailable: res.RA,
		AuthenticatedData:  res.AD,
		CheckingDisabled:   res.CD,
		Rcode:              int(res.Status),
	}

	// Return complete message
	return dns.Msg{
		MsgHdr:   header,
		Compress: req.Compress,
		Question: questions,
		Answer:   answers,
		Ns:       authorities,
		Extra:    additionals,
	}
}

// parseRR converts a single `Answer` struct into a single `dns.RR` resource record.
func parseRR(a *Answer) dns.RR {
	// Construct resource record string for parsing
	typeName, _ := dns.TypeToString[a.Type]
	resource := fmt.Sprintf("%s %d IN %s %s", a.Name, a.TTL, typeName, a.Data)

	rr, err := dns.NewRR(resource)
	if err != nil {
		log.Println(err)
	}
	return rr
}

func main() {
	server := &dns.Server{Net: "udp", Handler: handler{}}
	server.ListenAndServe()
}
