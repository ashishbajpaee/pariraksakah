package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/gin-gonic/gin"
)

type ResponseAction struct {
	ActionID        string  `json:"action_id"`
	ProposedByPeer  string  `json:"proposed_by_peer_id"`
	ActionType      string  `json:"action_type"`
	Target          string  `json:"target"`
	VotesFor        int     `json:"votes_for"`
	VotesAgainst    int     `json:"votes_against"`
	RequiredThresh  float64 `json:"required_threshold"`
	ConsensusReached bool   `json:"consensus_reached"`
	Status          string  `json:"status"`
	ProposedAt      string  `json:"proposed_at"`
}

var (
	actions   = make(map[string]*ResponseAction)
	actionsMu sync.RWMutex
	kafkaProd *kafka.Producer
)

// Consensus thresholds per action type
var thresholds = map[string]float64{
	"block_ip":       0.51,
	"quarantine":     0.67,
	"share_signature": 0.51,
	"network_alert":  0.34,
	"peer_ejection":  0.75,
}

var playbooks = []map[string]string{
	{"id": "ddos-mitigation", "name": "Distributed DDoS Mitigation", "type": "block_ip"},
	{"id": "zero-day-response", "name": "Zero-Day Exploit Response", "type": "share_signature"},
	{"id": "ransomware-contain", "name": "Ransomware Containment", "type": "quarantine"},
	{"id": "supply-chain", "name": "Supply Chain Attack Response", "type": "share_signature"},
	{"id": "credential-stuffing", "name": "Credential Stuffing Defense", "type": "block_ip"},
	{"id": "apt-campaign", "name": "APT Campaign Response", "type": "quarantine"},
}

func initKafka() {
	broker := os.Getenv("KAFKA_BOOTSTRAP_SERVERS")
	if broker == "" { broker = "kafka:9092" }
	prod, _ := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": broker})
	kafkaProd = prod
}

func publishEvent(topic string, payload interface{}) {
	if kafkaProd == nil { return }
	val, _ := json.Marshal(payload)
	t := topic
	_ = kafkaProd.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &t, Partition: kafka.PartitionAny},
		Value: val,
	}, nil)
}

func proposeHandler(c *gin.Context) {
	var req struct {
		ActionType string `json:"action_type"`
		Target     string `json:"target"`
	}
	c.ShouldBindJSON(&req)
	aid := fmt.Sprintf("action-%d", time.Now().UnixNano())
	thresh := thresholds[req.ActionType]
	if thresh == 0 { thresh = 0.51 }

	action := &ResponseAction{
		ActionID: aid, ProposedByPeer: "local-node", ActionType: req.ActionType,
		Target: req.Target, RequiredThresh: thresh, Status: "PROPOSED",
		ProposedAt: time.Now().Format(time.RFC3339),
	}
	actionsMu.Lock()
	actions[aid] = action
	actionsMu.Unlock()
	publishEvent("dsrn.response.proposed", action)

	// Simulate votes from dev peers
	go func() {
		time.Sleep(3 * time.Second)
		actionsMu.Lock()
		action.VotesFor = 3
		action.VotesAgainst = 1
		totalPeers := 4
		if float64(action.VotesFor)/float64(totalPeers) >= action.RequiredThresh {
			action.ConsensusReached = true
			action.Status = "COMMITTED"
			publishEvent("dsrn.response.committed", action)
		}
		actionsMu.Unlock()
	}()

	c.JSON(http.StatusOK, action)
}

func pendingHandler(c *gin.Context) {
	actionsMu.RLock()
	defer actionsMu.RUnlock()
	var pending []*ResponseAction
	for _, a := range actions {
		if a.Status == "PROPOSED" { pending = append(pending, a) }
	}
	c.JSON(http.StatusOK, gin.H{"pending": pending})
}

func committedHandler(c *gin.Context) {
	actionsMu.RLock()
	defer actionsMu.RUnlock()
	var committed []*ResponseAction
	for _, a := range actions {
		if a.Status == "COMMITTED" { committed = append(committed, a) }
	}
	c.JSON(http.StatusOK, gin.H{"committed": committed})
}

func executeHandler(c *gin.Context) {
	aid := c.Param("action_id")
	actionsMu.Lock()
	defer actionsMu.Unlock()
	if a, ok := actions[aid]; ok && a.ConsensusReached {
		a.Status = "EXECUTED"
		publishEvent("dsrn.response.committed", a)
		c.JSON(http.StatusOK, gin.H{"status": "executed", "action": a})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "Action not committed or not found"})
}

func playbooksHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"playbooks": playbooks})
}

func main() {
	initKafka()
	r := gin.Default()
	r.POST("/response/propose", proposeHandler)
	r.GET("/response/pending", pendingHandler)
	r.GET("/response/committed", committedHandler)
	r.POST("/response/execute/:action_id", executeHandler)
	r.GET("/response/playbooks", playbooksHandler)
	r.GET("/metrics", func(c *gin.Context) { c.String(200, "dsrn_response_actions_total %d\n", len(actions)) })
	port := os.Getenv("RESPONSE_PORT")
	if port == "" { port = "8063" }
	r.Run("0.0.0.0:" + port)
}
