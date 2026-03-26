package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/gin-gonic/gin"
)

type ConsensusRound struct {
	RoundID      string   `json:"round_id"`
	ProposalHash string   `json:"proposal_hash"`
	ProposalType string   `json:"proposal_type"`
	Phase        string   `json:"phase"`
	Participants []string `json:"participants"`
	Prepares     int      `json:"prepares"`
	Commits      int      `json:"commits"`
	Result       string   `json:"result"`
	StartedAt    string   `json:"started_at"`
}

var (
	rounds   = make(map[string]*ConsensusRound)
	roundsMu sync.RWMutex
	kafkaProd *kafka.Producer
)

func maxFaulty(n int) int { return (n - 1) / 3 }
func quorum(n int) int    { return 2*maxFaulty(n) + 1 }

func initKafka() {
	broker := os.Getenv("KAFKA_BOOTSTRAP_SERVERS")
	if broker == "" { broker = "kafka:9092" }
	prod, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": broker})
	if err != nil { log.Printf("Kafka init failed: %v", err) ; return }
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
		ProposalType string   `json:"proposal_type"`
		ProposalHash string   `json:"proposal_hash"`
		Participants []string `json:"participants"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Participants) < 4 {
		// Dev mode: add simulated peers
		req.Participants = append(req.Participants, "sim-peer-1", "sim-peer-2", "sim-peer-3", "sim-peer-4")
	}
	rid := fmt.Sprintf("round-%d", time.Now().UnixNano())
	round := &ConsensusRound{
		RoundID: rid, ProposalHash: req.ProposalHash, ProposalType: req.ProposalType,
		Phase: "PRE-PREPARE", Participants: req.Participants,
		Prepares: 0, Commits: 0, Result: "PENDING", StartedAt: time.Now().Format(time.RFC3339),
	}
	roundsMu.Lock()
	rounds[rid] = round
	roundsMu.Unlock()

	// Simulate PBFT progression in background
	go simulatePBFT(rid)

	publishEvent("dsrn.consensus.round", round)
	c.JSON(http.StatusOK, round)
}

func simulatePBFT(rid string) {
	roundsMu.Lock()
	r, ok := rounds[rid]
	if !ok { roundsMu.Unlock(); return }
	n := len(r.Participants)
	q := quorum(n)

	// PRE-PREPARE -> PREPARE
	r.Phase = "PREPARE"
	roundsMu.Unlock()
	publishEvent("dsrn.consensus.round", r)
	time.Sleep(2 * time.Second)

	// Simulate prepare messages from honest peers (3 out of 4 in dev)
	roundsMu.Lock()
	r.Prepares = q
	r.Phase = "COMMIT"
	roundsMu.Unlock()
	publishEvent("dsrn.consensus.round", r)
	time.Sleep(2 * time.Second)

	// Simulate commit messages
	roundsMu.Lock()
	r.Commits = q
	r.Phase = "REPLY"
	r.Result = "COMMITTED"
	roundsMu.Unlock()
	publishEvent("dsrn.consensus.round", r)
}

func voteHandler(c *gin.Context) {
	rid := c.Param("round_id")
	var req struct{ Vote string `json:"vote"` }
	c.ShouldBindJSON(&req)
	roundsMu.Lock()
	defer roundsMu.Unlock()
	if r, ok := rounds[rid]; ok {
		if req.Vote == "PREPARE" { r.Prepares++ }
		if req.Vote == "COMMIT"  { r.Commits++ }
		n := len(r.Participants)
		if r.Commits >= quorum(n) { r.Result = "COMMITTED"; r.Phase = "REPLY" }
		c.JSON(http.StatusOK, r)
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error":"Round not found"})
}

func statusHandler(c *gin.Context) {
	rid := c.Param("round_id")
	roundsMu.RLock()
	defer roundsMu.RUnlock()
	if r, ok := rounds[rid]; ok { c.JSON(http.StatusOK, r); return }
	c.JSON(http.StatusNotFound, gin.H{"error":"Not found"})
}

func historyHandler(c *gin.Context) {
	roundsMu.RLock()
	defer roundsMu.RUnlock()
	list := make([]*ConsensusRound, 0)
	for _, r := range rounds { list = append(list, r) }
	c.JSON(http.StatusOK, gin.H{"rounds": list})
}

func peersHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"min_peers": 4, "quorum_formula": "2f+1", "max_faulty": "f=(n-1)/3"})
}

func main() {
	initKafka()
	r := gin.Default()
	r.POST("/consensus/propose", proposeHandler)
	r.POST("/consensus/vote/:round_id", voteHandler)
	r.GET("/consensus/status/:round_id", statusHandler)
	r.GET("/consensus/history", historyHandler)
	r.GET("/consensus/peers", peersHandler)
	r.GET("/metrics", func(c *gin.Context) { c.String(200, "dsrn_consensus_rounds_total %d\n", len(rounds)) })
	port := os.Getenv("CONSENSUS_PORT")
	if port == "" { port = "8061" }
	r.Run("0.0.0.0:" + port)
}
