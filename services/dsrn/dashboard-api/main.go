package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var (
	peerURL      = envOr("PEER_NODE_URL", "http://dsrn-peer-node:8060")
	consensusURL = envOr("CONSENSUS_ENGINE_URL", "http://dsrn-consensus-engine:8061")
	gossipURL    = envOr("GOSSIP_URL", "http://dsrn-threat-gossip:8062")
	responseURL  = envOr("RESPONSE_COORDINATOR_URL", "http://dsrn-response-coordinator:8063")
	trustURL     = envOr("TRUST_MANAGER_URL", "http://dsrn-peer-trust-manager:8064")
	ledgerURL    = envOr("LEDGER_URL", "http://dsrn-blockchain-ledger:8065")
	monitorURL   = envOr("MONITOR_URL", "http://dsrn-network-monitor:8066")
)

func envOr(key, def string) string { if v := os.Getenv(key); v != "" { return v }; return def }

func proxyGet(upstream string) gin.HandlerFunc {
	return func(c *gin.Context) {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(upstream)
		if err != nil { c.JSON(502, gin.H{"error": "upstream unavailable"}); return }
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var result interface{}
		json.Unmarshal(body, &result)
		c.JSON(resp.StatusCode, result)
	}
}

func main() {
	r := gin.Default()
	r.Use(cors.Default())

	api := r.Group("/dsrn")
	{
		api.GET("/peers", proxyGet(peerURL+"/peer/list"))
		api.GET("/topology", proxyGet(peerURL+"/peer/network/topology"))
		api.GET("/consensus/history", proxyGet(consensusURL+"/consensus/history"))
		api.GET("/threats/received", proxyGet(gossipURL+"/threat/received"))
		api.GET("/threats/validated", proxyGet(gossipURL+"/threat/validated"))
		api.GET("/threats/stats", proxyGet(gossipURL+"/threat/network/stats"))
		api.GET("/response/pending", proxyGet(responseURL+"/response/pending"))
		api.GET("/response/committed", proxyGet(responseURL+"/response/committed"))
		api.GET("/response/playbooks", proxyGet(responseURL+"/response/playbooks"))
		api.GET("/trust/leaderboard", proxyGet(trustURL+"/trust/leaderboard"))
		api.GET("/trust/blacklist", proxyGet(trustURL+"/trust/blacklist"))
		api.GET("/trust/health", proxyGet(trustURL+"/trust/network/health"))
		api.GET("/ledger/blocks", proxyGet(ledgerURL+"/ledger/blocks"))
		api.GET("/ledger/stats", proxyGet(ledgerURL+"/ledger/stats"))
		api.GET("/ledger/verify", proxyGet(ledgerURL+"/ledger/verify"))
		api.GET("/network/health", proxyGet(monitorURL+"/network/health"))
		api.GET("/network/resilience", proxyGet(monitorURL+"/network/resilience"))
		api.GET("/network/alerts", proxyGet(monitorURL+"/network/alerts"))
	}

	r.GET("/metrics", func(c *gin.Context) { c.String(200, "dsrn_dashboard_api_up 1\n") })

	port := os.Getenv("DSRN_DASHBOARD_PORT")
	if port == "" { port = "8067" }
	r.Run("0.0.0.0:" + port)
}
