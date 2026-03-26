package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
)

var ctx = context.Background()

type ImmuneSystem struct {
	redisClient    *redis.Client
	antibodyRules  map[string]string // pattern_id -> rule
	innateBlocked  map[string]bool   // ip -> bool
	mu             sync.RWMutex
	activationLvl  float64
}

func initRedis() *redis.Client {
    host := os.Getenv("REDIS_HOST")
    if host == "" { host = "redis" }
    port := os.Getenv("REDIS_PORT")
    if port == "" { port = "6379" }
    
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", host, port),
		Password: "", // no password set
		DB:       1,  // use DB 1 for immune memory
	})
	return rdb
}

var immune *ImmuneSystem

func getStatus(w http.ResponseWriter, r *http.Request) {
	immune.mu.RLock()
	defer immune.mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"innate_active": true,
		"adaptive_active": true,
		"activation_level": immune.activationLvl,
	})
}

func getAntibodies(w http.ResponseWriter, r *http.Request) {
	immune.mu.RLock()
	defer immune.mu.RUnlock()
	json.NewEncoder(w).Encode(immune.antibodyRules)
}

func vaccinate(w http.ResponseWriter, r *http.Request) {
	var payload map[string]string
	json.NewDecoder(r.Body).Decode(&payload)
	
	immune.mu.Lock()
	defer immune.mu.Lock() // wait, defer Unlock
	
	if pattern, ok := payload["pattern"]; ok {
	    // mock antibody gen
	    immune.antibodyRules[pattern] = "DROP"
	    immune.redisClient.Set(ctx, fmt.Sprintf("antibody:%s", pattern), "DROP", 0)
	    json.NewEncoder(w).Encode(map[string]string{"status": "Vaccinated against " + pattern})
	}
}

// Wrapper to fix the defer issue above
func vaccinateHandler(w http.ResponseWriter, r *http.Request) {
	var payload map[string]string
	json.NewDecoder(r.Body).Decode(&payload)
	
	immune.mu.Lock()
	defer immune.mu.Unlock() // Corrected
	
	if pattern, ok := payload["pattern"]; ok {
	    immune.antibodyRules[pattern] = "DROP"
	    immune.redisClient.Set(ctx, fmt.Sprintf("antibody:%s", pattern), "DROP", 0)
	    json.NewEncoder(w).Encode(map[string]string{"status": "Vaccinated against " + pattern})
	} else {
        json.NewEncoder(w).Encode(map[string]string{"error": "Missing pattern"})
    }
}

func getMemory(w http.ResponseWriter, r *http.Request) {
    immune.mu.RLock()
    defer immune.mu.RUnlock()
    keys, _ := immune.redisClient.Keys(ctx, "antibody:*").Result()
    json.NewEncoder(w).Encode(map[string]interface{}{
        "persistent_antibodies": len(keys),
        "in_memory_rules": len(immune.antibodyRules),
    })
}

func suppressRule(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    ruleID := vars["rule_id"]
    
    immune.mu.Lock()
    defer immune.mu.Unlock()
    
    delete(immune.antibodyRules, ruleID)
    immune.redisClient.Del(ctx, fmt.Sprintf("antibody:%s", ruleID))
    
    json.NewEncoder(w).Encode(map[string]string{"status": "Rule suppressed", "rule_id": ruleID})
}

func getHealth(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "layer": "Innate & Adaptive"})
}

func backgroundLoader() {
    // Poll redis to sync distributed antibodies (from peers via DSRN)
    for {
        time.Sleep(10 * time.Second)
        keys, err := immune.redisClient.Keys(ctx, "antibody:*").Result()
        if err == nil {
            immune.mu.Lock()
            for _, k := range keys {
                val, _ := immune.redisClient.Get(ctx, k).Result()
                // Strip "antibody:" prefix for local map
                pattern := k[9:]
                immune.antibodyRules[pattern] = val
            }
            immune.mu.Unlock()
        }
    }
}

func main() {
	immune = &ImmuneSystem{
		redisClient:   initRedis(),
		antibodyRules: make(map[string]string),
		innateBlocked: make(map[string]bool),
		activationLvl: 12.5,
	}

    go backgroundLoader()

	r := mux.NewRouter()
	r.HandleFunc("/immune/status", getStatus).Methods("GET")
	r.HandleFunc("/immune/antibodies", getAntibodies).Methods("GET")
	r.HandleFunc("/immune/vaccinate", vaccinateHandler).Methods("POST")
	r.HandleFunc("/immune/memory", getMemory).Methods("GET")
	r.HandleFunc("/immune/suppress/{rule_id}", suppressRule).Methods("POST")
	r.HandleFunc("/immune/health", getHealth).Methods("GET")

    port := os.Getenv("NEURO_IMMUNE_PORT")
    if port == "" {
        port = "8075"
    }

	log.Printf("Adaptive Immune System starting on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), r))
}
