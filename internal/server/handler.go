package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"obfuskit/cmd"
	"obfuskit/internal/constants"
	"obfuskit/internal/model"
	"obfuskit/internal/util"
)

// ServerHandler is a struct handler for Burp integration
type ServerHandler struct {
	Config *cmd.Config
}

// ServeHTTP implements http.Handler
func (h *ServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ProcessServerRequestHandler(w, r, h.Config)
}

// ProcessServerRequestHandler handles POST requests from Burp
func ProcessServerRequestHandler(w http.ResponseWriter, r *http.Request, config *cmd.Config) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST supported", http.StatusMethodNotAllowed)
		return
	}
	log.Println("Received Burp request")
	var req model.BurpRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	payload := req.Payload
	attackType := util.DetectAttackType(payload)

	// Load config.yaml for evasion level if available
	level := constants.Medium // default
	if config != nil {
		attackType = config.Attack.Type
		level = util.ParseEvasionLevel(config.Evasion.Level)
	}
	evasions, exists := cmd.GetEvasionsForPayload(attackType)
	if !exists {
		log.Println("No evasions found for attack type: ", attackType)
		evasions = []string{"Base64Variants", "HexVariants", "UnicodeVariants"}
	}

	var results []model.BurpEvadedPayload
	for _, evasionType := range evasions {
		variants, err := cmd.ApplyEvasion(payload, evasionType, level)
		if err != nil {
			continue
		}
		for _, variant := range variants {
			results = append(results, model.BurpEvadedPayload{
				OriginalPayload: payload,
				AttackType:      attackType,
				EvasionType:     evasionType,
				Level:           level,
				Variant:         variant,
			})
		}
	}
	resp := model.BurpResponse{
		Status:   "ok",
		Payloads: results,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
