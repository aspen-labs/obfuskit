package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"obfuskit/cmd"
	"obfuskit/internal/model"
	"obfuskit/internal/util"
	"obfuskit/types"
)

// ServerHandler is a struct handler for Burp integration
type ServerHandler struct {
	Config *types.Config
}

// ServeHTTP implements http.Handler
func (h *ServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ProcessServerRequestHandler(w, r, h.Config)
}

// ProcessServerRequestHandler handles POST requests from Burp
func ProcessServerRequestHandler(w http.ResponseWriter, r *http.Request, config *types.Config) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST supported", http.StatusMethodNotAllowed)
		return
	}
	log.Println("Received api request")
	var req model.PayloadRequest
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
	level := types.EvasionLevelMedium // default
	if config != nil {
		attackType = config.AttackType
		level = config.EvasionLevel
	}
	evasions, exists := cmd.GetEvasionsForPayload(attackType)
	if !exists {
		log.Println("No evasions found for attack type: ", attackType)
		evasions = []types.PayloadEncoding{
			types.PayloadEncodingBase64,
			types.PayloadEncodingHex,
			types.PayloadEncodingUnicode,
			types.PayloadEncodingOctal,
			types.PayloadEncodingBestFit,
		}
	}

	var results []model.EvadedPayload
	for _, evasionType := range evasions {
		variants, err := cmd.ApplyEvasion(payload, evasionType, level)
		if err != nil {
			continue
		}
		for _, variant := range variants {
			results = append(results, model.EvadedPayload{
				OriginalPayload: payload,
				AttackType:      string(attackType),
				EvasionType:     string(evasionType),
				Level:           string(level),
				Variant:         variant,
			})
		}
	}
	resp := model.PayloadResponse{
		Status:   "ok",
		Payloads: results,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
