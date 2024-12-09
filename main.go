package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func CreateWallet() (map[string]interface{}, error) {
	authToken := os.Getenv("LUMX_AUTH_TOKEN")
	client := &http.Client{}

	// Configuração da requisição
	req, err := http.NewRequest("POST", "https://protocol-sandbox.lumx.io/v2/wallets", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	// Execução da requisição
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", res.StatusCode, string(bodyBytes))
	}

	var walletResponse map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&walletResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Filtrar os dados relevantes
	result := map[string]interface{}{
		"walletId":        walletResponse["id"],
		"address":         walletResponse["address"],
		"blockExplorerUrl": walletResponse["blockExplorerUrl"],
	}

	return result, nil
}


func InitiateInvestUSDCWithoutPermitTransaction(walletID string, amount uint64) (string, string, error) {
	authToken := os.Getenv("LUMX_AUTH_TOKEN")
	RivoolPool := os.Getenv("CONTRACT_RIVOOL")
	client := &http.Client{}

	transactionPayload := map[string]interface{}{
		"walletId":        walletID,
		"contractAddress": RivoolPool,
		"operations": []map[string]interface{}{
			{
				"functionSignature": "investUSDCWithoutPermit(uint256)",
				"argumentsValues": []interface{}{
					amount,
				},
			},
		},
	}

	payloadBytes, err := json.Marshal(transactionPayload)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal payload: %v", err)
	}
	req, err := http.NewRequest("POST", "https://protocol-sandbox.lumx.io/v2/transactions/custom", bytes.NewReader(payloadBytes))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to execute request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(res.Body)
		return "", "", fmt.Errorf("API request failed with status %d: %s", res.StatusCode, string(bodyBytes))
	}

	var transactionResponse map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&transactionResponse); err != nil {
		return "", "", fmt.Errorf("failed to parse response: %v", err)
	}

	transactionID, ok := transactionResponse["id"].(string)
	if !ok {
		return "", "", fmt.Errorf("failed to parse transaction ID from response: %+v", transactionResponse)
	}

	// Check transaction status
	status, transactionHash, err := checkTransactionStatus(transactionID)
	if err != nil {
		return "", "", fmt.Errorf("transaction status check failed: %v", err)
	}

	return status, transactionHash, nil
}

func InitiateApproveTransaction(walletID, spender string, value uint64) (string, string, error) {
	authToken := os.Getenv("LUMX_AUTH_TOKEN")
	Token := os.Getenv("CONTRACT_TOKEN")
	client := &http.Client{}

	transactionPayload := map[string]interface{}{
		"walletId":        walletID,
		"contractAddress": Token,
		"operations": []map[string]interface{}{
			{
				"functionSignature": "approve(address,uint256)",
				"argumentsValues": []interface{}{
					spender, value,
				},
			},
		},
	}

	payloadBytes, err := json.Marshal(transactionPayload)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal payload: %v", err)
	}
	req, err := http.NewRequest("POST", "https://protocol-sandbox.lumx.io/v2/transactions/custom", bytes.NewReader(payloadBytes))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to execute request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(res.Body)
		return "", "", fmt.Errorf("API request failed with status %d: %s", res.StatusCode, string(bodyBytes))
	}

	var transactionResponse map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&transactionResponse); err != nil {
		return "", "", fmt.Errorf("failed to parse response: %v", err)
	}

	transactionID, ok := transactionResponse["id"].(string)
	if !ok {
		return "", "", fmt.Errorf("failed to parse transaction ID from response: %+v", transactionResponse)
	}

	// Check transaction status
	status, transactionHash, err := checkTransactionStatus(transactionID)
	if err != nil {
		return "", "", fmt.Errorf("transaction status check failed: %v", err)
	}

	return status, transactionHash, nil
}

// Função para verificar o status da transação
func checkTransactionStatus(transactionID string) (string, string, error) {
	authToken := os.Getenv("LUMX_AUTH_TOKEN")
	client := &http.Client{}
	url := fmt.Sprintf("https://protocol-sandbox.lumx.io/v2/transactions/%s", transactionID)

	for {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", "", err
		}
		req.Header.Set("Authorization", "Bearer "+authToken)

		res, err := client.Do(req)
		if err != nil {
			return "", "", err
		}
		defer res.Body.Close()

		var statusResponse map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&statusResponse); err != nil {
			return "", "", err
		}

		status, ok := statusResponse["status"].(string)
		if !ok {
			return "", "", errors.New("failed to parse transaction status")
		}

		transactionHash, _ := statusResponse["transactionHash"].(string) // captura o hash, se disponível

		if status == "success" {
			if transactionHash == "" {
				return status, "", errors.New("transaction succeeded, but no transactionHash provided")
			}
			return status, transactionHash, nil
		} else if status == "failed" {
			if transactionHash != "" {
				errorDetails, err := getTransactionErrorDetails(transactionHash)
				if err != nil {
					return "failed", transactionHash, fmt.Errorf("failed to retrieve error details: %v", err)
				}
				return "failed", transactionHash, errors.New(errorDetails)
			}
			return "failed", "", errors.New("transaction failed without transactionHash")
		}

		// Aguarda 2 segundos antes de tentar novamente
		time.Sleep(2 * time.Second)
	}
}

// Implementação fictícia da função `getTransactionErrorDetails`
func getTransactionErrorDetails(transactionHash string) (string, error) {
	// Simulação de busca de detalhes de erro
	return fmt.Sprintf("Error details for transaction hash %s", transactionHash), nil
}

func handleCreateWallet(c *gin.Context) {
	result, err := CreateWallet()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create wallet", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}


func handleInvestUSDCWithoutPermitTransaction(c *gin.Context) {
	var req struct {
		WalletID string `json:"walletId" binding:"required"`
		Amount   uint64 `json:"amount" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data", "details": err.Error()})
		return
	}

	status, transactionHash, err := InitiateInvestUSDCWithoutPermitTransaction(req.WalletID, req.Amount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate invest transaction", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": status, "transactionHash": transactionHash})
}

func handleApproveTransaction(c *gin.Context) {
	var req struct {
		WalletID string `json:"walletId" binding:"required"`
		Spender  string `json:"spender" binding:"required"`
		Value    uint64 `json:"value" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data", "details": err.Error()})
		return
	}

	status, transactionHash, err := InitiateApproveTransaction(req.WalletID, req.Spender, req.Value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate approve transaction", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": status, "transactionHash": transactionHash})
}


func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	 // Configura o modo do Gin
	 gin.SetMode(os.Getenv("GIN_MODE"))

	 // Cria um novo router
	 r := gin.New()
 
	 // Configuração de middlewares e CORS
	 r.Use(gin.Logger())
	 r.Use(gin.Recovery())
	 r.Use(cors.Default())

	// Rotas POST
	r.POST("/invest-usdc", handleInvestUSDCWithoutPermitTransaction)
	r.POST("/approve", handleApproveTransaction)
	r.POST("/create-wallet", handleCreateWallet)


	log.Println("Server running on port 8080")
	r.Run(":8080")
}
