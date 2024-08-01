package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

var payloads = map[string]string{
	"{{7*7}}":             "49", // Jinja2, Twig
	"${{7*7}}":            "49", // Go templates
	"${7*7}":              "49", // Velocity, Freemarker
	"<%= 7 * 7 %>":        "49", // ERB (Ruby)
	"{% 7 * 7 %}":         "49", // Django (no output for basic math)
	"<#assign x=7*7>${x}": "49", // Freemarker
	"#{7*7}":              "49", // Thymeleaf
}

// Mapping payloads to their respective template engines
var templateEngines = map[string]string{
	"{{7*7}}":             "Jinja2, Twig",
	"${{7*7}}":            "Go templates",
	"${7*7}":              "Velocity, Freemarker",
	"<%= 7 * 7 %>":        "ERB (Ruby)",
	"{% 7 * 7 %}":         "Django",
	"<#assign x=7*7>${x}": "Freemarker",
	"#{7*7}":              "Thymeleaf",
}

func main() {
	font_logo := `
████████╗███████╗███╗   ███╗██████╗ ██╗      █████╗ ██████╗ 
╚══██╔══╝██╔════╝████╗ ████║██╔══██╗██║     ██╔══██╗██╔══██╗
   ██║   █████╗  ██╔████╔██║██████╔╝██║     ███████║██████╔╝
   ██║   ██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║     ██╔══██║██╔══██╗
   ██║   ███████╗██║ ╚═╝ ██║██║     ███████╗██║  ██║██║  ██║
   ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
                                                 ~ 0xSurya`
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(font_logo)
	fmt.Print("Enter the target URL 🗡️:")
	url, _ := reader.ReadString('\n')
	url = strings.TrimSpace(url)

	if !strings.Contains(url, "fuzz") {
		fmt.Println("Error: URL must contain 'fuzz' param")
		return
	}

	// Check SSTI for each payload and identify the template engine
	vulnerable := false
	var wg sync.WaitGroup
	results := make(chan string, len(payloads))

	for payload, expected := range payloads {
		wg.Add(1)
		go func(payload, expected string) {
			defer wg.Done()
			if result, engine := checkSSTI(url, payload, expected); result != "" {
				vulnerable = true
				results <- fmt.Sprintf("Potential SSTI detected with payload '%s'.\nVulnerable URL✅: %s\nLikely template engine(s)💯: %s\n", payload, result, engine)
			}
		}(payload, expected)
	}

	wg.Wait()
	close(results)

	if vulnerable {
		for res := range results {
			fmt.Println(res)
		}
	} else {
		fmt.Println("The target does not appear to be vulnerable to SSTI💀")
	}
}

func checkSSTI(url, payload, expected string) (string, string) {
	fullURL := strings.Replace(url, "fuzz", payload, -1)
	resp, err := http.Get(fullURL)
	if err != nil {
		fmt.Println("Error:", err)
		return "", ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return "", ""
	}

	bodyStr := string(body)
	// Check if the response contains the expected output but not the payload
	if strings.Contains(bodyStr, expected) && !strings.Contains(bodyStr, payload) {
		engine := templateEngines[payload]
		return fullURL, engine
	}

	return "", ""
}
