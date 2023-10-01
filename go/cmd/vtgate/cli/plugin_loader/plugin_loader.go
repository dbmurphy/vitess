package plugin_loader

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"plugin"
)

// PluginConfig Configuration struct for plugins (you can define this based on your configuration format)
type PluginConfig struct {
	Type    string
	Plugins map[string]PluginInfo
}

// PluginInfo struct contains source and version information
type PluginInfo struct {
	Source  string
	Version string
}

func LoadPlugins(config PluginConfig) error {
	var temporaryFiles []string // Store the names of temporary files

	for pluginName, pluginInfo := range config.Plugins {
		source := pluginInfo.Source
		version := pluginInfo.Version

		fmt.Printf("Fetching and loading plugin %s (version: %s)...\n", pluginName, version)

		// Define the URL to the GitHub release asset
		assetURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/vitess-plugin-%s-%s",
			source, version, config.Type, pluginName)

		// Fetch the plugin binary from GitHub
		resp, err := http.Get(assetURL)
		if err != nil {
			fmt.Printf("Failed to fetch plugin %s: %v\n", pluginName, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Failed to fetch plugin %s: HTTP status code %d\n", pluginName, resp.StatusCode)
			if err := resp.Body.Close(); err != nil {
				fmt.Printf("Error closing response body: %v\n", err)
			}
			continue
		}

		// Create a temporary file to write the plugin binary
		tmpFile, err := os.CreateTemp("", "plugin-*")
		if err != nil {
			fmt.Printf("Failed to create a temporary file: %v\n", err)
			if err := resp.Body.Close(); err != nil {
				fmt.Printf("Error closing response body: %v\n", err)
			}
			continue
		}

		// Write the plugin binary from the HTTP response to the temporary file
		_, err = io.Copy(tmpFile, resp.Body)
		if err != nil {
			fmt.Printf("Failed to write plugin to temporary file: %v\n", err)
			if err := tmpFile.Close(); err != nil {
				fmt.Printf("Error closing tmpFile: %v\n", err)
			}
			continue
		}

		// Store the name of the temporary file for later removal
		tmpFileName := tmpFile.Name()
		temporaryFiles = append(temporaryFiles, tmpFileName)

		// Load the plugin dynamically from the temporary file
		p, err := plugin.Open(tmpFileName)
		if err != nil {
			fmt.Printf("Failed to load plugin %s: %v\n", pluginName, err)
			if err := tmpFile.Close(); err != nil {
				fmt.Printf("Error closing tmpFile: %v\n", err)
			}
			continue
		}

		// Initialize the plugin using the init function
		initSym, err := p.Lookup("init")
		if err != nil {
			fmt.Printf("Plugin %s does not have an init function: %v\n", pluginName, err)
			if err := tmpFile.Close(); err != nil {
				fmt.Printf("Error closing tmpFile: %v\n", err)
			}
			continue
		}

		initFunc, ok := initSym.(func())
		if !ok {
			fmt.Printf("Plugin %s init function has an unexpected signature\n", pluginName)
			if err := tmpFile.Close(); err != nil {
				fmt.Printf("Error closing tmpFile: %v\n", err)
			}
			continue
		}

		initFunc() // Call the init function to initialize the loaded plugin

		fmt.Printf("Loaded plugin %s (version: %s)\n", pluginName, version)

		// Close the temporary file and remove it
		if err := tmpFile.Close(); err != nil {
			fmt.Printf("Error closing temporary file: %v\n", err)
		}
		if err := os.Remove(tmpFileName); err != nil {
			fmt.Printf("Failed to remove temporary file: %v\n", err)
		}

		// Close the response body
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}

	return nil
}
