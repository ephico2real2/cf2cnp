package main

import (
	"fmt"
	"os"

	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/flow"
	"github.com/hubble-policy-gen/internal/policy"
	"github.com/hubble-policy-gen/internal/server"
	"github.com/spf13/cobra"
)

var (
	inputDir      string
	outputDir     string
	port          int
	externalURL   string
	l7            bool
	dnsVisibility bool
	yoloNamespace string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cf2cnp",
		Short: "CF2CNP - Cilium Flow to CiliumNetworkPolicy",
		Long: `CF2CNP (Cilium Flow to CiliumNetworkPolicy) is a CLI tool that reads Hubble flow JSON files
and generates CiliumNetworkPolicy YAML files based on the observed traffic.

The tool analyzes traffic patterns from Hubble flows and creates appropriate
network policies with:
- Proper endpoint selectors based on app labels
- Cross-namespace traffic handling
- FQDN-based egress with DNS resolution rules
- Port and protocol specifications

Use the 'generate' command to process flow files from a directory,
or use the 'serve' command to run as an HTTP server.`,
	}

	// Generate command (file-based)
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate policies from flow files in a directory",
		Long:  "Read Hubble flow JSON files from an input directory and generate CiliumNetworkPolicy YAML files.",
		RunE:  runGenerate,
	}
	generateCmd.Flags().StringVarP(&inputDir, "input", "i", "", "Input directory containing Hubble flow JSON files (required)")
	generateCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for generated CiliumNetworkPolicy YAML files (required)")
	generateCmd.Flags().BoolVar(&l7, "l7", false, "Emit layer-7 rules (HTTP method+path, DNS names) from the flows' l7 records; the port then goes through the proxy")
	generateCmd.Flags().BoolVar(&dnsVisibility, "dns-visibility", false, "For world traffic without DNS names, add the kube-dns L7 DNS rule so the next flows carry names (toFQDNs on the next run)")
	generateCmd.MarkFlagRequired("input")
	generateCmd.MarkFlagRequired("output")

	// Serve command (HTTP server)
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start HTTP server for policy generation",
		Long: `Start an HTTP server that accepts Hubble flow JSON via POST requests
and returns CiliumNetworkPolicy YAML files.

Endpoints:
  POST /generate      - Send flow JSON (one flow, a JSON array, or one flow per line), receive policy YAML;
                        with Accept: application/json, receive {download_url, filename, yaml, flows, policies}.
                        ?name=<policy name> names the (single) resulting policy.
  GET  /download/{id} - Download a generated policy (cached 10 minutes)
  GET  /health        - Health check endpoint
  GET  /              - Web UI`,
		RunE: runServe,
	}
	serveCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	serveCmd.Flags().StringVar(&externalURL, "external-url", os.Getenv("CF2CNP_EXTERNAL_URL"),
		"Base URL clients reach the server at (e.g. https://cf2cnp.example.com); used for download_url. "+
			"Default: derived from the request and its Forwarded / X-Forwarded-Proto / X-Forwarded-Host headers. "+
			"Env: CF2CNP_EXTERNAL_URL")

	// YOLO command (easter egg)
	yoloCmd := &cobra.Command{
		Use:   "yolo",
		Short: "YOLO mode - generate permissive policies",
		Long:  "Easter egg commands for generating permissive policies. Use with caution!",
	}

	yoloNsCmd := &cobra.Command{
		Use:   "ns",
		Short: "Generate a policy that allows all traffic within a namespace",
		Long: `Generate a CiliumNetworkPolicy that allows all ingress and egress traffic
within the same namespace. This is useful for development/testing but should
NOT be used in production!

Example:
  cf2cnp yolo ns --namespace my-namespace`,
		RunE: runYoloNs,
	}
	yoloNsCmd.Flags().StringVarP(&yoloNamespace, "namespace", "n", "default", "Target namespace for the YOLO policy")

	yoloCmd.AddCommand(yoloNsCmd)

	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(yoloCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runYoloNs(cmd *cobra.Command, args []string) error {
	fmt.Println("YOLO MODE ACTIVATED!")
	fmt.Printf("Generating permissive policy for namespace: %s\n", yoloNamespace)
	fmt.Println()

	yamlBytes, err := policy.YOLONamespacePolicyYAML(yoloNamespace)
	if err != nil {
		return fmt.Errorf("failed to generate YOLO policy: %w", err)
	}

	fmt.Println(string(yamlBytes))
	return nil
}

func runGenerate(cmd *cobra.Command, args []string) error {
	// Validate input directory exists
	if _, err := os.Stat(inputDir); os.IsNotExist(err) {
		return fmt.Errorf("input directory does not exist: %s", inputDir)
	}

	fmt.Printf("Reading flows from: %s\n", inputDir)

	// Parse all flow files from input directory
	flows, err := flow.ParseFlowsFromDirectory(inputDir)
	if err != nil {
		return fmt.Errorf("failed to parse flows: %w", err)
	}

	if len(flows) == 0 {
		fmt.Println("No flow files found in input directory")
		return nil
	}

	fmt.Printf("Parsed %d flow(s)\n", len(flows))

	// Aggregate flows by source/destination
	aggregatedFlows := aggregator.AggregateFlows(flows)
	fmt.Printf("Aggregated into %d policy/policies\n", len(aggregatedFlows))

	// Generate policies
	generator := policy.NewGenerator(outputDir)
	if l7 {
		generator = generator.WithL7()
	}
	if dnsVisibility {
		generator = generator.WithDNSVisibility()
	}
	if err := generator.GeneratePolicies(aggregatedFlows); err != nil {
		return fmt.Errorf("failed to generate policies: %w", err)
	}

	fmt.Println("Policy generation complete!")
	return nil
}

func runServe(cmd *cobra.Command, args []string) error {
	srv := server.NewServer(port, externalURL)
	return srv.Start()
}
