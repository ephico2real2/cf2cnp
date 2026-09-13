package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"runtime/debug"

	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/crd"
	"github.com/hubble-policy-gen/internal/flow"
	"github.com/hubble-policy-gen/internal/policy"
	"github.com/hubble-policy-gen/internal/server"
	"github.com/spf13/cobra"
)

// version is set at build time: -ldflags "-X main.version=<tag>" (the release workflow and the Dockerfile do)
var version = "dev"

var (
	inputDir       string
	outputDir      string
	port           int
	externalURL    string
	l7             bool
	dnsVisibility  bool
	existingFile   string
	outputFile     string
	yoloNamespace  string
	allowedOrigins string
	authToken      string
	dnsProfile     string
	dnsResolver    string
	// serve has its own pair: cobra's StringVar sets the variable to the flag's default at registration, so a variable
	// shared with generate/merge would be reset to "auto" by whichever command registers last (measured: the env
	// default was lost)
	serveDNSProfile  string
	serveDNSResolver string
)

func main() {
	rootCmd := &cobra.Command{
		SilenceUsage: true, // a runtime error is not a usage error: print the message, not the flags
		Use:          "cf2cnp",
		Short:        "CF2CNP - Cilium Flow to CiliumNetworkPolicy",
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
	generateCmd.Flags().StringVarP(&inputDir, "input", "i", "", "A Hubble flow file (one flow, an array, or one per line) or a directory of such files (required)")
	generateCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for generated CiliumNetworkPolicy YAML files (required)")
	generateCmd.Flags().BoolVar(&l7, "l7", false, "Emit layer-7 rules (HTTP method+path, DNS names) from the flows' l7 records; the port then goes through the proxy")
	generateCmd.Flags().BoolVar(&dnsVisibility, "dns-visibility", false, "For world traffic without DNS names, add the kube-dns L7 DNS rule so the next flows carry names (toFQDNs on the next run)")
	generateCmd.Flags().StringVar(&dnsProfile, "dns-profile", "auto", "The DNS resolver rule toFQDNs and --dns-visibility write: auto (from the observed DNS flows, else kubernetes), kubernetes (kube-system, k8s-app=kube-dns, 53/ANY), openshift (openshift-dns, 5353/ANY)")
	generateCmd.Flags().StringVar(&dnsResolver, "dns-resolver", "", "The DNS resolver explicitly, over --dns-profile: <namespace>[/<label>=<value>]:<port>[/<protocol>], e.g. openshift-dns:5353/ANY (no protocol: ANY)")
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
	serveCmd.Flags().StringVar(&allowedOrigins, "allowed-origins", os.Getenv("CF2CNP_ALLOWED_ORIGINS"),
		"Comma-separated origins allowed by CORS (e.g. https://grafana.example.com). Empty or * = any origin. Env: CF2CNP_ALLOWED_ORIGINS")
	serveCmd.Flags().StringVar(&authToken, "auth-token", os.Getenv("CF2CNP_AUTH_TOKEN"),
		"When set, /generate and /download require Authorization: Bearer <token>. Env: CF2CNP_AUTH_TOKEN (prefer the env)")
	serveCmd.Flags().StringVar(&serveDNSProfile, "dns-profile", envOr("CF2CNP_DNS_PROFILE", "auto"),
		"The DNS resolver profile a request gets when it omits ?dnsProfile= (see generate --dns-profile). Env: CF2CNP_DNS_PROFILE")
	serveCmd.Flags().StringVar(&serveDNSResolver, "dns-resolver", os.Getenv("CF2CNP_DNS_RESOLVER"),
		"The DNS resolver a request gets when it omits ?dnsResolver= (see generate --dns-resolver). Env: CF2CNP_DNS_RESOLVER")

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

	// Merge command (E5): evolve an existing policy instead of regenerating it
	mergeCmd := &cobra.Command{
		Use:   "merge",
		Short: "Merge rules generated from flows into an existing CiliumNetworkPolicy file",
		Long: `Read flows (a file or a directory), generate the policy for their workload, and add its rules to an
existing CiliumNetworkPolicy YAML — keeping every field of the existing document, adding only rules that
are not already there. Running it twice changes nothing. The existing policy must be the same target
(namespace, name, endpointSelector); otherwise the command refuses.`,
		RunE: runMerge,
	}
	mergeCmd.Flags().StringVar(&existingFile, "existing", "", "Existing CiliumNetworkPolicy YAML (required)")
	mergeCmd.Flags().StringVarP(&inputDir, "input", "i", "", "Flow file (one flow, an array, or one per line) or a directory of such files (required)")
	mergeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Where to write the merged policy (default: --existing, in place)")
	mergeCmd.Flags().StringVar(&dnsProfile, "dns-profile", "auto", "The DNS resolver rule (see generate --dns-profile)")
	mergeCmd.Flags().StringVar(&dnsResolver, "dns-resolver", "", "The DNS resolver explicitly (see generate --dns-resolver)")
	mergeCmd.MarkFlagRequired("existing")
	mergeCmd.MarkFlagRequired("input")

	// Version: the tool's own version and the policy spec it supports — the Cilium module its types come from
	// and the CRD embedded from it. A release states both; a Cilium bump is a release.
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version and the CiliumNetworkPolicy spec this build supports",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cf2cnp %s\n", version)
			fmt.Printf("policy spec: CiliumNetworkPolicy cilium.io/v2 as of Cilium %s (types: github.com/cilium/cilium/pkg/policy/api %s; CRD embedded from the same module)\n", crd.Version(), ciliumModuleVersion())
		},
	}

	// Validate: the checks the agent applies at admission (Cilium's Rule.Sanitize), on any policy file — generated
	// or hand-written. The CRD schema itself is checked in CI against the embedded copy (see .github/workflows/ci.yml).
	validateCmd := &cobra.Command{
		Use:   "validate <file>...",
		Short: "Validate CiliumNetworkPolicy YAML files with Cilium's own rule checks",
		Args:  cobra.MinimumNArgs(1),
		RunE:  runValidate,
	}

	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(mergeCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(versionCmd)
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
	fmt.Printf("Reading flows from: %s\n", inputDir)

	// A file or a directory (0.7.0: the directory-only form left the policy-PR template's first run without a policy)
	flows, err := readFlows(inputDir)
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
	if err := applyDNSFlags(generator); err != nil {
		return err
	}
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
	var origins []string
	for _, o := range strings.Split(allowedOrigins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	// refuse a bad default at start, not per request
	if _, err := policy.NewGenerator("").WithDNSProfile(serveDNSProfile); err != nil {
		return err
	}
	if serveDNSResolver != "" {
		if _, err := policy.ParseDNSResolver(serveDNSResolver); err != nil {
			return err
		}
	}
	srv := server.NewServerWithOptions(port, externalURL, server.Options{
		AllowedOrigins: origins, AuthToken: authToken, DNSProfile: serveDNSProfile, DNSResolver: serveDNSResolver,
	})
	return srv.Start()
}

// envOr is an environment variable's value, or the default when it is unset or empty
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// readFlows reads a flows file or every .json file of a directory
func readFlows(path string) ([]*flow.ParsedFlow, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return flow.ParseFlowsFromDirectory(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return flow.ParseFlowsFromBytes(data)
}

func runMerge(cmd *cobra.Command, args []string) error {
	existingBytes, err := os.ReadFile(existingFile)
	if err != nil {
		return err
	}
	flows, err := readFlows(inputDir)
	if err != nil {
		return err
	}
	generator := policy.NewGenerator("")
	if err := applyDNSFlags(generator); err != nil {
		return err
	}
	policies, err := generator.BuildPolicies(aggregator.AggregateFlows(flows))
	if err != nil {
		return err
	}
	if len(policies) != 1 {
		return fmt.Errorf("the flows produce %d policies; merge takes exactly one target — filter the flows to one workload", len(policies))
	}
	out, added, err := policy.MergeDocument(existingBytes, policies[0])
	if err != nil {
		return err
	}
	target := outputFile
	if target == "" {
		target = existingFile
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(target, out, 0o644); err != nil {
		return err
	}
	fmt.Printf("%d rule(s) added → %s\n", added, target)
	return nil
}

// ciliumModuleVersion is the version of github.com/cilium/cilium linked into this binary (the supported spec)
func ciliumModuleVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/cilium/cilium" {
				return d.Version
			}
		}
	}
	return "unknown"
}

// runValidate parses every document of every file as a CiliumNetworkPolicy and runs policy.Validate on it; the
// exit code is the number of documents refused, and each refusal carries the agent's own sentence.
func runValidate(cmd *cobra.Command, args []string) error {
	failed := 0
	for _, path := range args {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		docs, err := policy.DecodePolicyDocuments(b)
		if err != nil {
			fmt.Printf("%s: cannot parse: %v\n", path, err)
			failed++
		}
		for i, p := range docs {
			if p.Kind != "CiliumNetworkPolicy" && p.Kind != "CiliumClusterwideNetworkPolicy" {
				fmt.Printf("%s (document %d): kind %q is not a Cilium policy\n", path, i+1, p.Kind)
				failed++
				continue
			}
			if err := policy.Validate(p); err != nil {
				fmt.Printf("%s (document %d): %v\n", path, i+1, err)
				failed++
				continue
			}
			fmt.Printf("%s (document %d): %s/%s ok\n", path, i+1, p.Metadata.Namespace, p.Metadata.Name)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d document(s) refused", failed)
	}
	return nil
}

// applyDNSFlags sets the DNS resolver options shared by generate and merge (0.7.0, dns.go)
func applyDNSFlags(g *policy.Generator) error {
	if _, err := g.WithDNSProfile(dnsProfile); err != nil {
		return err
	}
	if dnsResolver != "" {
		if _, err := g.WithDNSResolver(dnsResolver); err != nil {
			return err
		}
	}
	return nil
}
