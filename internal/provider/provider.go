// Package provider implements the dnsgate Terraform/OpenTofu provider.
package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/auth"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

const (
	envEndpoint               = "DNSGATE_ENDPOINT"
	envToken                  = "DNSGATE_TOKEN"
	envTokenFile              = "DNSGATE_TOKEN_FILE"
	envADOServiceConnectionID = "DNSGATE_ADO_SERVICE_CONNECTION_ID"
	defaultSigningAlg         = "RS256"
	defaultMaxRetries         = 10
	defaultRequestTimeout     = 60 * time.Second
)

var _ provider.Provider = (*dnsgateProvider)(nil)

type dnsgateProvider struct {
	version string
	// Replaced in tests.
	newSTS             func(region string) func(ctx context.Context) (auth.STSTokenAPI, error)
	newAzureCredential func(auth.AzureIdentityConfig) (azcore.TokenCredential, error)
	ciHTTP             *http.Client
	sleep              func(ctx context.Context, d time.Duration) error
}

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &dnsgateProvider{
			version: version, newSTS: auth.DefaultSTSClient, newAzureCredential: auth.DefaultAzureCredential,
			ciHTTP: &http.Client{Timeout: 30 * time.Second},
		}
	}
}

type providerModel struct {
	Endpoint       types.String `tfsdk:"endpoint"`
	MaxRetries     types.Int64  `tfsdk:"max_retries"`
	RequestTimeout types.String `tfsdk:"request_timeout"`
	Auth           *authModel   `tfsdk:"auth"`
}

type authModel struct {
	Token          types.String         `tfsdk:"token"`
	TokenFile      types.String         `tfsdk:"token_file"`
	TokenCommand   types.List           `tfsdk:"token_command"`
	AWSWebIdentity *awsWebIdentityModel `tfsdk:"aws_web_identity"`
	AzureIdentity  *azureIdentityModel  `tfsdk:"azure_identity"`
	AzureDevOps    *azureDevOpsModel    `tfsdk:"azure_devops"`
	GitHubActions  *githubActionsModel  `tfsdk:"github_actions"`
}

type awsWebIdentityModel struct {
	Audience         types.String `tfsdk:"audience"`
	SigningAlgorithm types.String `tfsdk:"signing_algorithm"`
	Region           types.String `tfsdk:"region"`
	DurationSeconds  types.Int64  `tfsdk:"duration_seconds"`
}

type azureIdentityModel struct {
	Scope    types.String `tfsdk:"scope"`
	TenantID types.String `tfsdk:"tenant_id"`
	ClientID types.String `tfsdk:"client_id"`
}

type azureDevOpsModel struct {
	ServiceConnectionID types.String `tfsdk:"service_connection_id"`
}

type githubActionsModel struct {
	Audience types.String `tfsdk:"audience"`
}

func (p *dnsgateProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "dnsgate"
	resp.Version = p.version
}

func (p *dnsgateProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages DNS record sets through a [dns-gate](https://github.com/KamorionLabs/dns-gate), " +
			"whatever the DNS provider behind it (EuroDNS, Route53...). Terraform only holds its own short-lived identity; " +
			"the gate holds the provider credentials, enforces RBAC and per-RRset ownership, and audits every change.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Base URL of the gate, for example `https://dns-gate.example.com`. Env: `DNSGATE_ENDPOINT`.",
			},
			"max_retries": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Retries of a request answered 423 `zone_locked`, 429, 5xx or lost in transit, with exponential " +
					"backoff (1s doubling, at most 30s, `Retry-After` honoured). Default 10. `0` disables retries.",
			},
			"request_timeout": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Timeout of one request, as a Go duration. Default `60s`.",
			},
		},
		Blocks: map[string]schema.Block{
			"auth": schema.SingleNestedBlock{
				MarkdownDescription: "How to obtain the bearer token sent to the gate: exactly one method, plus optionally one CI " +
					"method (`azure_devops`, `github_actions`) that takes precedence inside its CI system. Without this block, " +
					"`DNSGATE_TOKEN` or `DNSGATE_TOKEN_FILE` is used. See the authentication guide.",
				Attributes: map[string]schema.Attribute{
					"token": schema.StringAttribute{
						Optional: true, Sensitive: true,
						MarkdownDescription: "Static token (OIDC JWT, or a gate virtual key).",
					},
					"token_file": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "File holding the token, re-read when the token expires (projected Kubernetes tokens, CI OIDC token files).",
					},
					"token_command": schema.ListAttribute{
						Optional: true, ElementType: types.StringType,
						MarkdownDescription: "Command (argv) printing the token on stdout, run again when the token expires.",
					},
				},
				Blocks: map[string]schema.Block{
					"aws_web_identity": schema.SingleNestedBlock{
						MarkdownDescription: "Get a JWT signed by AWS STS (`sts:GetWebIdentityToken`, IAM outbound identity " +
							"federation) for the current AWS principal, from the default AWS credential chain.",
						Attributes: map[string]schema.Attribute{
							"audience":          schema.StringAttribute{Optional: true, MarkdownDescription: "Token audience expected by the gate. Required in this block."},
							"signing_algorithm": schema.StringAttribute{Optional: true, MarkdownDescription: "`RS256` (default) or `ES384`."},
							"region":            schema.StringAttribute{Optional: true, MarkdownDescription: "STS region. Default: from the AWS configuration."},
							"duration_seconds":  schema.Int64Attribute{Optional: true, MarkdownDescription: "Requested token lifetime."},
						},
					},
					"azure_identity": schema.SingleNestedBlock{
						MarkdownDescription: "Get a Microsoft Entra ID access token for the gate application: environment " +
							"credentials, AKS workload identity, managed identity, then Azure CLI.",
						Attributes: map[string]schema.Attribute{
							"scope":     schema.StringAttribute{Optional: true, MarkdownDescription: "Scope of the gate application, for example `api://dns-gate/.default`. Required in this block."},
							"tenant_id": schema.StringAttribute{Optional: true, MarkdownDescription: "Entra tenant. Default: from the environment or the Azure CLI login."},
							"client_id": schema.StringAttribute{Optional: true, MarkdownDescription: "Client id of a user-assigned managed identity or workload identity."},
						},
					},
					"azure_devops": schema.SingleNestedBlock{
						MarkdownDescription: "Inside an Azure DevOps job, get the OIDC token Azure DevOps issues for a service connection " +
							"(`SYSTEM_OIDCREQUESTURI`, with `SYSTEM_ACCESSTOKEN` mapped into the step environment). Outside a job, " +
							"the other method of the block is used.",
						Attributes: map[string]schema.Attribute{
							"service_connection_id": schema.StringAttribute{
								Optional:            true,
								MarkdownDescription: "Service connection id. Default: `DNSGATE_ADO_SERVICE_CONNECTION_ID`. Required inside a job, one way or the other.",
							},
						},
					},
					"github_actions": schema.SingleNestedBlock{
						MarkdownDescription: "Inside a GitHub Actions job with `permissions: id-token: write`, get the job's OIDC token " +
							"(`ACTIONS_ID_TOKEN_REQUEST_URL`). Outside a job, the other method of the block is used.",
						Attributes: map[string]schema.Attribute{
							"audience": schema.StringAttribute{Optional: true, MarkdownDescription: "Token audience expected by the gate. Required in this block."},
						},
					},
				},
			},
		},
	}
}

// providerData is handed to resources and data sources.
type providerData struct {
	client *client.Client
	info   *client.Info
}

func (p *dnsgateProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.Endpoint.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Unknown endpoint",
			"The gate endpoint must be known when the provider is configured.")
		return
	}
	opts, err := p.resolve(ctx, cfg)
	if err != nil {
		resp.Diagnostics.AddError("Invalid dnsgate provider configuration", err.Error())
		return
	}
	c, err := client.New(*opts)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Invalid endpoint", err.Error())
		return
	}
	info, err := c.Info(ctx)
	if errors.Is(err, client.ErrNotGate) {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Not a dns-gate",
			fmt.Sprintf("%s does not serve %s. Point endpoint at a dns-gate instance.", c.BaseURL(), client.InfoPath))
		return
	}
	if err != nil {
		addAPIError(&resp.Diagnostics, "Cannot reach the dns-gate", err)
		return
	}
	if !info.HasFeature(featureRRsetAPI) {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "The dns-gate does not serve the RRset API",
			fmt.Sprintf("%s (version %s) does not advertise the %q feature in %s. This provider needs a gate with the RRset REST API: "+
				"upgrade the gate, or use the kamorionlabs/eurodns provider in gate mode against older gates.",
				c.BaseURL(), firstNonEmpty(info.Version, "unknown"), featureRRsetAPI, client.InfoPath))
		return
	}
	data := &providerData{client: c, info: info}
	resp.ResourceData = data
	resp.DataSourceData = data
}

// resolve merges configuration and environment into client options.
func (p *dnsgateProvider) resolve(ctx context.Context, cfg providerModel) (*client.Options, error) {
	o := &client.Options{
		BaseURL:        firstNonEmpty(cfg.Endpoint.ValueString(), os.Getenv(envEndpoint)),
		UserAgent:      "terraform-provider-dnsgate/" + p.version,
		MaxRetries:     defaultMaxRetries,
		RequestTimeout: defaultRequestTimeout,
		Sleep:          p.sleep,
	}
	if o.BaseURL == "" {
		return nil, fmt.Errorf("endpoint is required (or %s)", envEndpoint)
	}
	if !cfg.MaxRetries.IsNull() {
		n := cfg.MaxRetries.ValueInt64()
		if n < 0 {
			return nil, errors.New("max_retries cannot be negative")
		}
		o.MaxRetries = int(n)
		if n == 0 {
			o.MaxRetries = -1
		}
	}
	if v := cfg.RequestTimeout.ValueString(); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("request_timeout: %q is not a positive Go duration", v)
		}
		o.RequestTimeout = d
	}
	src, err := p.tokenSource(ctx, cfg.Auth)
	if err != nil {
		return nil, err
	}
	o.Tokens = src
	return o, nil
}

func (p *dnsgateProvider) tokenSource(ctx context.Context, a *authModel) (auth.TokenSource, error) {
	if a == nil {
		tok, file := os.Getenv(envToken), os.Getenv(envTokenFile)
		switch {
		case tok != "" && file != "":
			return nil, fmt.Errorf("set only one of %s and %s", envToken, envTokenFile)
		case tok != "":
			return auth.Static(tok), nil
		case file != "":
			return auth.NewCaching(auth.FileFetch(file)), nil
		}
		return nil, fmt.Errorf("no credentials: set the auth block, %s or %s", envToken, envTokenFile)
	}

	n := 0
	for _, set := range []bool{
		a.Token.ValueString() != "",
		a.TokenFile.ValueString() != "",
		!a.TokenCommand.IsNull() && len(a.TokenCommand.Elements()) > 0,
		a.AWSWebIdentity != nil,
		a.AzureIdentity != nil,
	} {
		if set {
			n++
		}
	}
	const methods = "token, token_file, token_command, aws_web_identity, azure_identity"
	if a.AzureDevOps != nil && a.GitHubActions != nil {
		return nil, errors.New("auth: azure_devops and github_actions are mutually exclusive")
	}
	ci := a.AzureDevOps != nil || a.GitHubActions != nil
	switch {
	case ci && n > 1:
		return nil, errors.New("auth: a CI method (azure_devops, github_actions) can be combined with at most one of " + methods)
	case !ci && n != 1:
		return nil, errors.New("auth must set exactly one of " + methods + ", azure_devops, github_actions")
	}

	if a.AzureDevOps != nil {
		id := firstNonEmpty(a.AzureDevOps.ServiceConnectionID.ValueString(), os.Getenv(envADOServiceConnectionID))
		if auth.InAzureDevOpsJob() {
			if id == "" {
				return nil, fmt.Errorf("auth.azure_devops: service_connection_id is required (or %s in the environment)", envADOServiceConnectionID)
			}
			tok := os.Getenv(auth.EnvADOAccessToken)
			if tok == "" {
				return nil, fmt.Errorf("auth.azure_devops: %s is empty; map it into the step environment (env: %s: $(System.AccessToken))",
					auth.EnvADOAccessToken, auth.EnvADOAccessToken)
			}
			return auth.NewCaching(auth.AzureDevOpsFetch(auth.AzureDevOpsConfig{
				ServiceConnectionID: id, RequestURI: os.Getenv(auth.EnvADOOIDCRequestURI), AccessToken: tok,
			}, p.ciHTTP)), nil
		}
		if n == 0 {
			return nil, fmt.Errorf("auth.azure_devops only works inside an Azure DevOps job (%s is not set); add another method for runs outside a pipeline",
				auth.EnvADOOIDCRequestURI)
		}
	}
	if a.GitHubActions != nil {
		aud := a.GitHubActions.Audience.ValueString()
		if aud == "" {
			return nil, errors.New("auth.github_actions.audience is required")
		}
		if auth.InGitHubActionsJob() {
			tok := os.Getenv(auth.EnvGitHubRequestToken)
			if tok == "" {
				return nil, fmt.Errorf("auth.github_actions: %s is empty; grant the job `permissions: id-token: write`", auth.EnvGitHubRequestToken)
			}
			return auth.NewCaching(auth.GitHubActionsFetch(auth.GitHubActionsConfig{
				Audience: aud, RequestURL: os.Getenv(auth.EnvGitHubRequestURL), RequestToken: tok,
			}, p.ciHTTP)), nil
		}
		if n == 0 {
			return nil, fmt.Errorf("auth.github_actions only works inside a GitHub Actions job (%s is not set); add another method for runs outside a workflow",
				auth.EnvGitHubRequestURL)
		}
	}

	switch {
	case a.Token.ValueString() != "":
		return auth.Static(a.Token.ValueString()), nil
	case a.TokenFile.ValueString() != "":
		return auth.NewCaching(auth.FileFetch(a.TokenFile.ValueString())), nil
	case a.AWSWebIdentity != nil:
		w := a.AWSWebIdentity
		if w.Audience.ValueString() == "" {
			return nil, errors.New("auth.aws_web_identity.audience is required")
		}
		alg := firstNonEmpty(w.SigningAlgorithm.ValueString(), defaultSigningAlg)
		if alg != "RS256" && alg != "ES384" {
			return nil, fmt.Errorf("auth.aws_web_identity.signing_algorithm: %q is not RS256 or ES384", alg)
		}
		c := auth.AWSWebIdentityConfig{Audience: w.Audience.ValueString(), SigningAlgorithm: alg,
			Region: w.Region.ValueString(), DurationSeconds: int32(w.DurationSeconds.ValueInt64())}
		return auth.NewCaching(auth.AWSWebIdentityFetch(c, p.newSTS(c.Region))), nil
	case a.AzureIdentity != nil:
		z := a.AzureIdentity
		if z.Scope.ValueString() == "" {
			return nil, errors.New("auth.azure_identity.scope is required")
		}
		c := auth.AzureIdentityConfig{Scope: z.Scope.ValueString(), TenantID: z.TenantID.ValueString(), ClientID: z.ClientID.ValueString()}
		return auth.NewCaching(auth.AzureFetch(c, p.newAzureCredential)), nil
	default:
		var argv []string
		if diags := a.TokenCommand.ElementsAs(ctx, &argv, false); diags.HasError() || len(argv) == 0 {
			return nil, errors.New("auth.token_command must be a non-empty list of strings")
		}
		return auth.NewCaching(auth.CommandFetch(argv)), nil
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func (p *dnsgateProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newRecordSetResource, newRoleResource, newBindingResource}
}

func (p *dnsgateProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newZonesDataSource, newRecordSetsDataSource, newRecordSetDataSource}
}

// providerDataFrom extracts the provider data in Configure of resources and data sources.
func providerDataFrom(data any, add func(summary, detail string)) *providerData {
	if data == nil {
		return nil
	}
	pd, ok := data.(*providerData)
	if !ok {
		add("Unexpected provider data", fmt.Sprintf("got %T", data))
		return nil
	}
	return pd
}
