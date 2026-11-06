package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

// dnsgate_url_forward

type urlForwardDataSource struct{ pd *providerData }

func newURLForwardDataSource() datasource.DataSource { return &urlForwardDataSource{} }

type urlForwardDataModel struct {
	ID          types.String `tfsdk:"id"`
	Zone        types.String `tfsdk:"zone"`
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	URL         types.String `tfsdk:"url"`
	Title       types.String `tfsdk:"title"`
	Keywords    types.String `tfsdk:"keywords"`
	Description types.String `tfsdk:"description"`
	OwnerTeam   types.String `tfsdk:"owner_team"`
	Status      types.String `tfsdk:"status"`
	HTTPSStatus types.String `tfsdk:"https_status"`
	Hash        types.String `tfsdk:"hash"`
}

func (d *urlForwardDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_url_forward"
}

func (d *urlForwardDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The URL forward (HTTP redirect) of a name in a zone served by the gate, whoever owns it. Fails if " +
			"the name has no forward.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, MarkdownDescription: "`<zone>/<name>`, the import id of `dnsgate_url_forward`."},
			"zone":        schema.StringAttribute{Required: true},
			"name":        schema.StringAttribute{Required: true, MarkdownDescription: "Name relative to the zone, `@` for the apex."},
			"type":        schema.StringAttribute{Computed: true, MarkdownDescription: "`301`, `302` or `frame`."},
			"url":         schema.StringAttribute{Computed: true, MarkdownDescription: "Target URL."},
			"title":       schema.StringAttribute{Computed: true, MarkdownDescription: "Title of a frame forward, empty otherwise."},
			"keywords":    schema.StringAttribute{Computed: true, MarkdownDescription: "Meta keywords of a frame forward, empty otherwise."},
			"description": schema.StringAttribute{Computed: true, MarkdownDescription: "Meta description of a frame forward, empty otherwise."},
			"owner_team":  schema.StringAttribute{Computed: true, MarkdownDescription: "Owner team, empty when not owned."},
			"status":      schema.StringAttribute{Computed: true, MarkdownDescription: "`managed`, `pending`, `tainted`, `foreign`, `missing`."},
			"https_status": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Whether the forwards of the zone answer HTTPS: `active`, `pending`, `no_forward`, `inactive` " +
					"(plain HTTP only), `unsupported`, `unknown`.",
			},
			"hash": schema.StringAttribute{Computed: true, MarkdownDescription: "Content hash (the ETag of the forward)."},
		},
	}
}

func (d *urlForwardDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
	if d.pd != nil {
		requireForwards(d.pd, "the dnsgate_url_forward data source", &resp.Diagnostics)
	}
}

func (d *urlForwardDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data urlForwardDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone := client.NormalizeZone(data.Zone.ValueString())
	name := strings.ToLower(strings.TrimSpace(data.Name.ValueString()))
	v, err := d.pd.client.GetForward(ctx, zone, name)
	if client.IsNotFound(err) || err == nil && v.Forward == nil {
		resp.Diagnostics.AddError("URL forward not found", fmt.Sprintf("%s has no URL forward in zone %s.", name, zone))
		return
	}
	if err != nil {
		addForwardError(&resp.Diagnostics, "Cannot read the URL forward", zone, err)
		return
	}
	f := v.Forward
	data.ID = types.StringValue(urlForwardID(zone, name))
	data.Type, data.URL = types.StringValue(strings.ToLower(f.Type)), types.StringValue(f.URL)
	data.Title, data.Keywords, data.Description = types.StringValue(f.Title), types.StringValue(f.Keywords), types.StringValue(f.Description)
	data.OwnerTeam, data.Status = types.StringValue(v.Owner), types.StringValue(v.Status)
	data.HTTPSStatus, data.Hash = types.StringValue(httpsStatus(v.HTTPS)), types.StringValue(v.Hash)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
