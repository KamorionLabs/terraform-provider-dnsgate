package provider

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

var (
	_ resource.ResourceWithConfigure      = (*urlForwardResource)(nil)
	_ resource.ResourceWithImportState    = (*urlForwardResource)(nil)
	_ resource.ResourceWithValidateConfig = (*urlForwardResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*urlForwardResource)(nil)
)

type urlForwardResource struct {
	pd *providerData
}

func newURLForwardResource() resource.Resource { return &urlForwardResource{} }

type urlForwardModel struct {
	ID           types.String `tfsdk:"id"`
	Zone         types.String `tfsdk:"zone"`
	Name         types.String `tfsdk:"name"`
	Type         types.String `tfsdk:"type"`
	URL          types.String `tfsdk:"url"`
	Title        types.String `tfsdk:"title"`
	Keywords     types.String `tfsdk:"keywords"`
	Description  types.String `tfsdk:"description"`
	RequireHTTPS types.Bool   `tfsdk:"require_https"`
	Team         types.String `tfsdk:"team"`
	OwnerTeam    types.String `tfsdk:"owner_team"`
	Status       types.String `tfsdk:"status"`
	HTTPSStatus  types.String `tfsdk:"https_status"`
}

func (r *urlForwardResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_url_forward"
}

func (r *urlForwardResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	frameOnly := func(what string, max int) schema.StringAttribute {
		return schema.StringAttribute{
			Optional: true,
			MarkdownDescription: what + " of the frame page, plain text of at most " + strconv.Itoa(max) +
				" characters without `<`, `>`, `\"`, `'` nor `` ` ``. Only with `type = \"frame\"`.",
			Validators: []validator.String{trimmedValidator{}, frameTextValidator{max: max}},
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "The URL forward (HTTP redirect) of a name in a zone served by a dns-gate: the DNS provider answers " +
			"HTTP requests for the name with a 301 or 302 redirect to `url`, or with a page showing it in a frame. Only zones " +
			"whose DNS provider has URL forwards (EuroDNS) have them. Like a record set, the forward is owned by a team of the " +
			"provider identity in the gate (its default team, or `team`), and every change is audited. Creation fails if the " +
			"name already has a forward: adopt it in the gate, then import it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "`<zone>/<name>`, also the import id.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"zone": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Zone name, lowercase without trailing dot, for example `example.com`. Changing it replaces the forward.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:          []validator.String{zoneValidator{}},
			},
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Name relative to the zone, lowercase, without trailing dot: `go`, `www`, `@` for the apex. " +
					"Changing it replaces the forward.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{nameValidator{}},
			},
			"type": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "`301` (permanent redirect), `302` (temporary redirect) or `frame` (a page showing `url` " +
					"in a frame, the browser keeping the forwarded name in its address bar).",
				Validators: []validator.String{stringvalidator.OneOf(client.ForwardTypes...)},
			},
			"url": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Target, an absolute `http://` or `https://` URL of at most 2048 bytes in canonical form, " +
					"without user name, password, spaces nor unencoded `<>\"'`\\{}|^`, for example `https://www.example.com/landing`.",
				Validators: []validator.String{forwardURLValidator{}},
			},
			"title":       frameOnly("Title", maxForwardTitle),
			"keywords":    frameOnly("Meta keywords", maxForwardKeywords),
			"description": frameOnly("Meta description", maxForwardDescription),
			"require_https": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Fail the apply instead of writing a forward that answers plain HTTP only: the gate refuses " +
					"the write (`409 https_unavailable`) unless the forwards of the zone answer HTTPS (`https_status` `active`, " +
					"`no_forward`; `pending` is refused, its certificate is not issued yet). Sent on every write, never read back: the state keeps the configured value. " +
					"Default `false`.",
			},
			"team": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Team of the provider identity to act for, when it belongs to several teams in the gate. " +
					"Sent as the `X-DNS-Gate-Team` header on create, update and delete: the forward is created for this team, " +
					"and the gate refuses to change it unless this team owns it. Unset, the gate uses the default team of the " +
					"identity. Changing `team` never moves an existing forward to another team: the plan fails unless the forward " +
					"is already owned by the new team (same rules as `dnsgate_record_set`).",
				Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"owner_team": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Team that owns the forward in the gate.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"status": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Ownership status in the gate: `managed`, `pending`, `tainted` (modified outside the gate, " +
					"writes blocked until reviewed), `foreign` (not owned by the gate).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"https_status": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Whether the forwards of the zone answer HTTPS requests, as the gate reads it from the DNS " +
					"provider: `active`, `no_forward` or `pending` (an HTTPS redirect subscription covers the domain, `pending` while its certificate is issued), `inactive` " +
					"(plain HTTP only), `unsupported` (the provider has no forwards), `unknown`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *urlForwardResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.pd = providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
	if r.pd != nil {
		requireForwards(r.pd, "dnsgate_url_forward", &resp.Diagnostics)
	}
}

// requireForwards refuses gates without the URL forward API: their 404 for
// an unknown route would read as a deleted forward.
func requireForwards(pd *providerData, what string, diags *diag.Diagnostics) {
	if !pd.info.HasFeature(client.FeatureForwards) {
		diags.AddError("The dns-gate does not serve the URL forward API",
			fmt.Sprintf("%s needs a gate that advertises the %q feature (GET %s, version %s here). Upgrade the gate.",
				what, client.FeatureForwards, client.InfoPath, firstNonEmpty(pd.info.Version, "unknown")))
	}
}

func (r *urlForwardResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg urlForwardModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	checkRelativeName(cfg.Zone, cfg.Name, &resp.Diagnostics)
	if cfg.Type.IsUnknown() || cfg.Type.IsNull() || cfg.Type.ValueString() == client.ForwardFrame {
		return
	}
	for name, v := range map[string]types.String{"title": cfg.Title, "keywords": cfg.Keywords, "description": cfg.Description} {
		if !v.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Only frame forwards have "+name,
				fmt.Sprintf("%s applies to type = \"frame\" only: remove it, or change type.", name))
		}
	}
}

func (r *urlForwardResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.pd == nil {
		return
	}
	var plan urlForwardModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || plan.Team.IsUnknown() || plan.Team.IsNull() {
		return
	}
	if req.State.Raw.IsNull() {
		planCreateTeam(ctx, r.pd, plan.Team.ValueString(), resp)
		return
	}
	var state urlForwardModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, name := state.key()
	planTeamChange(ctx, r.pd, teamChange{
		Team:    plan.Team.ValueString(),
		Owner:   state.OwnerTeam.ValueString(),
		Changed: !plan.Team.Equal(state.Team) || !sameForward(&plan, &state),
		Zone:    zone, Object: "the URL forward of " + name, Kind: "URL forward", Noun: "a forward",
	}, &resp.Diagnostics)
}

func (m *urlForwardModel) key() (zone, name string) {
	return m.Zone.ValueString(), m.Name.ValueString()
}

func urlForwardID(zone, name string) string { return zone + "/" + name }

func (m *urlForwardModel) body() client.ForwardBody {
	return client.ForwardBody{
		Type: m.Type.ValueString(), URL: m.URL.ValueString(),
		Title: m.Title.ValueString(), Keywords: m.Keywords.ValueString(), Description: m.Description.ValueString(),
		RequireHTTPS: m.RequireHTTPS.ValueBool(),
	}
}

// sameForward reports whether plan and state write the same forward.
func sameForward(a, b *urlForwardModel) bool {
	return a.Type.Equal(b.Type) && a.URL.Equal(b.URL) && a.Title.Equal(b.Title) && a.Keywords.Equal(b.Keywords) &&
		a.Description.Equal(b.Description) && a.RequireHTTPS.Equal(b.RequireHTTPS)
}

// forwardEquivalent reports whether the gate holds the desired forward.
func forwardEquivalent(want client.ForwardBody, got *client.Forward) bool {
	return got != nil && strings.EqualFold(want.Type, got.Type) && want.URL == got.URL && want.Title == got.Title &&
		want.Keywords == got.Keywords && want.Description == got.Description
}

func httpsStatus(h *client.HTTPSRedirect) string {
	if h == nil || h.Status == "" {
		return client.HTTPSUnknown
	}
	return h.Status
}

func describeForward(f *client.Forward) string {
	if f == nil {
		return "no forward"
	}
	s := fmt.Sprintf("type %s, url %q", f.Type, f.URL)
	for _, kv := range [][2]string{{"title", f.Title}, {"keywords", f.Keywords}, {"description", f.Description}} {
		if kv[1] != "" {
			s += fmt.Sprintf(", %s %q", kv[0], kv[1])
		}
	}
	return s
}

// written records the gate's answer in the state: the planned forward
// stays, the gate decides owner and status.
func (r *urlForwardResource) written(plan *urlForwardModel, want client.ForwardBody, got *client.ForwardView, diags *diag.Diagnostics) {
	zone, name := plan.key()
	plan.ID = types.StringValue(urlForwardID(zone, name))
	owner := got.Owner
	if owner == "" && !plan.OwnerTeam.IsUnknown() {
		owner = plan.OwnerTeam.ValueString()
	}
	plan.OwnerTeam = types.StringValue(owner)
	plan.Status = types.StringValue(firstNonEmpty(got.Status, client.StatusManaged))
	if plan.HTTPSStatus.IsUnknown() {
		plan.HTTPSStatus = types.StringValue(httpsStatus(got.HTTPS))
	}
	if team := plan.Team.ValueString(); team != "" && got.Owner != "" && got.Owner != team {
		diags.AddError("URL forward written for another team",
			fmt.Sprintf("The forward of %s in %s is owned by team %q in the gate, not by team %q. The gate did not apply the team "+
				"selection (X-DNS-Gate-Team): upgrade the gate, or remove team.", name, zone, got.Owner, team))
	}
	if !forwardEquivalent(want, got.Forward) {
		diags.AddWarning("The gate stored a different forward",
			fmt.Sprintf("The forward of %s in %s: the gate answered with %s, not the configured forward. The next plan will show "+
				"a difference: write the forward as the gate stores it.", name, zone, describeForward(got.Forward)))
	}
}

// reconcile handles a 412 answered after a retry: an earlier attempt may
// have been applied before its answer was lost. The write is a success if
// the gate now holds the desired forward.
func (r *urlForwardResource) reconcile(ctx context.Context, zone, name, team string, want client.ForwardBody, err error) (*client.ForwardView, bool) {
	e, ok := client.AsAPIError(err)
	if !ok || e.Status != http.StatusPreconditionFailed || e.Attempts < 2 {
		return nil, false
	}
	got, gerr := r.pd.client.GetForward(ctx, zone, name)
	if gerr != nil || !forwardEquivalent(want, got.Forward) || team != "" && got.Owner != "" && got.Owner != team {
		return nil, false
	}
	tflog.Info(ctx, "write refused after a retry, but the gate holds the desired forward: an earlier attempt was applied",
		map[string]any{"zone": zone, "name": name})
	return got, true
}

// addForwardError explains a refusal of the forward API.
func addForwardError(diags *diag.Diagnostics, summary, zone string, err error) {
	detail := describe(err)
	if client.Is(err, http.StatusBadRequest, client.ReasonInvalid) {
		detail = fmt.Sprintf("URL forwards exist only on zones whose DNS provider has them (EuroDNS): check the DNS provider of %s "+
			"(dnsgate_zones data source).\n\n%s", zone, detail)
	}
	diags.AddError(summary, detail)
}

func (r *urlForwardResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan urlForwardModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, name := plan.key()
	want := plan.body()
	team := plan.Team.ValueString()
	got, err := r.pd.client.PutForward(ctx, zone, name, want, client.Condition{IfNoneMatch: true, Team: team})
	if err != nil {
		var ok bool
		if got, ok = r.reconcile(ctx, zone, name, team, want, err); !ok {
			r.createError(&resp.Diagnostics, zone, name, err)
			return
		}
	}
	r.written(&plan, want, got, &resp.Diagnostics)
	setHash(ctx, resp.Private, got.Hash, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *urlForwardResource) createError(diags *diag.Diagnostics, zone, name string, err error) {
	id := urlForwardID(zone, name)
	switch {
	case client.IsPrecondition(err):
		diags.AddError("URL forward already exists",
			fmt.Sprintf("%s already has a URL forward in zone %s. If your team owns it in the gate, import it:\n\n"+
				"  import {\n    to = dnsgate_url_forward.<name>\n    id = %q\n  }", name, zone, id))
	case client.Is(err, http.StatusConflict, client.ReasonForeignRRset):
		diags.AddError("URL forward exists outside the gate",
			fmt.Sprintf("%s already has a URL forward in zone %s, not owned by the gate. %s\n\n%s", name, zone, importForwardHelp(zone, name), describe(err)))
	default:
		addForwardError(diags, "Cannot create the URL forward "+id, zone, err)
	}
}

func importForwardHelp(zone, name string) string {
	return fmt.Sprintf("The gate only lets a team manage the forwards it created or adopted. Adopt it for your team first, in the "+
		"gate web UI (zone page, select the forward of %s, Adopt) or with POST /api/v1/zones/%s/adopt/preview then /adopt "+
		"(host %q, type URLFWD), then import it with the id %q.", name, zone, name, urlForwardID(zone, name))
}

func (r *urlForwardResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state urlForwardModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, name := state.key()
	got, err := r.pd.client.GetForward(ctx, zone, name)
	if client.IsNotFound(err) {
		tflog.Info(ctx, "URL forward not found in the gate, removing it from the state", map[string]any{"zone": zone, "name": name})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		addForwardError(&resp.Diagnostics, "Cannot read the URL forward "+urlForwardID(zone, name), zone, err)
		return
	}
	if got.Status == client.StatusMissing || got.Forward == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromGate(got)
	forwardStatusWarning(&resp.Diagnostics, zone, name, got.Status)
	setHash(ctx, resp.Private, got.Hash, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// fromGate sets the state from the gate. require_https and team are not
// read back.
func (m *urlForwardModel) fromGate(got *client.ForwardView) {
	zone, name := m.key()
	m.ID = types.StringValue(urlForwardID(zone, name))
	m.OwnerTeam = types.StringValue(got.Owner)
	m.Status = types.StringValue(got.Status)
	m.HTTPSStatus = types.StringValue(httpsStatus(got.HTTPS))
	m.Type = types.StringValue(strings.ToLower(got.Forward.Type))
	m.URL = types.StringValue(got.Forward.URL)
	m.Title = optionalString(got.Forward.Title)
	m.Keywords = optionalString(got.Forward.Keywords)
	m.Description = optionalString(got.Forward.Description)
	if m.RequireHTTPS.IsNull() || m.RequireHTTPS.IsUnknown() {
		m.RequireHTTPS = types.BoolValue(false)
	}
}

func forwardStatusWarning(diags *diag.Diagnostics, zone, name, status string) {
	switch status {
	case client.StatusTainted:
		diags.AddWarning("URL forward tainted in the gate",
			fmt.Sprintf("The forward of %s in %s was modified outside the gate. %s", name, zone, reasonHelp[client.ReasonTainted]))
	case client.StatusForeign:
		diags.AddWarning("URL forward not owned by the gate",
			fmt.Sprintf("The forward of %s in %s is no longer owned by the gate (foreign): changes will be refused. %s", name, zone, reasonHelp[client.ReasonForeignRRset]))
	}
}

func (r *urlForwardResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan urlForwardModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state urlForwardModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	zone, name := plan.key()
	want := plan.body()
	hash := getHash(ctx, req.Private, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if sameForward(&plan, &state) {
		// Only team changed, to the team that already owns the forward
		// (ModifyPlan refuses anything else): nothing to write.
		plan.ID, plan.OwnerTeam, plan.Status, plan.HTTPSStatus = state.ID, state.OwnerTeam, state.Status, state.HTTPSStatus
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	team := plan.Team.ValueString()
	got, err := r.pd.client.PutForward(ctx, zone, name, want, client.Condition{IfMatch: hash, Team: team})
	if err != nil {
		var ok bool
		if got, ok = r.reconcile(ctx, zone, name, team, want, err); !ok {
			if client.IsPrecondition(err) {
				resp.Diagnostics.AddError("URL forward changed outside Terraform",
					fmt.Sprintf("The forward of %s in %s changed in the gate since Terraform read it. %s", name, zone, reasonHelp[client.ReasonPrecondition]))
				return
			}
			addForwardError(&resp.Diagnostics, "Cannot update the URL forward "+urlForwardID(zone, name), zone, err)
			return
		}
	}
	r.written(&plan, want, got, &resp.Diagnostics)
	setHash(ctx, resp.Private, got.Hash, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *urlForwardResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state urlForwardModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	hash := getHash(ctx, req.Private, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, name := state.key()
	err := r.pd.client.DeleteForward(ctx, zone, name, client.Condition{IfMatch: hash, Team: state.Team.ValueString()})
	if err == nil || client.IsNotFound(err) {
		return
	}
	if e, ok := client.AsAPIError(err); ok && e.Status == http.StatusPreconditionFailed {
		if e.Attempts > 1 {
			if _, gerr := r.pd.client.GetForward(ctx, zone, name); client.IsNotFound(gerr) {
				return
			}
		}
		resp.Diagnostics.AddError("URL forward changed outside Terraform",
			fmt.Sprintf("The forward of %s in %s changed in the gate since Terraform read it, so it was not deleted. %s", name, zone, reasonHelp[client.ReasonPrecondition]))
		return
	}
	addForwardError(&resp.Diagnostics, "Cannot delete the URL forward "+urlForwardID(zone, name), zone, err)
}

// ImportState accepts "<zone>/<name>". The gate only lets a team manage the
// forwards it owns: foreign forwards must be adopted first.
func (r *urlForwardResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	zone, name, ok := parseURLForwardID(req.ID)
	if !ok {
		resp.Diagnostics.AddError("Invalid import id",
			fmt.Sprintf("Expected <zone>/<name>, for example example.com/go or example.com/@, got %q.", req.ID))
		return
	}
	got, err := r.pd.client.GetForward(ctx, zone, name)
	switch {
	case client.IsNotFound(err):
		resp.Diagnostics.AddError("URL forward not found", fmt.Sprintf("%s has no URL forward in zone %s (or the zone is not served by the gate).", name, zone))
		return
	case client.Is(err, http.StatusConflict, client.ReasonForeignRRset):
		resp.Diagnostics.AddError("URL forward not adopted", fmt.Sprintf("The forward of %s in %s exists but is not owned by the gate (foreign). %s", name, zone, importForwardHelp(zone, name)))
		return
	case err != nil:
		addForwardError(&resp.Diagnostics, "Cannot read the URL forward "+req.ID, zone, err)
		return
	case got.Status == client.StatusForeign:
		resp.Diagnostics.AddError("URL forward not adopted", fmt.Sprintf("The forward of %s in %s exists but is not owned by the gate (foreign). %s", name, zone, importForwardHelp(zone, name)))
		return
	case got.Status == client.StatusMissing || got.Forward == nil:
		resp.Diagnostics.AddError("URL forward not found", fmt.Sprintf("The forward of %s is owned in the gate but missing from zone %s.", name, zone))
		return
	case got.ReadOnly != "":
		resp.Diagnostics.AddError("URL forward cannot be managed", fmt.Sprintf("The forward of %s in %s is read-only in the gate (%s).", name, zone, got.ReadOnly))
		return
	}
	if me, merr := r.pd.client.Me(ctx); merr == nil && got.Owner != "" && len(me.Teams) > 0 && !contains(me.Teams, got.Owner) {
		resp.Diagnostics.AddError("URL forward owned by another team",
			fmt.Sprintf("The forward of %s in %s is owned by team %q in the gate; this identity acts for %s. Only the owner team can manage it: "+
				"import it from that team's configuration, or have it transferred in the gate.", name, zone, got.Owner, strings.Join(me.Teams, ", ")))
		return
	} else if merr != nil {
		tflog.Debug(ctx, "cannot read /api/v1/me, ownership not checked at import", map[string]any{"error": merr.Error()})
	}
	forwardStatusWarning(&resp.Diagnostics, zone, name, got.Status)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), urlForwardID(zone, name))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("zone"), zone)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("require_https"), false)...)
}

func parseURLForwardID(id string) (zone, name string, ok bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	zone = client.NormalizeZone(parts[0])
	name = importName(zone, parts[1])
	if !zoneRe.MatchString(zone) || validName(name) != "" {
		return "", "", false
	}
	return zone, name, true
}
