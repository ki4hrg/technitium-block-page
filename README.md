# technitium-block-page

A block page and override service for [Technitium DNS Server](https://technitium.com/dns/).
It gives you different rules per VLAN, temporary or permanent exceptions, pauses, and
Pocket ID–backed approval. A parent can approve from their own phone.

```
 kid's tablet ──DNS──▶ Technitium (Advanced Blocking app)
      │                    │  youtube.com → 10.0.0.250 (blockingAddresses)
      └──HTTP──▶ block page :80 on 10.0.0.250 ──── code + QR ────┐
                                                                 ▼
 parent's phone ──HTTPS──▶ admin UI (blocks.example.com) ◀── Pocket ID login
                              │ allow 1h / today / forever, pause VLAN
                              ▼
                    reconciler ──▶ Technitium API (apps/config/set)
```

- **Block listener (:80 on a dedicated LAN IP).** It reads the blocked domain from the `Host`
  header and finds the VLAN from the source IP.
  - Trusted VLANs can unblock straight from the page.
  - Kid VLANs show a short code and a QR code, with an optional "Ask to unblock" button.
  - The page polls and moves on to the site once it's allowed.
- **Admin UI (:3000 behind your reverse proxy).** Sign in with Pocket ID. From here you can:
  - enter a code and see the other domains that device was blocked on at the same moment
    (sites often need CDN hosts too);
  - review pending requests and recent blocks from the query log;
  - pause or resume blocking per VLAN or everywhere, and remove exceptions.
- **Reconciler.** The service's SQLite database holds every exception and pause. The reconciler
  writes them into the Advanced Blocking app config and removes them when they expire.
  - It only removes `allowed[]` entries it added, so anything you add by hand in Technitium stays.
  - When a pause ends it puts `enableBlocking` back to whatever it was before.
- **`/api/v1` + webhooks + SSE.** The same operations are available to integrations such as
  Home Assistant (see below).

## Why Advanced Blocking (not the built-in lists)

Technitium's built-in blocking applies to the whole network. Per-network rules only exist in
the **Advanced Blocking** app (`networkGroupMap` maps CIDRs to groups, and each group has its
own lists, allow list and `blockingAddresses`).

Technitium's own "temporarily disable blocking" doesn't affect app-based blocking, so this
service does pausing itself. A global pause also pauses built-in blocking, controlled by
`technitium.pauseBuiltInBlocking`.

Checked against Technitium's source:
- An `allowed` entry also covers all its subdomains.
- Rewriting the app config keeps the block lists it has already downloaded instead of
  downloading them again.

## Setup

### 1. Technitium

1. **Install the apps.** Under Apps → App Store, install **Advanced Blocking** and
   **Query Logs (Sqlite)**.
2. **Create the API user.** Make a dedicated user (e.g. `block-page`) with these permissions:
   - Settings: View + Modify (only needed for the global pause of built-in blocking)
   - Apps: View + Modify
   - Logs: View

   Then create an API token as that user: Administration → Sessions → Create Token, or
   `/api/user/createToken`.
3. **Migrate from the built-in lists.** Generate a starting Advanced Blocking config from your
   current built-in settings and your VLANs:

   ```sh
   cp config/policy.example.yaml config/policy.yaml   # edit VLANs, IPs, URLs first
   TECHNITIUM_TOKEN=… npm run migrate:print > advanced-blocking.json
   ```

   Review it, give the kids group stricter lists, and paste it into Advanced Blocking → Config.
   Then clear the built-in block list URLs under Settings → Blocking.
4. **Set a low `blockingAnswerTtl`** in the app config (10 seconds is good). Unblocking can't
   take effect before devices' cached "blocked" answers expire.

### 2. Pocket ID

1. Create an OIDC client named `technitium-blocks`.
   - Callback URL: `https://blocks.example.com/auth/callback`
   - Confidential client, PKCE on.
   - Allowed user groups: e.g. `parents`, `grandparents`, `admins`.
2. The service asks for the `openid profile email groups` scopes. Rules in `policy.yaml` match
   on `preferred_username` (`users:`) and on group names (`groups:`).

### 3. Networking

The block page needs its **own IP address on the LAN**, and it must see each device's
**real source IP**. That means routed traffic with no NAT and no reverse proxy in front of
port 80.

`compose.yaml` sets this up:
- A macvlan network gives the container that IP.
- A second bridge network (`proxy`) lets your existing reverse proxy reach the admin UI on
  :3000. A Docker host can't reach its own macvlan containers, which is why the second network
  is needed.

Firewall rules:
- **Every VLAN** must reach `BLOCK_PAGE_IP:80`.
- **VLANs where someone signs in on the same device** must also reach the admin hostname and
  Pocket ID.
- Kid VLANs don't need those two if approvals always happen on a parent's phone.

**HTTPS sites:** browsers expect a certificate for the real site, so a blocked `https://` page
shows a certificate error instead of the block page. Workarounds:
- Bookmark `http://blocked.home.arpa` (any name in `blockPage.hostnames` that resolves to the
  block IP). It lists what was recently blocked on that device, and opening an entry gets an
  unblock code.
- Parents can also act on anything from the dashboard's "Recently blocked" list.

### 4. Deploy

GitHub Actions runs typecheck and tests, then builds a multi-arch image and pushes it to
`ghcr.io/ki4hrg/technitium-block-page:{main,sha-…}`. Finally it calls the Dockhand webhook
(`DOCKHAND_WEBHOOK_URL`, plus `DOCKHAND_WEBHOOK_TOKEN` if needed). Compose uses
`pull_policy: always`, so a redeploy really pulls the new image.

Steps:
1. Set the variables from `.env.example` in Dockhand.
2. Mount your `policy.yaml`.
3. Make the GHCR package public, or give Dockhand registry credentials.

To check a deploy:

```sh
docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' <container>
```

## Policy

See [`config/policy.example.yaml`](config/policy.example.yaml). Each VLAN maps to an Advanced
Blocking group and offers these actions:

| action           | what it does                                                     |
| ---------------- | ---------------------------------------------------------------- |
| `allowTemporary` | allow a domain (and its subdomains) for one of `durations`       |
| `allowPermanent` | allow a domain until someone removes it                          |
| `pause`          | turn blocking off for the whole VLAN for one of `durations`      |
| `requestUnblock` | show "Ask to unblock" on the block page (creates a request + event) |

Who can do each action is set by `require`:
- `none`: anyone on that VLAN, right from the block page.
- `{ users: [...], groups: [...] }`: Pocket ID users or groups.

`admins` can do everything and can see the activity log. The `global` section lists actions
that apply to every VLAN.

## API (`/api/v1`)

The API accepts either a signed-in session cookie or an integration token sent as two headers:
`Authorization: Bearer <token>` and `X-Actor: <user>`. The actor must be listed under
`integrations.<id>.users`, and it gets only the groups mapped there. It is never matched by
user name, so a Home Assistant user called `john` is not the Pocket ID user `john`.

| method & path                       | purpose                                               |
| ----------------------------------- | ----------------------------------------------------- |
| `GET /api/v1/me`                    | who am I                                              |
| `GET /api/v1/status`                | per-VLAN pause state, available actions, pending count, sync status |
| `GET /api/v1/overrides`             | active exceptions and pauses                          |
| `POST /api/v1/overrides`            | `{scope: "global"\|<vlanId>, kind: "allow"\|"pause", domains?, duration}` |
| `DELETE /api/v1/overrides/:id`      | revoke                                                |
| `GET /api/v1/requests?status=`      | unblock requests (default `pending`)                  |
| `POST /api/v1/requests/:id/approve` | `{action?: "allow"\|"pause", duration, extraDomains?}` |
| `POST /api/v1/requests/:id/deny`    |                                                       |
| `GET /api/v1/codes/:code`           | look up a block code                                  |
| `GET /api/v1/blocked?minutes=&vlan=` | recent blocked queries from the query log, grouped    |
| `GET /api/v1/stream`                | server-sent events (same payloads as webhooks)        |

Webhook and SSE events: `block.created`, `request.created`, `request.approved`,
`request.denied`, `override.created`, `override.revoked`. Each is sent as `{type, ts, data}`.

### Home Assistant: no custom code needed yet

```yaml
# configuration.yaml
rest_command:
  blocks_approve:
    url: "https://blocks.example.com/api/v1/requests/{{ request_id }}/approve"
    method: POST
    headers:
      authorization: !secret blocks_api_bearer   # "Bearer <HA_API_TOKEN>"
      x-actor: "{{ actor }}"
    content_type: application/json
    payload: '{"duration": "{{ duration }}"}'

automation:
  - alias: Unblock request → notify parents
    trigger:
      - platform: webhook
        webhook_id: technitium-blocks-XXXX
        local_only: true
    condition: "{{ trigger.json.type == 'request.created' }}"
    action:
      - service: notify.parents_and_grandparents
        data:
          title: "Unblock {{ trigger.json.data.domain }}?"
          message: "{{ trigger.json.data.clientName or trigger.json.data.clientIp }}: {{ trigger.json.data.note or '' }}"
          data:
            url: "https://blocks.example.com/r/{{ trigger.json.data.code }}"
            actions:
              - action: "BLOCKS_ALLOW_1H_{{ trigger.json.data.id }}"
                title: Allow 1 hour
              - action: URI
                title: Open
                uri: "https://blocks.example.com/r/{{ trigger.json.data.code }}"
```

To act on the button, add an automation that handles `mobile_app_notification_action`. It
should call `rest_command.blocks_approve` with `actor` set to the HA user who tapped it, which
you map under `integrations.homeassistant.users`.

A custom HA integration with pause switches, a pending-requests sensor and approve/deny
services for a grandparents dashboard is planned on top of this same API.

## Development

```sh
npm install
npm test            # vitest: reconciler merge logic, policy, block page + admin + API flows
npm run typecheck
docker compose -f compose.dev.yaml up -d   # throwaway Technitium on :15380
cp config/policy.example.yaml config/policy.yaml
TECHNITIUM_TOKEN=… OIDC_CLIENT_SECRET=… SESSION_SECRET=$(openssl rand -base64 48) npm run dev
```

The block listener uses port 80 by default. Set `blockPage.port: 8080` locally and test with
`curl -H 'Host: youtube.com' -H 'Accept: text/html' http://localhost:8080/`.
