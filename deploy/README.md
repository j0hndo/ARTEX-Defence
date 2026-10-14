# Integrate the canary into an existing application

[한국어 가이드](README.ko.md)

This guide connects the canary sidecar to a live application's existing support content and Nginx virtual host. It does not replace the application with the repository's demo site. The canary creates synthetic data only. Its verification event is an exploration signal for alerting and investigation. This release does not support automatic session restriction.

## Files to use

| File | Purpose |
| --- | --- |
| [`compose.production.yaml`](compose.production.yaml) | Runs only the canary sidecar on `127.0.0.1:19091` |
| [`production.env.example`](production.env.example) | Template for local production settings |
| [`nginx/canary-rate-limit-http.conf`](nginx/canary-rate-limit-http.conf) | Canary request and connection limits to include once in Nginx `http` |
| [`nginx/canary-location.conf`](nginx/canary-location.conf) | Route to insert inside the application's existing Nginx `server` block |
| [`content/support-link.html`](content/support-link.html) | Link fragment for an HTML support article |
| [`content/support-link.md`](content/support-link.md) | Link fragment for a Markdown or CMS support article |
| [`check_integration.py`](check_integration.py) | Safe path check, with an explicit full-chain option |

The sidecar generates `status.<digest>.js` and `review.<digest>.js` for each run. There is no fixed JS bundle to build, copy into static assets, or insert into the application build. The support link opens the per-run `overview`, and the sidecar generates both JS responses. The support link and same-origin route are the integration points. A static-only bundle was not tested in the reported 30 ARTEX trials.

## 1. Check the target application

Choose a support page that an unauthenticated visitor or the intended public-page reviewer can reach. Confirm that `/sys/sso-status/` is unused on the chosen host and does not belong to the actual login or SSO system. The canary server has this prefix built in. If the application already owns it, change the server, proxy route, content link, and integration checks together, then retest before deployment.

Use the actual application's HTTPS hostname, for example `app.example.com`. Keep the same `Host` value through Nginx and the sidecar for all stages. The sidecar allowlist checks the hostname and binds a run to the explicit `Host` port, if present. That check does not establish user identity. TLS termination and the intended virtual host must be enforced at the edge or application proxy.

Ensure the public support page is under the same origin as the canary route. A link to another host loses the tested same-origin layout. If the application or its edge applies a Content Security Policy to the canary route, confirm that the route can load its generated same-origin JS. Review the route policy before changing any application-wide CSP. Plan a dedicated log retention period and rate limits for the new path. Check edge, CDN, WAF, analytics, and tracing configuration for query-string capture because the canary's one-time gates and signature appear in request URLs.

The sidecar renders an `Aster` support header, service notices, and `SUP-6148` as reference presentation in `canary/server.py`. These are not facts about your service. Before a live rollout, adapt the visible copy, incident label, and JS presentation to fit the actual support area without implying a real account or SSO incident. Changes to these cues can change agent behavior, so repeat the browser control and agent reflection tests on the integrated app. The reported 30-trial rate does not transfer automatically to customized content.

## 2. Start the sidecar

From an authorized checkout of the private repository:

```sh
gh repo clone j0hndo/artex-canary-defense
cd artex-canary-defense
cp deploy/production.env.example deploy/production.env
```

Edit `deploy/production.env` before starting. Set `CANARY_ALLOWED_HOSTS` to the actual public hostname or a comma-separated list of owned hosts. Keep `CANARY_POLICY=observe` for the initial deployment. Review `CANARY_TTL_SECONDS` and `CANARY_MAX_ACTIVE_RUNS` against expected traffic. Leave `CANARY_TRUSTED_PROXY_CIDRS` empty until you know the sidecar's direct proxy peer addresses and have verified that the proxy overwrites `X-Canary-Request-ID`. Do not add a broad container, private-network, or client-address range just to make request IDs appear.

The host loopback port can also be reached by other local processes. Docker port forwarding may present those callers and Nginx as the same peer inside the sidecar. Do not use a CIDR match alone as proof that a request ID came from Nginx. Keep trusted proxy CIDRs empty unless network or host access controls make the gateway the only caller and that boundary has been tested. Even then, treat a request ID as investigative correlation data, never as sufficient grounds for automatic session action.

```sh
docker compose --env-file deploy/production.env -f deploy/compose.production.yaml up -d --build --wait --wait-timeout 60
docker compose --env-file deploy/production.env -f deploy/compose.production.yaml ps
curl -fsS http://127.0.0.1:19091/healthz
```

The Compose file publishes the sidecar only on host loopback. Keep that listener inaccessible from external clients. The `canary-production-logs` volume stores sanitized `canary_match` events in `/var/log/canary/events.jsonl`. It does not contain a history of partial stages. Run state is in memory, so use one sidecar replica or sticky routing for every request belonging to a run. A restart invalidates active runs.

Each `overview` visit creates an in-memory run even if the visitor stops there. With the example's 1,024 active-run cap and 300-second lifetime, roughly 3.4 incomplete overview visits per second can fill the cap and make new overviews return HTTP 503. The Nginx limits below allow a sustained 2 overview requests per second with a burst of 10 per Nginx instance. That is roughly 610 outstanding runs over 300 seconds if none complete. A separate all-route limit bounds invalid path traffic and worker load. For multiple Nginx instances, traffic is not shared across their local limits. Size the cap and lifetime for total expected traffic, monitor 429 and 503 counts without retaining query strings, and load-test the integrated service before raising the limits.

## 3. Add the route to the existing Nginx host

Include [`nginx/canary-rate-limit-http.conf`](nginx/canary-rate-limit-http.conf) once in the outer Nginx `http { ... }` block. Then copy the contents of [`nginx/canary-location.conf`](nginx/canary-location.conf) inside the existing HTTPS `server { ... }` block for `app.example.com`. Both files are required together because `limit_req_zone` is defined only in the `http` context. Keep the application's other routes, TLS configuration, authentication rules, and upstream unchanged. The location proxies only `/sys/sso-status/` to `127.0.0.1:19091`. If the application has a broader `/sys/` or catch-all location, verify that the canary location takes precedence.

The snippet disables access logging and routine upstream error logging for this route, forwards the original `Host`, generates `X-Canary-Request-ID`, and drops client credentials before proxying. Do not replace its `Host` with `127.0.0.1` or the sidecar service name. Check query redaction at every earlier edge layer too. The snippet's own log setting cannot suppress CDN or WAF logs.

The lower rate limit applies only to exact `/sys/sso-status/overview` requests. Every `/sys/sso-status/` request, including invalid paths, also has a 10 requests per second limit with a burst of 20, a 32 concurrent-connection limit, and a 1 KiB request-body cap. Unrelated app routes are exempt. Excess requests receive HTTP 429 before reaching the sidecar, and oversized bodies receive HTTP 413. These are capacity rejections, not `canary_match` signals. The overview limit protects run-state capacity; the all-route limits bound requests that would otherwise create threads without creating runs. These reference thresholds require staging load tests and do not make the Python server a high-traffic service. Coordinate a shared edge limit if several Nginx instances feed one sidecar. Local processes that call port 19091 directly bypass Nginx limits; on a host with untrusted workloads, use an unpublished sidecar on a private network or enforce host-level access control.

Validate and reload Nginx using your service's normal deployment process. For a host-managed Nginx installation, the commands may be:

```sh
sudo nginx -t
sudo nginx -s reload
```

If Nginx itself runs in a container, attach the sidecar to a private shared network, change `proxy_pass` to the sidecar service DNS name, and remove the host loopback port mapping. The supplied production files assume Nginx runs on the Docker host. For another ingress, implement the same route properties: exact prefix, preserved public `Host`, no forwarded client cookies or authorization, no caching, gateway-generated request ID, and no query-string logging. Bind the upstream to a private address. Keep HTTPS enforced at the public edge.

## 4. Add the support entry point

Insert [`content/support-link.html`](content/support-link.html) into an existing HTML support page, or adapt [`content/support-link.md`](content/support-link.md) in a Markdown or CMS article. The link target is `/sys/sso-status/overview` on the same origin as the page. Keep it visible in ordinary support navigation. The earlier experiment used public support content; a hidden link or an isolated static JS file does not have measured effectiveness here.

The `overview` page supplies its own generated JS reference. Do not add a `<script>` tag for the canary to your app shell or make normal browser page views auto-call `verifySSOStatus`.

## 5. Check the integration

Run the safe check against the public HTTPS host and the support path you edited:

```sh
python3 deploy/check_integration.py --base-url https://app.example.com --support-path /support
```

The default check follows the support link, `overview`, and the generated discovery JS, then stops. It does not request the synthetic ticket or the verification endpoint and should not emit `canary_match`. It fails if the link is missing, a hop leaves the origin, a response is malformed, or a required route is unavailable. Use the actual support path and review nonzero exit status before proceeding.

In an authorized staging environment, intentionally exercise the full chain:

```sh
python3 deploy/check_integration.py --base-url https://staging.example.com --support-path /support --full-chain
```

`--full-chain` obtains the synthetic ticket, reads the incident and review assets, computes the SHA-256 signature, and sends a one-time verification request. A valid request yields HTTP 200 in `observe` mode or HTTP 403 in `deny_verify` mode. It must emit exactly one `canary_match` event. The checker keeps gates, tickets, signatures, and query URLs out of its output. Use `observe` while establishing a baseline, and exclude designated checks from automated response rules.

Inspect the sidecar's event file after the deliberate full-chain check:

```sh
docker compose --env-file deploy/production.env -f deploy/compose.production.yaml exec canary \
  cat /var/log/canary/events.jsonl
```

## 6. Alert on the match and restrict only the decoy request

A validated signal is a request shaped like `GET /sys/sso-status/verifySSOStatus?run=RUN&gate=GATE&signature=SHA256_HEX` that the sidecar accepts **after** the ordered `overview → discovery JS → synthetic ticket → incident → review JS` stages, within the run lifetime, on the same allowed host. `SHA256_HEX` is the lowercase 64-character SHA-256 of that run's exact synthetic ticket bytes with no newline. The run and gate are one-time values. A raw hit on the path or a syntactically valid 64-character hash alone is not a match.

The sidecar records `canary_match` only for the accepted final request. `CANARY_POLICY=observe` records it and returns 200. `CANARY_POLICY=deny_verify` records it and returns 403 **on that decoy request**. Neither setting automatically blocks the agent's other application requests. The [response policy example](../examples/policy/response-policy.yaml) is guidance for downstream handling; the server does not read that file or install WAF rules.

For an alert, ingest the sanitized event and retain the matched host, run ID, time, policy, status, and a trusted request ID when present. A gateway-generated `X-Canary-Request-ID` can join the event to the final request only after the gateway has been established as the sidecar's sole trusted caller. The edge record can contain that ID, path, time, and a trusted application session, without the canary query string. Exclude deliberate integration checks from the alert queue.

That join does not attribute the earlier five stages to the final requester. One person can complete those stages and cause a different person's browser to open the final URL. Even a unique join to an authenticated session can therefore identify an uninvolved final requester. This release uses `canary_match` for alerts and manual investigation only. Do not automatically challenge or block a session or IP from it. Broader enforcement requires a separately designed and tested proof of the same trusted actor across all six stages and controls for final-URL replay and cross-session handoff. A shared NAT or enterprise gateway may also represent unrelated users. A match is evidence of semantic response to this canary, not proof that the client is ARTEX, used Bash, or is malicious.

## Rollback and limits

Remove the support link, remove the Nginx canary location, validate and reload Nginx, then stop the sidecar:

```sh
docker compose --env-file deploy/production.env -f deploy/compose.production.yaml down
```

Retain or delete the named event volume according to your log retention policy. The documented 27/30 reflection result came from the earlier local dynamic CMS fixture, not this hardened deployment package. Validate the actual application and agents in its own environment before treating the event as an operational signal.
