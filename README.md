# Domain Rules for Clash, Shadowrocket & Xray

Weekly updated domain rule sets generated from [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community).

Currently includes:

| File                 | Description                                             | Default Policy |
|----------------------|---------------------------------------------------------|----------------|
| `clash-iran.yaml`    | Iran-related domains (`category-ir`)                    | `DIRECT`       |
| `clash-apple.yaml`   | Apple-related domains (`apple`)                         | `DIRECT`       |
| `clash-ads.yaml`     | All advertising & tracking domains (`category-ads-all`) | `REJECT`       |
| `shadowrocket.conf`  | Ready-to-use Shadowrocket configuration                 | —              |
| `xray-routing.json`  | Full Xray `routing` section (for Xray configs)          | —              |
| `xray-rulesets.json` | Importable rule list for Xray-based clients (v2rayNG, etc.) | —          |

---

## 📦 Download (always latest)

```text
https://github.com/mostafaznv/domain-rules/releases/latest/download/clash-iran.yaml
https://github.com/mostafaznv/domain-rules/releases/latest/download/clash-ads.yaml
https://github.com/mostafaznv/domain-rules/releases/latest/download/clash-apple.yaml
https://github.com/mostafaznv/domain-rules/releases/latest/download/shadowrocket.conf
https://github.com/mostafaznv/domain-rules/releases/latest/download/xray-routing.json
https://github.com/mostafaznv/domain-rules/releases/latest/download/xray-rulesets.json
```


## 🛠 Clash / Clash Meta / ClashX / Clash Verge

Add the following to your config:
```
rule-providers:
  iran:
    type: http
    behavior: domain
    url: "https://github.com/mostafaznv/domain-rules/releases/latest/download/clash-iran.yaml"
    path: ./ruleset/iran.yaml
    interval: 86400  # Update once every 24 hours
    
  ads:
    type: http
    behavior: domain
    url: "https://github.com/mostafaznv/domain-rules/releases/latest/download/clash-ads.yaml"
    path: ./ruleset/ads.yaml
    interval: 86400 

  apple:
    type: http
    behavior: domain
    url: "https://github.com/mostafaznv/domain-rules/releases/latest/download/clash-apple.yaml"
    path: ./ruleset/apple.yaml
    interval: 86400 

rules:
  # ... your other rules

  - RULE-SET,ads,REJECT
  - RULE-SET,iran,DIRECT
  - RULE-SET,apple,DIRECT
  
  # ... your other rules
  
  - MATCH,PROXY          # or DIRECT, depending on your preference
```


## 🚀 Shadowrocket

1. Copy this link:
```
https://github.com/mostafaznv/domain-rules/releases/latest/download/shadowrocket.conf
```

2. Open **Shadowrocket → Config** → tap the `+` button
3. Choose **Download from URL** and paste the link
4. After download, tap the config and select **Use Config**

The generated `.conf` already contains:
- Sensible [General] settings (skip-proxy, tun-excluded-routes, DNS, etc.)
- `iran` → `DIRECT`
- `ads` → `REJECT`
- `apple` → `DIRECT`
- Final fallback rule (`FINAL,PROXY`)


## ⚡ Xray (v2rayNG, Hiddify, Streisand and other Xray-based clients)

> **Important:** your Xray outbounds must use these tags: `proxy`, `direct` and `block`.

### Option 1: Import the rule list (recommended for apps)

1. Copy this link:
```
https://github.com/mostafaznv/domain-rules/releases/latest/download/xray-rulesets.json
```

2. In your client, open the **Routing** settings and import the rule list from a URL
   (or download the file and import it from the clipboard / local file). Menu names can be different in each client and version.
3. Enable the imported rules and select that routing set.

### Option 2: Use the full routing section in your own Xray config

Copy the `routing` object from this file into your Xray config:

```
https://github.com/mostafaznv/domain-rules/releases/latest/download/xray-routing.json
```

The rules are checked in this order (Xray uses the first match):

| Order | Match                          | Outbound |
|-------|--------------------------------|----------|
| 1     | Private IP ranges              | `direct` |
| 2     | Ads & tracking domains         | `block`  |
| 3     | Iran + Apple domains           | `direct` |
| 4     | Everything else (`tcp,udp`)    | `proxy`  |

It also contains the same extra manual rules as the Shadowrocket config (Iranian ad networks, Apple services, etc.).
`domainStrategy` is `IPIfNonMatch`. Change it to `AsIs` if you want to avoid the extra local DNS lookup for unmatched domains.



## 📄 License
The generated rule files inherit the license of [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community).

This repository’s scripts are released under the MIT License.