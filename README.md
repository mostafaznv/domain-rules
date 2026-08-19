# Domain Rules for Clash & Shadowrocket

Weekly updated domain rule sets generated from [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community).

Currently includes:

| File                | Description                                             | Default Policy |
|---------------------|---------------------------------------------------------|----------------|
| `clash-iran.yaml`   | Iran-related domains (`category-ir`)                    | `REJECT`       |
| `clash-ads.yaml`    | All advertising & tracking domains (`category-ads-all`) | `REJECT`       |
| `clash-apple.yaml`  | Apple-related domains (`apple`)                         | `DIRECT`       |
| `shadowrocket.conf` | Ready-to-use Shadowrocket configuration                 | —              |

---

## 📦 Download (always latest)

```text
https://github.com/mostafaznv/domain-rules/releases/latest/download/clash-iran.yaml
https://github.com/mostafaznv/domain-rules/releases/latest/download/clash-ads.yaml
https://github.com/mostafaznv/domain-rules/releases/latest/download/clash-apple.yaml
https://github.com/mostafaznv/domain-rules/releases/latest/download/shadowrocket.conf
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
  - RULE-SET,iran,DIRECT
  - RULE-SET,ads,REJECT
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



## 📄 License
The generated rule files inherit the license of [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community).

This repository’s scripts are released under the MIT License.