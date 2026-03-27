import pandas as pd
from datetime import timedelta

# ─────────────────────────────────────────────
# CONFIG — tweak thresholds here
# ─────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5       # failed attempts from same IP within window
BRUTE_FORCE_WINDOW_MIN = 2      # minutes
OFF_HOURS_START = 22            # 10 PM
OFF_HOURS_END = 6               # 6 AM
NHI_AGENT_KEYWORDS = ["curl", "python-requests", "boto", "okta-sdk"]

# ─────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────
df = pd.read_csv("auth_log.csv", parse_dates=["timestamp"])
df = df.sort_values("timestamp").reset_index(drop=True)

print("=" * 60)
print("  PEERLINK AUTH LOG ANALYSER — SECURITY REPORT")
print("=" * 60)
print(f"\nTotal events loaded : {len(df)}")
print(f"Time range          : {df['timestamp'].min()} → {df['timestamp'].max()}")
print(f"Unique users        : {df['user'].nunique()}")
print(f"Unique IPs          : {df['ip_address'].nunique()}")

# ─────────────────────────────────────────────
# SUMMARY TABLE
# ─────────────────────────────────────────────
print("\n── Login Summary by Status ─────────────────────────────")
print(df["status"].value_counts().to_string())

# ─────────────────────────────────────────────
# FLAG 1: BRUTE FORCE — many failures from same IP in short window
# ─────────────────────────────────────────────
print("\n── FLAG 1: Brute Force Attempts ────────────────────────")
fails = df[df["status"] == "FAIL"].copy()
flagged_ips = []

for ip, group in fails.groupby("ip_address"):
    group = group.sort_values("timestamp")
    for i in range(len(group)):
        window = group[(group["timestamp"] >= group.iloc[i]["timestamp"]) &
                       (group["timestamp"] <= group.iloc[i]["timestamp"] + timedelta(minutes=BRUTE_FORCE_WINDOW_MIN))]
        if len(window) >= BRUTE_FORCE_THRESHOLD:
            flagged_ips.append({
                "ip": ip,
                "failures_in_window": len(window),
                "first_attempt": window["timestamp"].min(),
                "users_targeted": ", ".join(window["user"].unique()),
                "country": group["country"].iloc[0]
            })
            break

if flagged_ips:
    for f in flagged_ips:
        print(f"  ⚠  IP: {f['ip']} ({f['country']})")
        print(f"     {f['failures_in_window']} failures within {BRUTE_FORCE_WINDOW_MIN} min starting {f['first_attempt']}")
        print(f"     Targeted user(s): {f['users_targeted']}")
else:
    print("  ✓  No brute force patterns detected.")

# ─────────────────────────────────────────────
# FLAG 2: SUCCESSFUL LOGIN AFTER MANY FAILURES (same user/IP)
# ─────────────────────────────────────────────
print("\n── FLAG 2: Success After Repeated Failures ─────────────")
combo_flags = []
for (user, ip), group in df.groupby(["user", "ip_address"]):
    group = group.sort_values("timestamp")
    fail_count = 0
    for _, row in group.iterrows():
        if row["status"] == "FAIL":
            fail_count += 1
        elif row["status"] == "SUCCESS" and fail_count >= BRUTE_FORCE_THRESHOLD:
            combo_flags.append({
                "user": user, "ip": ip,
                "failures_before_success": fail_count,
                "success_time": row["timestamp"],
                "country": row["country"]
            })
            fail_count = 0

if combo_flags:
    for f in combo_flags:
        print(f"  ⚠  User: {f['user']} | IP: {f['ip']} ({f['country']})")
        print(f"     {f['failures_before_success']} failures → SUCCESS at {f['success_time']}")
        print(f"     Possible credential stuffing or successful brute force.")
else:
    print("  ✓  No suspicious success-after-failure patterns.")

# ─────────────────────────────────────────────
# FLAG 3: IMPOSSIBLE TRAVEL — same user, 2 countries within 10 min
# ─────────────────────────────────────────────
print("\n── FLAG 3: Impossible Travel ────────────────────────────")
travel_flags = []
for user, group in df[df["status"] == "SUCCESS"].groupby("user"):
    group = group.sort_values("timestamp")
    for i in range(len(group) - 1):
        a = group.iloc[i]
        b = group.iloc[i + 1]
        time_diff = (b["timestamp"] - a["timestamp"]).total_seconds() / 60
        if a["country"] != b["country"] and time_diff <= 10:
            travel_flags.append({
                "user": user,
                "country_a": a["country"], "time_a": a["timestamp"], "ip_a": a["ip_address"],
                "country_b": b["country"], "time_b": b["timestamp"], "ip_b": b["ip_address"],
                "minutes_apart": round(time_diff, 1)
            })

if travel_flags:
    for f in travel_flags:
        print(f"  ⚠  User: {f['user']}")
        print(f"     Login from {f['country_a']} ({f['ip_a']}) at {f['time_a']}")
        print(f"     Login from {f['country_b']} ({f['ip_b']}) at {f['time_b']}")
        print(f"     Only {f['minutes_apart']} min apart — physically impossible.")
else:
    print("  ✓  No impossible travel detected.")

# ─────────────────────────────────────────────
# FLAG 4: OFF-HOURS LOGINS
# ─────────────────────────────────────────────
print("\n── FLAG 4: Off-Hours Logins ─────────────────────────────")
df["hour"] = df["timestamp"].dt.hour
off_hours = df[
    (df["status"] == "SUCCESS") &
    ((df["hour"] >= OFF_HOURS_START) | (df["hour"] < OFF_HOURS_END))
]
if not off_hours.empty:
    for _, row in off_hours.iterrows():
        print(f"  ⚠  {row['user']} logged in at {row['timestamp']} from {row['ip_address']} ({row['country']})")
else:
    print("  ✓  No off-hours logins detected.")

# ─────────────────────────────────────────────
# FLAG 5: NON-HUMAN IDENTITY (NHI) — automated agents
# ─────────────────────────────────────────────
print("\n── FLAG 5: Non-Human Identity (Automated Agents) ───────")
nhi_pattern = "|".join(NHI_AGENT_KEYWORDS)
nhi_events = df[df["user_agent"].str.contains(nhi_pattern, case=False, na=False)]
if not nhi_events.empty:
    for user, group in nhi_events.groupby("user"):
        print(f"  ℹ  Service account: {user}")
        print(f"     {len(group)} automated requests | Agent: {group['user_agent'].iloc[0]}")
        print(f"     IPs used: {', '.join(group['ip_address'].unique())}")
        print(f"     All statuses: {dict(group['status'].value_counts())}")
else:
    print("  ✓  No automated agent activity detected.")

# ─────────────────────────────────────────────
# FINAL RISK SUMMARY
# ─────────────────────────────────────────────
total_flags = len(flagged_ips) + len(combo_flags) + len(travel_flags) + len(off_hours) + len(nhi_events.groupby("user"))
print("\n" + "=" * 60)
print(f"  TOTAL FLAGS RAISED: {total_flags}")
print("=" * 60)
print("\nRecommended actions:")
if flagged_ips:
    print("  → Block/rate-limit IPs with brute force activity")
if combo_flags:
    print("  → Investigate accounts with success-after-failure — force password reset")
if travel_flags:
    print("  → Flag impossible travel accounts for MFA re-challenge")
if not off_hours.empty:
    print("  → Review off-hours logins with IT/security team")
if not nhi_events.empty:
    print("  → Audit service account permissions and rotate credentials")
print()
