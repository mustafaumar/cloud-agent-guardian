# Cloud Security Guardian: an AI Agent That Hardens Your Google Cloud Project
## Phase 01 - 
### Set up your Google Cloud account
## Phase 02 - Project Setup
### 2.1 - Create a project
```
# A unique project ID
export PROJECT_ID="devfest-sec-$RANDOM$RANDOM"
echo "$PROJECT_ID"
gcloud projects create "$PROJECT_ID" --name="DevFest security lab"

# Find your billing account ID (looks like 0X0X0X-0X0X0X-0X0X0X)
gcloud billing accounts list
```
### 2.2 Save your settings
```
cat > ~/lab-env.sh <<EOF
export PROJECT_ID="$PROJECT_ID"
export GOOGLE_CLOUD_PROJECT="$PROJECT_ID"
export REGION="us-central1"
export BUCKET="$PROJECT_ID-public-files"
EOF

source ~/lab-env.sh
gcloud config set project "$PROJECT_ID"
```
### 2.3 Turn on the APIs
```
gcloud services enable \
  aiplatform.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com
```
## Phase 03 - Plant the problems
### 3.1 - A public bucket with “customer data”
```
bash
gcloud storage buckets create "gs://$BUCKET" \
  --location="$REGION" --uniform-bucket-level-access

# Fake data only
printf 'customer_id,name,email\n1001,Ada Example,ada@example.com\n1002,Bola Example,bola@example.com\n' > customers.csv

# no-store stops caches from serving the file after you lock it down
gcloud storage cp customers.csv "gs://$BUCKET/customers.csv" --cache-control="no-store"

# The mistake: let anyone on the internet read objects
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member=allUsers --role=roles/storage.objectViewer
```
### 3.2 - Prove it is exposed
```
curl -s -o /dev/null -w "Anonymous read: %{http_code}\n" \
  "https://storage.googleapis.com/$BUCKET/customers.csv"

curl -s "https://storage.googleapis.com/$BUCKET/customers.csv"
```
Expected status code - `200` and the CSV contents

### 3.3 - Firewall rules open to the world
```
gcloud compute networks create lab-vpc --subnet-mode=custom

gcloud compute firewall-rules create allow-ssh-from-anywhere \
  --network=lab-vpc --direction=INGRESS --action=ALLOW \
  --rules=tcp:22 --source-ranges=0.0.0.0/0

gcloud compute firewall-rules create allow-rdp-from-anywhere \
  --network=lab-vpc --direction=INGRESS --action=ALLOW \
  --rules=tcp:3389 --source-ranges=0.0.0.0/0

# A safe rule, as a control: SSH from a private range only. The agent should NOT flag it.
gcloud compute firewall-rules create allow-ssh-internal-only \
  --network=lab-vpc --direction=INGRESS --action=ALLOW \
  --rules=tcp:22 --source-ranges=10.10.0.0/24
```
### 3.4 - An over-privileged service account
```
gcloud iam service-accounts create legacy-app --display-name="Legacy app (lab)"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:legacy-app@$PROJECT_ID.iam.gserviceaccount.com" \
  --role=roles/editor --condition=None
```
## Phase 04 - Build the agent
### 4.1 - Python environment
```
mkdir -p ~/devfest-agent && cd ~/devfest-agent
python3 --version            # needs 3.11 or newer

python3 -m venv .venv
source .venv/bin/activate

cat > requirements.txt <<'EOF'
google-adk==2.12.0
google-cloud-storage==3.17.1
google-cloud-compute==1.56.0
google-cloud-resource-manager==1.19.0
EOF

pip install -r requirements.txt
adk --version                # expect: adk, version 2.12.0
```
### 4.2 - Settings and package file
```
mkdir -p security_guardian

cat > security_guardian/.env <<EOF
GOOGLE_GENAI_USE_ENTERPRISE=1
GOOGLE_CLOUD_PROJECT=$PROJECT_ID
GOOGLE_CLOUD_LOCATION=global
EOF

echo "from . import agent" > security_guardian/__init__.py
cat security_guardian/.env
```
### 4.3 - The tools
These are ordinary Python functions. ADK reads each function’s name, docstring and parameters and shows them to Gemini as a tool description, so the docstrings are written for the model as much as for people. Paste the whole block.
```
cat > security_guardian/tools.py <<'EOF'
"""Tools the Cloud Security Guardian agent can call.

Scan tools only read configuration. Fix tools change it, and the agent
wraps them with require_confirmation=True so a human must approve each call.
Every tool works on one project only: the one in GOOGLE_CLOUD_PROJECT.
"""

import os

from google.cloud import compute_v1
from google.cloud import resourcemanager_v3
from google.cloud import storage

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
OPEN_RANGES = {"0.0.0.0/0", "::/0"}
RISKY_PORTS = {22: "SSH", 3389: "RDP"}
BASIC_ROLES = {"roles/owner", "roles/editor"}


def _project_id() -> str:
    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    if not project:
        raise RuntimeError("GOOGLE_CLOUD_PROJECT is not set in the agent's .env file.")
    return project


def _project_number(project_id: str) -> str:
    project = resourcemanager_v3.ProjectsClient().get_project(name=f"projects/{project_id}")
    return project.name.split("/", 1)[1]


def _port_is_open(ports: list[str], port: int) -> bool:
    """True if a firewall 'ports' list covers the port. An empty list means all ports."""
    if not ports:
        return True
    for entry in ports:
        if "-" in entry:
            low, high = entry.split("-", 1)
            if int(low) <= port <= int(high):
                return True
        elif int(entry) == port:
            return True
    return False


def _is_google_managed(member: str) -> bool:
    """Google-managed service agents need their roles. Never flag or touch them."""
    email = member.split(":", 1)[-1]
    return email.endswith("@cloudservices.gserviceaccount.com") or (
        email.startswith("service-") and email.endswith(".gserviceaccount.com")
    )


def scan_storage_buckets() -> dict:
    """Checks every Cloud Storage bucket in the lab project for public exposure.

    Looks for IAM grants to allUsers or allAuthenticatedUsers, whether public
    access prevention is enforced, and whether uniform bucket-level access is on.

    Returns:
        A dict with the project and a list of findings, one per problem found.
    """
    project = _project_id()
    client = storage.Client(project=project)
    findings = []
    buckets_checked = 0
    for bucket in client.list_buckets():
        buckets_checked += 1
        policy = bucket.get_iam_policy(requested_policy_version=3)
        public_grants = [
            {"role": binding["role"], "member": member}
            for binding in policy.bindings
            for member in binding["members"]
            if member in PUBLIC_MEMBERS
        ]
        pap = bucket.iam_configuration.public_access_prevention
        if public_grants:
            findings.append({
                "severity": "HIGH",
                "resource": f"gs://{bucket.name}",
                "issue": "Bucket is readable by anyone on the internet.",
                "evidence": public_grants,
                "public_access_prevention": pap,
                "fix_tool": "make_bucket_private",
            })
        elif pap != "enforced":
            findings.append({
                "severity": "LOW",
                "resource": f"gs://{bucket.name}",
                "issue": "Not public today, but public access prevention is not "
                         "enforced, so one bad IAM change could expose it.",
                "public_access_prevention": pap,
                "fix_tool": "make_bucket_private",
            })
        if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
            findings.append({
                "severity": "LOW",
                "resource": f"gs://{bucket.name}",
                "issue": "Uniform bucket-level access is off, so object ACLs "
                         "can still grant access outside IAM.",
                "suggested_command": f"gcloud storage buckets update gs://{bucket.name} "
                                     "--uniform-bucket-level-access",
            })
    return {"project": project, "buckets_checked": buckets_checked, "findings": findings}


def scan_firewall_rules() -> dict:
    """Checks VPC firewall rules for SSH (22) or RDP (3389) open to the whole internet.

    Returns:
        A dict with the project and a list of findings, one per risky rule.
    """
    project = _project_id()
    client = compute_v1.FirewallsClient()
    findings = []
    rules_checked = 0
    for rule in client.list(project=project):
        rules_checked += 1
        if rule.direction != "INGRESS" or rule.disabled:
            continue
        open_ranges = sorted(set(rule.source_ranges) & OPEN_RANGES)
        if not open_ranges:
            continue
        exposed = []
        for allowed in rule.allowed:
            if allowed.I_p_protocol not in ("tcp", "all"):
                continue
            for port, name in RISKY_PORTS.items():
                if _port_is_open(list(allowed.ports), port):
                    exposed.append(f"{name} ({port})")
        if exposed:
            findings.append({
                "severity": "HIGH",
                "resource": f"firewall rule {rule.name}",
                "network": rule.network.rsplit("/", 1)[-1],
                "issue": f"{', '.join(sorted(set(exposed)))} open to {', '.join(open_ranges)}.",
                "fix_tool": "disable_firewall_rule",
            })
    return {"project": project, "rules_checked": rules_checked, "findings": findings}


def scan_project_iam() -> dict:
    """Checks the project IAM policy for public members and for service accounts
    that hold the basic Owner or Editor role.

    This tool only reports. Changing project IAM is left to a human.

    Returns:
        A dict with the project and a list of findings with suggested commands.
    """
    project = _project_id()
    client = resourcemanager_v3.ProjectsClient()
    policy = client.get_iam_policy(request={"resource": f"projects/{project}"})
    findings = []
    for binding in policy.bindings:
        for member in binding.members:
            if member in PUBLIC_MEMBERS:
                findings.append({
                    "severity": "HIGH",
                    "resource": f"projects/{project}",
                    "issue": f"{member} holds {binding.role} on the whole project.",
                    "suggested_command": f"gcloud projects remove-iam-policy-binding {project} "
                                         f"--member={member} --role={binding.role} --condition=None",
                })
            elif (binding.role in BASIC_ROLES
                  and member.startswith("serviceAccount:")
                  and not _is_google_managed(member)):
                findings.append({
                    "severity": "MEDIUM",
                    "resource": f"projects/{project}",
                    "issue": f"Service account {member.split(':', 1)[1]} has the basic "
                             f"role {binding.role}, far more than a workload needs.",
                    "suggested_command": f"gcloud projects remove-iam-policy-binding {project} "
                                         f"--member={member} --role={binding.role} --condition=None",
                    "note": "Grant a narrow predefined role before removing this one, "
                            "or the workload using it will break.",
                })
    return {"project": project, "findings": findings}


def make_bucket_private(bucket_name: str) -> dict:
    """Removes public access from one bucket in the lab project.

    Enforces public access prevention first, then deletes every IAM grant to
    allUsers or allAuthenticatedUsers. Grants to real identities are kept.

    Args:
        bucket_name: The bucket name without the gs:// prefix.

    Returns:
        A dict describing what changed.
    """
    project = _project_id()
    bucket_name = bucket_name.removeprefix("gs://").strip("/")
    client = storage.Client(project=project)
    bucket = client.get_bucket(bucket_name)
    if str(bucket.project_number) != _project_number(project):
        return {"error": f"gs://{bucket_name} is not in project {project}. Refusing to change it."}

    bucket.iam_configuration.public_access_prevention = "enforced"
    bucket.patch()

    policy = bucket.get_iam_policy(requested_policy_version=3)
    removed = []
    kept_bindings = []
    for binding in policy.bindings:
        members = set(binding["members"])
        public = members & PUBLIC_MEMBERS
        removed += [{"role": binding["role"], "member": m} for m in sorted(public)]
        binding["members"] = members - public
        if binding["members"]:
            kept_bindings.append(binding)
    if removed:
        policy.bindings = kept_bindings
        bucket.set_iam_policy(policy)

    return {
        "bucket": f"gs://{bucket_name}",
        "public_access_prevention": "enforced",
        "removed_public_grants": removed,
        "undo_hint": f"gcloud storage buckets update gs://{bucket_name} --no-public-access-prevention",
    }


def disable_firewall_rule(rule_name: str) -> dict:
    """Disables (does not delete) one VPC firewall rule in the lab project.

    A disabled rule stops allowing traffic immediately but keeps its settings,
    so it can be turned back on with one command.

    Args:
        rule_name: The firewall rule name, for example allow-ssh-from-anywhere.

    Returns:
        A dict describing what changed.
    """
    project = _project_id()
    client = compute_v1.FirewallsClient()
    operation = client.patch(
        project=project,
        firewall=rule_name,
        firewall_resource=compute_v1.Firewall(disabled=True),
    )
    operation.result(timeout=120)
    return {
        "firewall_rule": rule_name,
        "disabled": True,
        "undo_hint": f"gcloud compute firewall-rules update {rule_name} --no-disabled",
    }
EOF
```
### 4.4 - The agent
```
cat > security_guardian/agent.py <<'EOF'
from google.adk.agents import Agent
from google.adk.tools import FunctionTool

from . import tools

INSTRUCTION = """
You are Cloud Security Guardian, a security assistant for ONE Google Cloud lab project.

How you work:
1. When asked to check the project, call scan_storage_buckets, scan_firewall_rules
   and scan_project_iam. Base every statement on what the tools return. Never guess.
2. Start the report by naming the project the tools scanned. Then list the
   findings ordered HIGH, MEDIUM, LOW. For each one say
   what is wrong in plain words, why an attacker would care, and the fix.
3. Only call make_bucket_private or disable_firewall_rule after the user asks you to
   fix something, and only for a resource that a scan reported. Fix one resource
   per call. The system will also ask the user to approve each call.
4. You cannot change project IAM. For IAM findings, show the suggested_command
   from the scan and explain that a human should run it after checking which
   workload uses the service account.
5. After a fix, run the matching scan again and show that the finding is gone.
6. If a tool returns an error, show the error and stop. Do not retry a rejected fix.

Keep answers short and friendly. The audience is new to cloud security.
"""

root_agent = Agent(
    name="security_guardian",
    model="gemini-3.8-flash",
    description="Finds and fixes common security misconfigurations in a lab project.",
    instruction=INSTRUCTION,
    tools=[
        tools.scan_storage_buckets,
        tools.scan_firewall_rules,
        tools.scan_project_iam,
        FunctionTool(tools.make_bucket_private, require_confirmation=True),
        FunctionTool(tools.disable_firewall_rule, require_confirmation=True),
    ],
)
EOF
```
## Phase 05 - Test the pieces before you chat
When an agent misbehaves, the cause is usually a missing permission or a wrong setting, not the model. Check both on their own first.

### 5.1 - Can you reach Gemini?
```
set -a; source security_guardian/.env; set +a

python - <<'EOF'
from google import genai
client = genai.Client()
reply = client.models.generate_content(model="gemini-3.8-flash", contents="Reply with one word: ready")
print(reply.text)
EOF
```
Expected outcome: a short reply such as `ready`
### 5.2 Do the tools work without the model?
```
python -c "
import json
from security_guardian import tools
print(json.dumps(tools.scan_storage_buckets(), indent=2))
print(json.dumps(tools.scan_firewall_rules(), indent=2))
"
```

## Phase 06 - Run the agent and scan
### 6.1 - Start the web UI
```
cd ~/devfest-agent
export GOOGLE_CLOUD_PROJECT="$PROJECT_ID"
adk web --port 8080 --allow_origins="https://8080-$WEB_HOST" .
```
### 6.2 - Ask for a scan
Type this into the message box:
`Check my project for security problems.`

## Phase 07 - Fix with human approval
### 7.1 - Approve the bucket fix
`Fix the public bucket.`
The agent calls make_bucket_private, and ADK stops it before the function runs. A confirmation card appears in the chat:

<img width="434" height="168" alt="download" src="https://github.com/user-attachments/assets/57868646-2b20-4fd7-bba7-2ed5d216ff43" />
The real ADK 2.12 confirmation card. The payload shows exactly which bucket will change.

- Check that bucket_name is your lab bucket.
- Tick Confirmed, then click Submit.

The function now runs. The agent re-scans storage and should report the finding gone. Prove it from outside, the same way you proved the exposure:
```
curl -s -o /dev/null -w "Anonymous read: %{http_code}\n" \
  "https://storage.googleapis.com/$BUCKET/customers.csv"

gcloud storage buckets get-iam-policy "gs://$BUCKET"
gcloud storage buckets describe "gs://$BUCKET" | grep -i public
```
Expected: `401` or `403` instead of `200`, no allUsers in the policy, and public access prevention shown as enforced. If you still get 200, wait a minute and retry; access changes take a short time to spread.

### 7.2 - Reject a fix
Show the room that “no” works too.
```
Disable the firewall rule allow-ssh-from-anywhere.
```
When the card appears, leave Confirmed unticked and click Submit. The function never runs; ADK hands the model the result `This tool call is rejected.` and the agent tells you it left the rule alone.
```
gcloud compute firewall-rules list --filter="network:lab-vpc"
```
### 7.3 - Approve the firewall fixes
```
OK, now disable allow-ssh-from-anywhere and allow-rdp-from-anywhere.
```
You get one card per rule, because the instructions say one resource per call. Approve each. Then check again:
```
gcloud compute firewall-rules list --filter="network:lab-vpc"
```
Expected: both rules now show DISABLED True, and allow-ssh-internal-only is untouched. If you also want the default-allow-ssh and default-allow-rdp rules handled, ask for them by name.

## Phase 08 - The fix it won’t make
```
Can you fix the service account problem too?
```
The agent has no tool for IAM changes, so it can only show the suggested_command from the scan. That is deliberate. Removing Editor from a service account that a real application uses breaks the application, and only a person who knows the workload can decide what narrower role it needs.
In the lab, legacy-app runs nothing, so you can remove the role yourself:
```
gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:legacy-app@$PROJECT_ID.iam.gserviceaccount.com" \
  --role=roles/editor --condition=None
```
## Phase 09 - See the audit trail
Every change the agent made was a normal Google Cloud API call made with your identity, so Cloud Audit Logs recorded it.
```
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity"' \
  --freshness=1h --limit=20 \
  --format="table(timestamp, protoPayload.methodName, protoPayload.resourceName, protoPayload.authenticationInfo.principalEmail)"
```
Look for the bucket IAM change, the bucket update and the firewall patches made while you approved the fixes. Admin Activity logs are always on and free. 

## Phase 10 - How it works under the hood
### 10.1 - What Gemini actually sees
