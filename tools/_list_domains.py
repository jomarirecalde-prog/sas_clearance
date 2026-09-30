import os
import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(
    "109.106.254.155",
    port=65002,
    username="u899628465",
    password=os.environ["DEPLOY_SSH_PASSWORD"],
    timeout=60,
    allow_agent=False,
    look_for_keys=False,
)
for cmd in [
    'find "$HOME"/domains -maxdepth 2 -type d -name public_html 2>/dev/null',
    'ls -1 "$HOME"/domains 2>/dev/null',
]:
    _, o, e = c.exec_command(cmd)
    print(o.read().decode())
    err = e.read().decode()
    if err:
        print("err:", err)
c.close()
