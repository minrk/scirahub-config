c = get_config()  # noqa

import pwd

# pre-populate allowed users list (so all users exist)
c.Authenticator.allowed_users = {
    user.pw_name for user in pwd.getpwall() if 1000 <= user.pw_uid < 50000
}
c.Authenticator.delete_invalid_users = True

# replace these with 'real' users
# c.Authenticator.allowed_users = {"tst01", "tst02"}

# c.JupyterHub.authenticator_class = "dummy"


c.JupyterHub.log_level = 10
c.JupyterHub.cleanup_servers = True

collab_user = 'project-collab'

c.JupyterHub.load_roles = [
    {
        "name": "admin-servers",
        "scopes": [
            "admin-ui",
            "admin:servers",
            "list:users",
        ],
        "groups": ["server-admins"],
    },
    {
        "name": "collab-access",
        "scopes": [
            "admin-ui",
            f"admin:servers!user={collab_user}",
            f"list:users!user={collab_user}",
            f"access:servers!user={collab_user}",
        ],
        "groups": ["project"],
    },


    # grant specific users access to all servers
    {
        "name": "full-access",
        "scopes": [
            "access:servers",
        ],
        "users": ["minrk-admin"],
    },
]

c.JupyterHub.load_groups = {
    # project group: access to _this project's_ collaborative server
    "project": [
        "minrk",
        "rcthomas",
        "shreyas",
    ],
    # full server admins (doesn't include access)
    "server-admins": [
        "minrk-admin",
    ],
    "collaborative": [
        collab_user,
    ]
}


c.JupyterHub.bind_url = "http://127.0.0.1:8000/rtc/"

def pre_spawn_hook(spawner):
    group_names = {group.name for group in spawner.user.groups}
    if "collaborative" in group_names:
        spawner.log.info(f"Enabling RTC for user {spawner.user.name}")
        spawner.args.append("--LabApp.collaborative=True")

c.Spawner.pre_spawn_hook = pre_spawn_hook
