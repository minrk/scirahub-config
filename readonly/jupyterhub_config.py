c = get_config()  # noqa

import pwd

# pre-populate allowed users list (so all users exist)
c.Authenticator.allowed_users = {
    user.pw_name for user in pwd.getpwall() if 1000 <= user.pw_uid < 50000
}
c.Authenticator.delete_invalid_users = True

c.JupyterHub.cleanup_servers = True

# dummy for testing
# c.Authenticator.allowed_users = {'minrk', 'shreyas', 'rcthomas'}
# c.JupyterHub.authenticator_class = 'dummy'


c.JupyterHub.custom_scopes = {
    "custom:jupyter_server:read:*": {
        "description": "read-only access to your server",
    },
    "custom:jupyter_server:write:*": {
        "description": "access to modify files on your server. Does not include execution.",
        "subscopes": ["custom:jupyter_server:read:*"],
    },
    "custom:jupyter_server:execute:*": {
        "description": "Execute permissions on servers.",
        "subscopes": [
            "custom:jupyter_server:write:*",
            "custom:jupyter_server:read:*",
        ],
    },
}

c.JupyterHub.load_roles = [
    # grant specific users read-only access to all servers
    {
        "name": "read-only",
        "scopes": [
            "access:servers",
            "custom:jupyter_server:read:*",
        ],
        "users": ["minrk", "shreyas", "rcthomas"],
    },

    {
        "name": "admin-ui",
        "scopes": [
            "admin-ui",
            "list:users",
            "admin:servers",
        ],
        "users": ["minrk"],
    },

    # {
    #     "name": "full-access",
    #     "scopes": [
    #         "access:servers",
    #         "custom:jupyter_server:execute:*",
    #     ],
    #     "users": ["minrk"],
    # },
    # all users have full access to their own servers
    {
        "name": "user",
        "scopes": [
            "custom:jupyter_server:execute:*!user",
            "custom:jupyter_server:read:*!user",
            "self",
        ],
    },
]

# servers request access to themselves

c.Spawner.oauth_client_allowed_scopes = [
    "access:servers!server",
    "custom:jupyter_server:read:*!server",
    "custom:jupyter_server:execute:*!server",
]

import sys

from pathlib import Path
here = Path(__file__).parent.resolve()

c.Spawner.environment = {
    "JUPYTERHUB_SINGLEUSER_EXTENSION": "1",
}
c.Spawner.args = [
    f"--config={here}/jupyter_server_config.py",
]

sys.path.insert(0, str(here.parent))
from scirahubspawner import SCIRAHubSpawner
c.JupyterHub.spawner_class = SCIRAHubSpawner
# c.JupyterHub.spawner_class = 'simple'

c.JupyterHub.bind_url = "http://127.0.0.1:9000/readonly/"
c.ConfigurableHTTPProxy.api_url = "http://127.0.0.1:9001"
c.JupyterHub.hub_bind_url = "http://127.0.0.1:9090"
