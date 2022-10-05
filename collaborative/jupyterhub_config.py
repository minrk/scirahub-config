c = get_config()  # noqa

c.Authenticator.allowed_users = {"tst01", "tst02"}
c.JupyterHub.authenticator_class = "dummy"
c.JupyterHub.spawner_class = "simple"
c.JupyterHub.log_level = 10
c.JupyterHub.cleanup_servers = True


c.JupyterHub.load_roles = [
    # grant specific users access to all servers
    {
        "name": "full-access",
        "scopes": [
            "access:servers",
        ],
        "users": ["tst01"],
    },
]


c.JupyterHub.ip = "127.0.0.1"
c.Spawner.cmd = ["jupyterhub-singleuser", "--LabApp.collaborative=True"]
