import os
from jupyter_server.auth import Authorizer
from jupyterhub.services.auth import  check_scopes

class JupyterHubAuthorizer(Authorizer):
    """Authorizer that looks for permissions in JupyterHub scopes"""

    def is_authorized(self, handler, user, action, resource):
        # print(user)
        scopes = user.hub_user["scopes"]
        # authorize if any of these permissions are present
        # filters check for access to this specific server
        filters = [
            f"!user={os.environ['JUPYTERHUB_USER']}",
            f"!server={os.environ['JUPYTERHUB_USER']}/{os.environ['JUPYTERHUB_SERVER_NAME']}",
        ]
        required_scopes = set()
        for f in filters:
            required_scopes.update(
                {
                    f"custom:jupyter_server:{action}:{resource}{f}",
                    f"custom:jupyter_server:{action}:*{f}",
                }
            )
        # self.log.info(f"Required scopes are: {required_scopes}")
        have_scopes = check_scopes(required_scopes, scopes)

        # self.log.debug(f"{user['name']} has permissions: { user['scopes']}")
        self.log.debug(
            f"{user.username} has permissions {have_scopes} required to {action} on {resource}"
        )
        return bool(have_scopes)


c = get_config()  # noqa

c.ServerApp.authorizer_class = JupyterHubAuthorizer

# import pprint
# pprint.pprint(dict(os.environ))

# # reimplement service prefix
# from urllib.parse import urlparse
#
# url = urlparse(os.environ['JUPYTERHUB_SERVICE_URL'])
# c.ServerApp.port = url.port
# c.ServerApp.ip = url.hostname
# c.ServerApp.base_url = url.path
# c.ServerApp.open_browser = False
