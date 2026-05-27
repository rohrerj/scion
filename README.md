# How to set up the marketplace
The code for the marketplace can be found in the [marketplace](./marketplace) folder.
The topology generator scripts do not set up a marketplace, this has to be done manually:

0. Create your topology like normally, e.g. `./scion.sh topology -c topology/default.topo`
1. Inside the [gen](./gen/) folder, create a folder called `marketplace` and inside of it a file `marketplace.toml` and a folder called `certs`.
2. Copy the sample marketplace configuration into [gen/marketplace/marketplace.toml](./gen/marketplace/marketplace.toml):
```
[general]
id = "marketplace"
config_dir = "gen/ASff00_0_111"

[log.console]
level = "debug"

[marketplace]
api_addr = "localhost:8888"
account_addr = "localhost:8889"
```
3. (Optionally) copy some trust root configurations from [gen/trcs](./gen/trcs) into [gen/marketplace/certs](./gen/marketplace/certs).
4. Add an entry in the [gen/supervisord.conf](./gen/supervisord.conf) like this:
```
[program:marketplace]
autostart = false
autorestart = false
environment = TZ=UTC,GODEBUG="cgocheck=0"
stdout_logfile = logs/marketplace.log
redirect_stderr = True
startretries = 0
startsecs = 5
priority = 100
command = bin/marketplace --config gen/marketplace/marketplace.toml
```
5. Add the marketplace program to the AS program list in the [gen/supervisord.conf](./gen/supervisord.conf). This could look like this:
```
[group:as1-ff00_0_111]
programs = br1-ff00_0_111-1,br1-ff00_0_111-2,br1-ff00_0_111-3,cs1-ff00_0_111-1,sd1-ff00_0_111,marketplace
```
6. Start using `./scion.sh start`

# Configure ASes to sell assets on marketplace
No manual step necessary for connectivity. ASes will use their AS certificate to request a JWT token which then will be used for both publishing assets and redeeming assets.
Only hardcoded assets are published.

# Connect as an endhost
1. You need a JWT token, while the topology is running, open in the webbrowser [https://localhost:8889](https://localhost:8889), register using a new user and password. (accounts are in-memory, restarting the topology will delete the account)
2. Click on the "Create new Token" button.
3. Now run the command `./bin/marketplace_client`

# Folder description:
- [marketplace](./marketplace) Contains the marketplace server logic.
- [marketplace/webapp](./marketplace/webapp) Contains the marketplace account webpage logic.
- [marketplace_client](./marketplace_client) Contains a very simple marketplace client for an endhost
- [control/marketplace](./control/marketplace/) Contains the AS marketplace client (jwt token requester, asset publisher and redemption service)
