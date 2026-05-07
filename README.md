# How to set up the marketplace
The code for the marketplace can be found in the *marketplace* folder.
The topology generator scripts do not set up a marketplace, this has to be done manually:


0. Create your topology like normally, e.g. `./scion.sh topology -c topology/default.topo`
1. Inside *gen* create a folder *marketplace* and inside of it a file *marketplace.toml* and a folder called *certs*.
2. Copy the sample marketplace configuration into *marketplace.toml*:
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
3. (Optionally) copy trust root configurations into *gen/marketplace/certs*
4. Add an entry in the *gen/supervisord.conf* like this:
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
5. Add the marketplace program to the AS program list in the *gen/supervisord.conf*. This could look like this:
```
[group:as1-ff00_0_111]
programs = br1-ff00_0_111-1,br1-ff00_0_111-2,br1-ff00_0_111-3,cs1-ff00_0_111-1,sd1-ff00_0_111,marketplace
```
6. Start using `./scion.sh start`

# Configure ASes to sell assets on marketplace
No manual step necessary for connectivity. ASes will use their AS certificate to request a JWT token which then will be used for both publishing assets and redeeming assets.
Only hardcoded assets are published.

# Connect as an endhost
1. You need a JWT token, while the topology is running, open in the webbrowser `https://localhost:8889`, register using a new user and password. (accounts are in-memory, restarting the topology will delete the account)
2. Click on the "Create new Token" button.
3. Now run the command `./bin/marketplace_client XXX`
where XXX is your token. The tokens have a validity of 1 week.
