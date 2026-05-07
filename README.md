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
Currently if configured, ASes only sell hardcoded assets just to test whether publishing and redeeming assets work.

1. Each AS needs a JWT token. Currently this can be automatically requested using this command:
`curl https://localhost:8889/ia-token --cert gen/ASff00_0_110/crypto/as/ISD1-ASff00_0_110.pem --key gen/ASff00_0_110/crypto/as/cp-as.key -k -X POST`
where the folder paths and file names are dependent on the AS that wants to request the AS. (curl uses this certificate in a mTLS handshake)
2. Open the control service configuration file and add:
```
[marketplace]
token = XXX
```
where XXX is the token you previously obtained.
3. Repeat this for the other ASes you want. Then restart the topology.

# Connect as an endhost
1. You need a JWT token, while the topology is running, open in the webbrowser `https://localhost:8888`, register using a new user and password. (accounts are in-memory, restarting the topology will delete the account, however, the JWT tokens remain valid as long as the topology is not reseted)
2. Click on the "Create new Token" button.
3. Now run the command `./bin/marketplace_client XXX`
where XXX is your token. The tokens have a validity of 1 week.
