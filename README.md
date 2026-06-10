# How to set up the marketplace
The code for the marketplace can be found in the [marketplace](./marketplace) folder.
The topology generator scripts do not set up a marketplace, this has to be done manually:

1. Create your topology like normally, e.g. `./scion.sh topology -c topology/default.topo`
2. Run `python setup_marketplace.py <IA>`, where AS is in the format `1-ff00_0_111`, which configures the marketplace to be run inside that AS. This setup script currently supports only a single marketplace per topology.
3. Start using `./scion.sh start`

# Configure ASes to sell assets on marketplace
No manual step necessary for connectivity. ASes will use their AS certificate to request a JWT token which then will be used for both publishing assets and redeeming assets.
Only hardcoded assets are published.

# Connect as an endhost
1. You need a JWT token, while the topology is running, open in the webbrowser [https://localhost:8889](https://localhost:8889), login or register using a new user and password.
2. Click on the "Create new Token" button.
3. Now run the command `./bin/marketplace_client`
4. Now you can either connect over SCION or over TCP. The default address for SCION would be: `[1-ff00:0:111,127.0.0.1]:9888`, and the default address for TCP: `https://localhost:8888`.
5. When running over SCION, you have to provide the endhost API Url of the local AS. (see the topology.json files inside the gen/ASff00_0_XXX folder)

# Folder description:
- [marketplace](./marketplace) Contains the marketplace server logic.
- [marketplace/webapp](./marketplace/webapp) Contains the marketplace account webpage logic.
- [marketplace_client](./marketplace_client) Contains a very simple marketplace client for an endhost
- [control/marketplace](./control/marketplace/) Contains the AS marketplace client (jwt token requester, asset publisher and redemption service)
