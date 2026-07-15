# How to set up the marketplace
The code for the marketplace can be found in the [marketplace](./marketplace) folder.
The topology generator scripts do not set up a marketplace, this has to be done manually:

1. Create your topology like normally, e.g. `./scion.sh topology -c topology/default.topo`
2. Run `python setup_marketplace.py <IA>`, where AS is in the format `1-ff00_0_111`, which configures the marketplace to be run inside that AS. This setup script currently supports only a single marketplace per topology.
3. (Optional) Load assets, users, reservations, redemption delegations from file: `python populate_marketplace.py --db gen-cache/marketplace.db --schema marketplace/db/schema.sql --file <your-file>`
4. Start using `./scion.sh start`

# Sell assets on marketplace
1. If you dont already have the JWT tokens, follow the instructions under `Register an AS user`
2. Follow the instructions under `Connect as an AS user`
3. Type "publish" and then provide the necessary asset informations and confirm.

# Connect as an endhost
1. You need a JWT token, while the topology is running, open in the webbrowser [https://localhost:8888](https://localhost:8888), login or register using a new user and password.
2. Click on the "Create new Token" button.
3. Now run the command `./bin/marketplace_client` (or `./bin/marketplace_client --insecure` to skip TLS certificate validation)
4. Now you can either connect over SCION or over TCP. The default address for SCION would be: `[1-ff00:0:111,127.0.0.1]:8888`, and the default address for TCP: `https://localhost:8888`.
5. When running over SCION, you have to provide the endhost API Url of the local AS. (see the topology.json files inside the gen/ASff00_0_XXX folder)
6. Now you can call the info endpoint, search for assets, buy assets, split assets, combine assets, redeem assets, or reset your JWT token.

# Register an AS user
1. While the topology is running, run the command `./bin/marketplace_client --register` (or `./bin/marketplace_client --register --insecure` to skip TLS certificate validation).
2. Now you can either connect over SCION or over TCP. The default address for SCION would be: `[1-ff00:0:111,127.0.0.1]:8888`, and the default address for TCP: `https://localhost:8888`.
3. Configure the local IA for which you want to request the JWT tokens
4. Provide folder paths to the trust root configurations, the certificates and the private keys. (gen/ASff00_0_110/certs, gen/ASff00_0_110/crypto/as, gen/ASff00_0_110/crypto/as)
5. Now you should have obtained an asset publisher JWT token, and a token for the redemption service.

# Connect as an AS user
1. Run the command `./bin/marketplace_client` (or `./bin/marketplace_client --insecure` to skip TLS certificate validation)
2. Now you can either connect over SCION or over TCP. The default address for SCION would be: `[1-ff00:0:111,127.0.0.1]:8888`, and the default address for TCP: `https://localhost:8888`.
3. For asset publishing or statistics, provide the AS publisher JWT token, for redemption delegation provide the redemption service token.
4. When running over SCION, you have to provide the endhost API Url of the local AS. (see the topology.json files inside the gen/ASff00_0_XXX folder)
5. Now you can publish assets, fetch statistics or control redemption delegation

# Reset JWT tokens
1. Run the command `./bin/marketplace_client` (or `./bin/marketplace_client --insecure` to skip TLS certificate validation)
2. Now you can either connect over SCION or over TCP. The default address for SCION would be: `[1-ff00:0:111,127.0.0.1]:8888`, and the default address for TCP: `https://localhost:8888`.
3. Provide your JWT token (it works the same for users and AS users)
4. When running over SCION, you have to provide the endhost API Url of the local AS. (see the topology.json files inside the gen/ASff00_0_XXX folder)
5. Type "reset" and confirm. Warning: if this is called using an AS user, it will interrupt a currently connected redemption service connection.
6. Now all tokens issued to this user are no longer valid. The endhost user can retrieve a new token through the web interface and an AS user has to run the AS registration steps again.

# Folder description:
- [marketplace](./marketplace) Contains the marketplace server logic.
- [marketplace/webapp](./marketplace/webapp) Contains the marketplace account webpage logic.
- [marketplace_client](./marketplace_client) Contains the marketplace client used by the endhost and AS users to interact with the marketplace. Is also used for AS user registration.
- [control/marketplace](./control/marketplace/) Contains some test / simulation code for account registration and redemption service, please ignore.
