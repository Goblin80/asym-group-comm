# Asymmetric Group Communication

Communication utility between multiple clients.

1. Clients asks certificate authority (CA_server.py) to generate `RSA` keys for them.

1. CA sends `RSA` privates to the clients after symmetrically encrypting them.

1. `Fernet` used as the symmetric encryption method of choice (`AES` in `CBC` mode with 128-bit key) after agreeing on a shared key using `Diffie-Hellman` key exchange.

1. Public keys generated are kept in a registry maintained by CA.

1. Clients communicate directly with each other directly, only polling CA for new clients.