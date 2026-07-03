# Custom TLS

## Create a RSA-key certificate

Create a TLS certificate for your domain using [certbot][certbot] and its official [Docker image][certbot-docker].

```bash
docker run -it --rm \
  -v ${pwd}/certbot/etc/letsencrypt:/etc/letsencrypt \
  -v ${pwd}/certbot/var/lib/letsencrypt:/var/lib/letsencrypt \
  certbot/certbot certonly --manual \
  --preferred-challenges dns \
  --key-type rsa \
  --email your-email@email.com \
  --domain '*.your-domain.com' \
  --server https://acme-v02.api.letsencrypt.org/directory \
  --agree-tos
```

You can find sample certificate files in the `cert/example` directory, sourced from [AcornPublishing/tls-cryptography][book].

## View the contents of the certificate

```bash
# Show the public key chain details
openssl x509 -in fullchain1.pem -text
keytool -printcert -v -file fullchain1.pem

# Show the private key details
openssl rsa -in privkey1.pem -text
```

## Run tests

Use the following commands to configure, build, and test:

```bash
cmake --preset default -DBUILD_TESTING=ON
cmake --build build
ctest --preset default
```

Generate the test coverage report:

```bash
cmake --preset coverage
cmake --build build-coverage --target coverage
```

> [!NOTE]
> These presets require the `VCPKG_ROOT` environment variable and use vcpkg to resolve CMake dependencies. `coverage` preset also requires `lcov`, `gcov`, and `genhtml` binaries.

## Nix

With the Nix package manager, you do not need vcpkg to get CMake dependencies.

Build:

```bash
nix build .
```

Run tests:

```bash
nix flake check
```

Enter the development shell:

```bash
nix develop
```

Inside the development shell, configure, build, and test with CMake:

```bash
cmake -B build -G Ninja -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build
```

Generate test coverage report:

```bash
cmake -B build-coverage \
  -G Ninja \
  -DBUILD_TESTING=ON \
  -DENABLE_COVERAGE=ON \
  -DCMAKE_BUILD_TYPE=Debug

cmake --build build-coverage --target coverage
```

> [!NOTE]
> `nix build .` and `nix flake check` do not provide incremental compilation.
> For iterative development, use the development shell and run the CMake commands above.

## TLS 1.3 Handshake

```mermaid
sequenceDiagram
    participant Client
    participant Server

    Client->>Server: ClientHello (supported_groups, key_share, supported_versions, psk_key_exchange_modes, signature_algorithms, ...)

    Server->>Client: ServerHello (selected version, key_share)

    Note over Client,Server: Encrypted with Handshake Traffic Keys from ServerHello onwards

    Server-->>Client: EncryptedExtensions
    Server-->>Client: Certificate
    Server-->>Client: CertificateVerify
    Server-->>Client: Finished

    Note over Client: Verify server Finished →  Verify server authentication and handshake integrity

    Client-->>Server: Finished

    Note over Client,Server: Handshake complete, Application Traffic Keys start being used.

    Note over Client,Server: (Optional) ChangeCipherSpec messages may appear for compatibility
```


[book]: https://github.com/AcornPublishing/tls-cryptography
[certbot]: https://github.com/certbot/certbot
[certbot-docker]: https://hub.docker.com/r/certbot/certbot
