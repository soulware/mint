# Mint

Mint lets you create "roles" consisting of flexible IAM policy templates associated with Tigris access keys. 
We use macaroons to handle both authorization and authentication (via third-party caveats).
Policy templates support expressions (`{{env.bucket}}`) replaced with values sourced from configuration.
Templates also support expressions (`{{caveat.path}}`) replaced directly from caveats on the macaroon itself.

Mint extends the simplified [Tigris IAM](https://www.tigrisdata.com/docs/iam/) model, with the ability to exchange long-lived "service tokens" for temporary, limited-privilege credentials derived from policy templates. Think of this as _roughly_ analogous to a lightweight macaroon-aware STS (but don't quote me on that).

* AWS [Identity and Access Management](https://aws.amazon.com/iam/) (IAM)
* AWS [Security Token Service](https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) (STS)

Example policy template -

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::{{env.bucket}}/{{env.prefix}}/*"],
      "Condition": {
        "DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}
      }
    }
  ]
}
```

The following expressions are replaced when the policy is created from the template -

* `{{env.bucket}}` - bucket name
* `{{env.prefix}}` - path prefix
* `{{mint.expiry}}` - policy expiration

Mint additionally supports flexible `{{caveat.<key>}}` expressions fulfilled by the client credential itself. This lets us do interesting things with both *attenuation* and *attestation* -

* *attenuation* of existing credentials to further restrict a policy
* *attestation* (by a third-party) of policy template expression values

## Getting Started

Initial configuration and Tigris admin credential management -
```bash
cp examples/mint-demo.toml ./mint-demo.toml   # then edit bucket name (note: store.bucket and env.bucket)
export MINT_CONFIG=./mint-demo.toml

# Then either (A) or (B) below -

# (A) Tigris admin credentials in 1Password
cp examples/mint-demo.env ./mint-demo.env    # then edit to match your vault and path

# (B) Tigris admin credentials directly exported
export AWS_ACCESS_KEY_ID=<KEY_ID>
export AWS_SECRET_ACCESS_KEY=<SECRET_KEY>
```

Run the `mint` server -

```bash
# Build it first
cargo build

# Then run it via 1Password "op run" -
op run --env-file ./mint-demo.env -- ./target/debug/mint serve

# Or with admin credentials exported as env vars, simply -
./target/debug/mint serve
```

With `mint serve` still running we can then interact with it via the mint cli in a new terminal. Note that the mint server by default runs with a demo authentication service available via `auth.sock` locally.

```bash
export MINT_CONFIG=./mint-demo.toml

# Login via mint cli
./target/debug/mint login

# "Seal" the example policy templates (to prevent them being tampered with)
./target/debug/mint seal

# Display the <INVITE> for enrolling a new client
./target/debug/mint invite
```

The mint cli includes a demonstration `client` sub-cmd to allow the enrollment flow to be exercised.

```bash
# Client begins the enrollment process, providing the <INVITE> from earlier -
./target/debug/mint client enroll demo_client <INVITE>

# The operator can then approve the enrollment request -
./target/debug/mint enroll list
./target/debug/mint enroll approve demo_client

# The client fingerprint can be verified out-of-band -
./target/debug/mint client fingerprint
```

Once a client has successfully enrolled with mint it can exchange its credentials for per-role long-lived "service tokens". The client can then "assume-role" swapping a service token for short-lived Tigris/S3 credentials associated with an IAM policy built from the associated template.

```bash
# List the available roles (these are what we "sealed" earlier) -
./target/debug/mint role list

# Exchange for a long-lived service token for the "demo" role -
./target/debug/mint client exchange demo

# Assume this demo role to obtain short-lived Tigris access keys -
./target/debug/mint client assume-role demo
```

For a more complex example the `demo-attested` template requires an attested role-specific value. By default mint runs with a demo attestation service available via `attest.sock` locally.

The template for the `demo-attested` role substitutes two `{{caveat.X}}` values:

* `{{caveat.sub}}` - the client identifier (defined at enrollment)
* `{{caveat.path}}` - role-specific value (defined at _exchange_ and attested via third-party caveat)

```bash
# Exchange for the role-specific service token, passing the value to be attested for the {{caveat.path}} template expression
./target/debug/mint client exchange demo-attested --attest path=images

# Assume the role to obtain short-lived Tigris access keys
./target/debug/mint client assume-role demo-attested
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
