# kerberust
A commandline tool to attack kerberos protocol.

## Usage
Basic usage: 
```bash
kerberust [options] <module> [module-options]
```
Current capabilites:
- userenum
- string2key
### userenum
`userenum` module can be used to enumerate valid users in a domain. It can enumerate users with kerberos pre-authentication disabled, and optionally dump AS-REP hash, that can be cracked using `john` or `hashcat`. `kerberust` will try to resolve the supplied domain, but in case it is not able to, ip address needs to be supplied using the `--ip` option.
```bash 
# Check validity of a single user
kerberust userenum --domain DOMAIN.local --username Administrator

# Check validiy for multiple users from a username list.
kerberust userenum --domain DOMAIN.local --userlist usernames.txt --threads 50

# Dump AS-REP hash for users having kerberos pre-auth disabled using --npauth flag.
kerberust userenum --domain DOMAIN.local --username john.doe --npauth

# By default, RC4-HMAC encryption type is negotiated, if supporrted by the server. Use --opsec flag to disable RC4 negotiation.
kerberust userenum --domain DOMAIN.local --username john.doe --npauth --opsec
```
### string2key
`string2key` module can be used to generate AES128, AES256 and RC4(NTLM) keys from password and salt.
```bash
kerberust string2key --password P@SSw0rd! --salt DOMAIN.LOCALAdministrator
```
## Installation
```bash
# Clone the repository
git clone https://github.com/drdragon79/kerberust
# Navigate to the directory
cd kerberust
# Use cargo to build and install the binary
cargo install --path .
# Kerberust binary will be installed at $HOME/.cargo/bin by default
```
### License
kerberust is licensed under MIT.