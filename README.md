# oencrypt: portable javascript encryption interface

`oencrypt` is based on the Web Crypto API
`oencrypt` interface may run in a browser or at command line
`oenc` command line is compatible with subset of openssl command line encryption.

## Usage

Open SSL compatible (pbkdf2):
```
echo validate | openssl enc -aes-256-ctr -pbkdf2 -pass pass:test -iter 10000 | ./oenc -aes-256-ctr -pass test -d
```

```
echo validate | openssl enc -aes-256-cbc -pbkdf2 -pass pass:test -iter 10000 | ./oenc -aes-256-cbc -pass test -d
```

Using AES wrapped key (password generated with PBKDF2):

```
key="$(./oenc -genkey -pass test)"
echo validate | ./oenc -key "$key" -pass test -base64 |  ./oenc -key "$key" -pass test -base64 -d
```

Using "key" representing offset from actual PBKDF2 key.

```
key="$(./oenc -genkey -key-is-offset -pass test)"
echo validate | ./oenc -key-is-offset -key "$key" -pass test -base64 |  ./oenc -key-is-offset -key "$key" -pass test -base64 -d
```

key encryption test in a browser

[test.html](https://dmahurin.github.io/oencrypt/test.html)
