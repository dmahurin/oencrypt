#!/bin/sh -e

trap '[ $? -eq 0 ] || echo Failure' EXIT

validate="validate"
pass="test"
pass2="check"
iter=10000
key="$(./oenc -genkey -pass "$pass" )"
key2="$(./oenc -genkey -key "$key" -pass "$pass" -new-pass "$pass2")"
okey="$(./oenc -genkey -key-is-offset -pass "$pass" )"
okey2="$(./oenc -genkey -key-is-offset -key "$okey" -pass "$pass" -new-pass "$pass2")"
echo "basic (pbkdf2)" && test "$validate" = "$(echo "$validate" | ./oenc -pass "$pass" | ./oenc -pass "$pass" -d)"
echo "basic (pbkdf2) negative" && test "$validate" != "$(echo "$validate" | ./oenc -pass "$pass" | ./oenc -pass "$pass2" -d)"
echo "basic (pbkdf2 ) with base64" && test "$validate" = "$(echo "$validate" | ./oenc -pass "$pass" -base64 | ./oenc -pass "$pass" -base64 -d)"
echo "key" && test "$validate" = "$(echo "$validate" | ./oenc -key "$key" -pass "$pass" | ./oenc -key "$key" -pass "$pass" -d)"
echo "key negative test" && test "$validate" != "$(echo "$validate" | ./oenc -key "$key" -pass "$pass" | ./oenc -key "$key" -pass "$pass2" -d)"
echo "key base64" && test "$validate" = "$(echo "$validate" | ./oenc -key "$key" -pass "$pass" -base64 | ./oenc -key "$key" -pass "$pass" -base64 -d)"
echo "key rekey" && test "$validate" = "$(echo "$validate" | ./oenc -key "$key" -pass "$pass" | ./oenc -key "$key2" -pass "$pass2" -d)"
echo "offset key" && test "$validate" = "$(echo "$validate" | ./oenc -key-is-offset -key "$okey" -pass "$pass" | ./oenc -key-is-offset -key "$okey" -pass "$pass" -d)"
echo "offset key rekey" && test "$validate" = "$(echo "$validate" | ./oenc -key-is-offset -key "$okey" -pass "$pass" | ./oenc -key-is-offset -key "$okey2" -pass "$pass2" -d)"
echo "openssl aes-ctr defaults" && test "$validate" = "$(echo "$validate" | openssl enc -aes-256-ctr -pbkdf2 -pass pass:"$pass" | ./oenc -pass "$pass" -d)"
echo "openssl aes-ctr" && test "$validate" = "$(echo "$validate" | openssl enc -aes-256-ctr -pbkdf2 -pass pass:"$pass" -iter "$iter" | ./oenc -aes-256-ctr -pass "$pass" -d)"
echo "openssl aes-cbc" && test "$validate" = "$(echo "$validate" | openssl enc -aes-256-cbc -pbkdf2 -pass pass:"$pass" -iter "$iter" | ./oenc -aes-256-cbc -pass "$pass" -d)"

echo "Success"
