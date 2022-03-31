#!/bin/sh -e

passed () {
 echo "passed: $test"
}
failed () {
 echo "failed: $test"
}

trap '[ $? -eq 0 ] || failed' EXIT

validate="validate"
pass="test"
pass2="check"
iter=10000
key="$(./oenc -genkey -pass "$pass" )"
key2="$(./oenc -genkey -key "$key" -pass "$pass" -new-pass "$pass2")"
okey="$(./oenc -genkey -key-is-offset -pass "$pass" )"
okey2="$(./oenc -genkey -key-is-offset -key "$okey" -pass "$pass" -new-pass "$pass2")"
test="basic (pbkdf2)" ; test "$validate" = "$(echo "$validate" | ./oenc -pass "$pass" | ./oenc -pass "$pass" -d)" ; passed
test="basic (pbkdf2) negative" ; test "$validate" != "$(echo "$validate" | ./oenc -pass "$pass" | ./oenc -pass "$pass2" -d)" ; passed
test="basic (pbkdf2) with base64" && test "$validate" = "$(echo "$validate" | ./oenc -pass "$pass" -base64 | ./oenc -pass "$pass" -base64 -d)" ; passed
test="key" ; test "$validate" = "$(echo "$validate" | ./oenc -key "$key" -pass "$pass" | ./oenc -key "$key" -pass "$pass" -d)" ; passed
test="key negative test" && test "$validate" != "$(echo "$validate" | ./oenc -key "$key" -pass "$pass" | ./oenc -key "$key" -pass "$pass2" -d)" ; passed
test="key base64" ; test "$validate" = "$(echo "$validate" | ./oenc -key "$key" -pass "$pass" -base64 | ./oenc -key "$key" -pass "$pass" -base64 -d)" ; passed
test="key rekey" ; test "$validate" = "$(echo "$validate" | ./oenc -key "$key" -pass "$pass" | ./oenc -key "$key2" -pass "$pass2" -d)" ; passed
test="offset key" ; test "$validate" = "$(echo "$validate" | ./oenc -key-is-offset -key "$okey" -pass "$pass" | ./oenc -key-is-offset -key "$okey" -pass "$pass" -d)" ; passed
test="offset key rekey" ; test "$validate" = "$(echo "$validate" | ./oenc -key-is-offset -key "$okey" -pass "$pass" | ./oenc -key-is-offset -key "$okey2" -pass "$pass2" -d)" ; passed
test="openssl aes-ctr defaults" && test "$validate" = "$(echo "$validate" | openssl enc -aes-256-ctr -pbkdf2 -pass pass:"$pass" | ./oenc -pass "$pass" -d)" ; passed
test="openssl aes-ctr" ; test "$validate" = "$(echo "$validate" | openssl enc -aes-256-ctr -pbkdf2 -pass pass:"$pass" -iter "$iter" | ./oenc -aes-256-ctr -pass "$pass" -d)" ; passed
test="openssl aes-cbc" ; test "$validate" = "$(echo "$validate" | openssl enc -aes-256-cbc -pbkdf2 -pass pass:"$pass" -iter "$iter" | ./oenc -aes-256-cbc -pass "$pass" -d)" ; passed

echo "Success"
