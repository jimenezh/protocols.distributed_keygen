from pydoc import plain
from paillier_shared_key import PaillierSharedKey
from tno.mpc.encryption_schemes.paillier import PaillierPublicKey, Paillier, PaillierCiphertext
from math import factorial
from tno.mpc.encryption_schemes.utils import pow_mod

# Computed values
n = 799
n_2 = n*n
g = n+1
phi_n = 736
n_inv_mod_phi_n = 479

threshold = 2
party_count = 2
delta = factorial(party_count)
extra_factor = 4*(delta**2)

analyst_secret_exp = 1584955
analyst_secret_rand_exp = 100
server_secret_exp = 1088108
server_secret_rand_exp = 379

server_id = 1
analyst_id = 2

# Create public key
public_key = PaillierPublicKey(n, g)
paillier = Paillier(public_key=public_key, secret_key=None, share_secret_key=False)

# Create private keys
server_secret_key = PaillierSharedKey (n, threshold , server_id, server_secret_exp, delta, extra_factor, server_secret_rand_exp)
analyst_secret_key = PaillierSharedKey (n, threshold , analyst_id, analyst_secret_exp,delta,  extra_factor, analyst_secret_rand_exp)

# Test
message = 12
ciphertext = paillier.encrypt(message)
# ciphertext = PaillierCiphertext(467076, paillier)

## Partial decryptions
partial_analyst = analyst_secret_key.partial_decrypt(ciphertext)
partial_server = server_secret_key.partial_decrypt(ciphertext)

## Share combine
partial_dict = {1: partial_analyst, 2: partial_server }
plaintext = analyst_secret_key.decrypt(partial_dict)

## Partial Randomnesses
partial_rand_analyst = analyst_secret_key.partial_randomness_recovery(ciphertext, plaintext)
partial_rand_server = server_secret_key.partial_randomness_recovery(ciphertext, plaintext)

## Total randomness
r = partial_rand_server * partial_rand_analyst

## Checking correctness of randomness 
### ciphertext = g^m * r^{n} mod n^2
c_prime = (pow_mod(g, message, n_2)*pow_mod(r, n, n_2)) % n_2

print(f"Public keys {n} {g}")
print(f"Analyst key is {analyst_secret_key.share}")
print(f"Server key is {server_secret_key.share}")
print(f"Encrypt {message} into {ciphertext.value}")
print(f"Partial decryptions: \n  {partial_server   } \n  {partial_analyst}")
print(f"Reconstructed plaintext is {plaintext}")
print(f"Partial randomnesses: {partial_rand_server} {partial_rand_analyst}")
print(f"Total randombess {r}")

print(f"Re-encrypting {plaintext} with randomness {partial_rand_analyst} is { c_prime} (original ciphertext is {ciphertext.value})")