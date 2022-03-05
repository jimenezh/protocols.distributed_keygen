import asyncio
from pydoc import plainpager
from typing import List

from tno.mpc.communication import Pool

from tno.mpc.protocols.distributed_keygen import DistributedPaillier

corruption_threshold = 0  # corruption threshold
key_length = 128  # bit length of private key
prime_thresh = 2000  # threshold for primality check
correct_param_biprime = 40  # correctness parameter for biprimality test
stat_sec_shamir = (
    40  # statistical security parameter for secret sharing over the integers
)

PARTIES = 2  # number of parties that will be involved in the protocol, you can change this to any number you like


def setup_local_pool(server_port: int, ports: List[int]) -> Pool:
    pool = Pool()
    pool.add_http_server(server_port, "localhost")
    for client_port in (port for port in ports if port != server_port):
        pool.add_http_client(f"client{client_port}", "localhost", client_port)
    return pool


local_ports = [3000 + i for i in range(PARTIES)]
local_pools = [
    setup_local_pool(server_port, local_ports) for server_port in local_ports
]

loop = asyncio.get_event_loop()
async_coroutines = [
    DistributedPaillier.from_security_parameter(
        pool,
        corruption_threshold,
        key_length,
        prime_thresh,
        correct_param_biprime,
        stat_sec_shamir,
        distributed=False,
    )
    for pool in local_pools
]
print("Starting distributed key generation protocol.")
distributed_paillier_schemes = loop.run_until_complete(
    asyncio.gather(*async_coroutines)
)

server = distributed_paillier_schemes[0]
analyst = distributed_paillier_schemes[1]

print("n = ",server.public_key.n, " g = ", server.public_key.g )
print("Server secret key is ", server.secret_key.t)

message = 12
ciphertext = server.encrypt(message)

pserver = server.secret_key.partial_decrypt(ciphertext)
panalyst = analyst.secret_key.partial_decrypt(ciphertext)

plaintext_attempt = server.secret_key.decrypt({0: pserver, 1:panalyst } )

# plaintext = server.decrypt(ciphertext)

print(f"Message: {message}\nCiphertext: {ciphertext}\nPartial decryptions: \n  Server - {pserver} \n  Analyst -  {panalyst}")


print("The protocol has completed.")