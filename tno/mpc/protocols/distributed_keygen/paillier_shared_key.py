"""
Paillier secret key that is shared amongst several parties.
"""

from typing import Dict

from tno.mpc.encryption_schemes.paillier import PaillierCiphertext
from tno.mpc.encryption_schemes.shamir import IntegerShares
from tno.mpc.encryption_schemes.templates.asymmetric_encryption_scheme import SecretKey
from tno.mpc.encryption_schemes.utils import mod_inv, pow_mod

from utils import mult_list


class PaillierSharedKey(SecretKey):
    """
    Class containing relevant attributes and methods of a shared paillier key.
    """

    def __init__(
        self, n: int, t: int, player_id: int, share: int, delta: int, theta: int, x: int
    ) -> None:
        """
        Initializes a Paillier shared key.

        :param n: modulus of the DistributedPaillier scheme this secret key belongs to
        :param t: corruption_threshold of the secret sharing
        :param player_id: the index of the player to whom the key belongs
        :param share: secret sharing of the exponent used during decryption
        :param delta: factorial of number of parties
        :param theta: Value used in the computation of a full decryption after partial decryptions
            have been obtained. We refer to the paper for more details
        :param x: secret share of n^-1 mod phi(n) used in randomness recovery
        """
        super().__init__()
        self.share = share
        self.n = n
        self.n_square = n * n
        self.t = t
        self.player_id = player_id
        self.theta = theta
        self.theta_inv = mod_inv(self.theta, self.n)
        self.delta = delta
        self.x = x

    def partial_decrypt(self, ciphertext: PaillierCiphertext) -> int:
        """
        Function that does local computations to get a partial decryption of a ciphertext.

        :param ciphertext: ciphertext to be partially decrypted
        :raise TypeError: If the given ciphertext is not of type PaillierCiphertext.
        :raise ValueError: If the ciphertext is encrypted against a different key.
        :return: partial decryption of ciphertext
        """

        if not isinstance(ciphertext, PaillierCiphertext):
            raise TypeError(
                f"Expected ciphertext to be a PaillierCiphertext not: {type(ciphertext)}"
            )

        if self.n != ciphertext.scheme.public_key.n:
            raise ValueError("encrypted against a different key!")
        ciphertext_value = ciphertext.value

        # Partial decryption, c_i = c^{2*delta*s_i} mod n^2
        partial_decryption = pow_mod(ciphertext_value, 2*self.delta*self.share, self.n_square)

        # Lagrange Coefficients
        other_honest_players = [
            i + 1 for i in range(self.t) if i + 1 != self.player_id
        ]

        # NB: Here the reconstruction set is implicit defined, but any
        # large enough subset of shares will do.
        # reconstruction_shares = {key: shares[key] for key in list(shares.keys())[:degree + 1]}

        lagrange_interpol_enumerator = self.delta * mult_list(other_honest_players)
        lagrange_interpol_denominator = mult_list(
            [(j - self.player_id) for j in other_honest_players]
        )

        # Exponent is 2*lambda_{0,i}^S
        exp = (
             lagrange_interpol_enumerator * 2
        ) // lagrange_interpol_denominator


        # Notice that the partial decryption is already raised to the power given
        # by the Lagrange interpolation coefficient
        if exp < 0:
            partial_decryption = mod_inv(partial_decryption, self.n_square)
            exp = -exp
        partial_decryption = pow_mod(partial_decryption, exp, self.n_square)
        return partial_decryption

    def decrypt(self, partial_dict: Dict[int, int]) -> int:
        r"""
        Function that uses partial decryptions of other parties to reconstruct a
        full decryption of the initial ciphertext.

        :param partial_dict: dictionary containing the partial decryptions of each party
        :raise ValueError: Either in case not enough shares are known in order to decrypt.
            Or when the combined decryption minus one is not divisible by $N$. This last case is
            most likely caused by the fact the ciphertext that is being decrypted,
            differs between parties.
        :return: full decryption
        """

        partial_decryptions = [
            partial_dict[i + 1] for i in range(self.t)
        ]

        if len(partial_decryptions) < self.t:
            raise ValueError("Not enough shares.")

        combined_decryption = (
            mult_list(partial_decryptions[: self.t]) % self.n_square
        )

        if (combined_decryption - 1) % self.n != 0:
            raise ValueError(
                "Combined decryption minus one is not divisible by N. This might be caused by the "
                "fact that the ciphertext that is being decrypted, differs between the parties."
            )

        message = ((combined_decryption - 1) // self.n * self.theta_inv) % self.n

        return message

    def partial_randomness_recovery(self, ciphertext: PaillierCiphertext, plaintext: int) -> int:
        ciphertext_value = ciphertext.value
        # Compute (ciphertext * (1-n*plaintext))^x mod n
        partial_randomness = (ciphertext_value*(1-plaintext*self.n) ) % self.n_square
        partial_randomness = pow_mod(partial_randomness, self.x, self.n)
        return partial_randomness

    def __str__(self) -> str:
        """
        Utility function to represent the local share of the private key as a string.

        :return: String representation of this private key part.
        """
        return str(
            {
                "priv_shared_key": {
                    "n": self.n,
                    "t": self.t,
                    "player_id": self.player_id,
                    "theta": self.theta,
                    "share": self.share,
                }
            }
        )
