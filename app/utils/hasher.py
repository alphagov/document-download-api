import argon2.exceptions
from argon2 import PasswordHasher, Type


class Hasher:
    """
    We use the argon2ID hasher and parameters laid out by OWASP here:
    https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#password-hashing-algorithms
    """

    _hasher = PasswordHasher(memory_cost=15360, time_cost=2, parallelism=1, hash_len=16, type=Type.ID)

    def hash(self, value: str):
        return self._hasher.hash(value)

    def verify(self, value: str, hash_to_verify: str):
        try:
            return self._hasher.verify(hash_to_verify, value)

        except argon2.exceptions.VerifyMismatchError:
            pass

        return False
