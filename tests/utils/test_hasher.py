from hypothesis import given, settings
from hypothesis.strategies import emails

from app.utils.hasher import Hasher


class TestHasher:
    def test_hasher_using_argon2id_with_expected_parameters(self):
        hasher = Hasher()

        hash = hasher.hash("abc123")

        assert hash.startswith("$argon2id$")
        assert "$m=15360,t=2,p=1$" in hash

    @settings(deadline=None)
    @given(emails())
    def test_hash_verifies_correctly(self, value):
        hasher = Hasher()

        hash = hasher.hash(value)

        assert hasher.verify(value=value, hash_to_verify=hash)
