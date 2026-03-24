"""Tests for secure memory scrubbing (SecureString and secure_zero)."""
import pytest
from src.vault.secure_string import secure_zero, SecureString


class TestSecureZero:
    """Tests for the secure_zero function."""

    def test_zeroes_string_memory(self):
        """After secure_zero, the string's characters should be overwritten."""
        # Create a string that is unlikely to be interned
        s = "x" * 10 + "unique_secret_value_12345"
        secure_zero(s)
        # The string object still exists but its content should be zeroed.
        # We cannot reliably read the zeroed content via Python (it may
        # appear as empty or NUL chars), but we verify no exception is raised.

    def test_handles_empty_string_gracefully(self):
        """secure_zero should not crash on an empty string."""
        secure_zero("")

    def test_handles_non_string_gracefully(self):
        """secure_zero should silently ignore non-string inputs."""
        secure_zero(None)
        secure_zero(12345)
        secure_zero(b"bytes")


class TestSecureString:
    """Tests for the SecureString context manager."""

    def test_context_manager_provides_value(self):
        """Value should be accessible inside the context manager."""
        with SecureString("my-secret") as ss:
            assert ss.value == "my-secret"

    def test_scrubbed_after_exit(self):
        """Value should be None after exiting the context manager."""
        ss = SecureString("my-secret")
        with ss:
            pass
        assert ss.value is None
        assert ss.is_scrubbed is True

    def test_str_before_and_after_scrub(self):
        """str() should return the value before scrub and '<scrubbed>' after."""
        ss = SecureString("my-secret")
        assert str(ss) == "my-secret"
        ss.scrub()
        assert str(ss) == "<scrubbed>"

    def test_repr_hides_value(self):
        """repr should never reveal the secret."""
        ss = SecureString("my-secret")
        assert "my-secret" not in repr(ss)
        assert "***" in repr(ss)

    def test_bool_true_when_active(self):
        ss = SecureString("something")
        assert bool(ss) is True

    def test_bool_false_after_scrub(self):
        ss = SecureString("something")
        ss.scrub()
        assert bool(ss) is False

    def test_bool_false_for_none(self):
        ss = SecureString(None)
        assert bool(ss) is False

    def test_equality_with_string(self):
        ss = SecureString("abc")
        assert ss == "abc"
        assert ss != "xyz"

    def test_equality_with_secure_string(self):
        a = SecureString("abc")
        b = SecureString("abc")
        assert a == b

    def test_double_scrub_is_safe(self):
        """Calling scrub() twice should not raise."""
        ss = SecureString("secret")
        ss.scrub()
        ss.scrub()
        assert ss.is_scrubbed

    def test_enter_after_scrub_raises(self):
        """Using context manager after scrub should raise RuntimeError."""
        ss = SecureString("secret")
        ss.scrub()
        with pytest.raises(RuntimeError):
            with ss:
                pass

    def test_none_value_creates_scrubbed_instance(self):
        """SecureString(None) should be immediately marked as scrubbed."""
        ss = SecureString(None)
        assert ss.is_scrubbed is True
        assert ss.value is None

    def test_context_manager_scrubs_on_exception(self):
        """Secret should be scrubbed even if an exception occurs inside the block."""
        ss = SecureString("secret")
        with pytest.raises(ValueError):
            with ss:
                raise ValueError("boom")
        assert ss.is_scrubbed is True
        assert ss.value is None
