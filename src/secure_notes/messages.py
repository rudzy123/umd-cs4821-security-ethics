"""Stable client-facing error text.

Authentication and authorization failures stay generic so a response does
not teach a caller which check failed.
"""

INVALID_CREDENTIALS = "Invalid credentials"
REGISTER_FAILED = "Unable to register with the provided details"
AUTHENTICATION_REQUIRED = "Authentication required"
NOTE_NOT_FOUND = "Note not found"
TOO_MANY_REQUESTS = "Too many requests"
INTERNAL_ERROR = "Internal server error"
