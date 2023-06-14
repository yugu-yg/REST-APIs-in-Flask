"""
blocklist.py

This file just contains the blocklist of the JWT tokens. It will be imported by
app and the logout resource so that tokens can be added to the blocklist when the
user logs out.

Note: Python sets don't persist. You should store this in a database (Redis etc.) when deploy.
"""

BLOCKLIST = set()