# Tailscale nginx auth plugin adapted for Traefik

This is a small tweak to the nginx auth plugin provided
by tailscale, but adapted to work with Traefik

- Listens on http
- Uses X-Forwarded-For instead of Remote-IP
- X-Forwarded-Port instead of Remote-Port (this is almost certainly wrong as it
  should be the source port, but traefik does not yet provide use an
  equivalent)
