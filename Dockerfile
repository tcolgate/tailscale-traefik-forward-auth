FROM scratch
COPY tailscale-traefik-forward-auth /tailscale-traefik-forward-auth
ENTRYPOINT ["/tailscale-traefik-forward-auth"]
