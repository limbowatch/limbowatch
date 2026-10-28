# The public site at limbo.watch: the static output of `limbowatch publish` behind nginx.
# CI (.github/workflows/site.yml) writes the site into ./public before building.
FROM nginx:1.30.0-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY public/ /usr/share/nginx/html/
