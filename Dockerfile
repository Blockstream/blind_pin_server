FROM debian:trixie@sha256:4ae67669760b807c19f23902a3fd7c121a6a70cf2ae709035674b23e712e4d62

RUN apt update -qq && apt upgrade --no-install-recommends -yqq \
  && apt install --no-install-recommends -yqq procps python3-pip uwsgi uwsgi-plugin-python3 python3-setuptools nginx runit \ 
  && mkdir /etc/service/nginx \
  && mkdir /etc/service/wsgi

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx.runit /etc/service/nginx/run
COPY wsgi.runit /etc/service/wsgi/run

WORKDIR /pinserver
COPY runit_boot.sh wsgi.ini requirements.txt wsgi.py server.py lib.py pindb.py __init__.py generateserverkey.py flaskserver.py /pinserver/
RUN pip install --ignore-installed --break-system-packages --require-hashes -r /pinserver/requirements.txt
CMD ["/bin/bash", "-c", "chown www-data:www-data /pins; ./runit_boot.sh"]
