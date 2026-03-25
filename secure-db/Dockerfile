FROM postgres:15-alpine

RUN mkdir -p /etc/postgresql/certs

COPY secure-db/postgresql.conf /etc/postgresql/postgresql.conf
COPY secure-db/pg_hba.conf /etc/postgresql/pg_hba.conf
COPY internal-certs/ca.pem /etc/postgresql/certs/ca.pem
COPY internal-certs/secure-db.crt /etc/postgresql/certs/secure-db.crt
COPY internal-certs/secure-db.key /etc/postgresql/certs/secure-db.key

RUN chown -R postgres:postgres /etc/postgresql && chmod 600 /etc/postgresql/certs/secure-db.key

CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]
