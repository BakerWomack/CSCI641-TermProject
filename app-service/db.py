import os
import psycopg2

def get_db_connection():
    host = os.getenv("SECURE_DB_HOST", "secure-db")
    port = int(os.getenv("SECURE_DB_PORT", "5432"))
    user = os.getenv("SECURE_DB_USER", "postgres")
    password = os.getenv("SECURE_DB_PASSWORD", "postgres")
    dbname = os.getenv("SECURE_DB_NAME", "postgres")
    sslrootcert = os.getenv("SECURE_DB_SSLROOTCERT", "/etc/service-certs/ca.pem")
    sslcert = os.getenv("SECURE_DB_SSLCERT", "/etc/service-certs/app-db-client.crt")
    sslkey = os.getenv("SECURE_DB_SSLKEY", "/etc/service-certs/app-db-client.key")

    return psycopg2.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        dbname=dbname,
        sslmode="verify-full",
        sslrootcert=sslrootcert,
        sslcert=sslcert,
        sslkey=sslkey,
    )