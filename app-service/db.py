import os
import psycopg2

def get_db_connection():
    host = os.getenv("SECURE_DB_HOST", "DB_HOST")
    port = int(os.getenv("SECURE_DB_PORT", "DB_PORT"))
    user = os.getenv("SECURE_DB_USER", "DB_USER")
    password = os.getenv("SECURE_DB_PASSWORD", "DB_PASSWORD")
    dbname = os.getenv("SECURE_DB_NAME", "DB_NAME")

    return psycopg2.connect(host=host, port=port, user=user, password=password, dbname=dbname)