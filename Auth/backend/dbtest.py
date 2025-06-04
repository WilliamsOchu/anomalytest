import psycopg2

# connection establishment
conn = psycopg2.connect(
   database="postgres",
    user='postgres',
    password='postgres',
    host='localhost',
    port= '5432'
)

conn.autocommit = True

# Creating a cursor object
cur = conn.cursor()
print("Connect success\n")

# Execute a test query
cur.execute("SELECT * FROM clients")

# Retrieve query results
records = cur.fetchall()

# Finally, you may print the output to the console or use it anyway you like
print(records)

# Closing the connection
conn.close()