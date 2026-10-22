def search_items(db, q):
    query = f"SELECT * FROM items WHERE name = '{q}'"
    return db.execute(query).fetchall()
