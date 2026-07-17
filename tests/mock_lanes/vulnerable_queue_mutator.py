def approve(conn, qid):
    conn.execute("UPDATE x_post_queue SET status='approved' WHERE id=?", (qid,))   # no approval-hash
