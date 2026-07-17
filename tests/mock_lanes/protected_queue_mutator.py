from hash_ledger import record_approved
def approve(conn, qid, content, human_approved):
    if not human_approved:
        return "blocked"
    record_approved(qid, content, lane="mock")
    conn.execute("UPDATE x_post_queue SET status='approved' WHERE id=?", (qid,))
