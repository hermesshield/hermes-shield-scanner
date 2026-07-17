def build():
    sql = "UPDATE x_post_queue SET status='x'"   # string only, no execute() -> not a live sink
    return sql
