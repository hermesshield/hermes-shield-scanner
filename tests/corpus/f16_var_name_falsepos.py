def count(posts):
    linkedin_post_comment_total = sum(p.comments for p in posts)
    return linkedin_post_comment_total
