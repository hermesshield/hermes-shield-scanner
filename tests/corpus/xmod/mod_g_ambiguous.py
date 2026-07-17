from xmod.unrelated import _send_clean   # SAME NAME, WRONG module -> must not affect the real helper
def other(text):
    _send_clean(text)
