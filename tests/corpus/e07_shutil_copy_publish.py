import shutil
def promote(src):
    shutil.copy(src, "content/publishing/approved/out.md")
