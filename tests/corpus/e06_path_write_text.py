from pathlib import Path
def save(t):
    Path("out/ready/note.md").write_text(t)
