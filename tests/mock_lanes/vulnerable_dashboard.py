class H:
    def do_POST(self):
        body = self.rfile.read(10)   # mutates state, no auth check -> should need certification
        apply_action(body)
