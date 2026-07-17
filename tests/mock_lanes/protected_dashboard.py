from dashboard_auth import is_dashboard_post_allowed
class H:
    def do_POST(self):
        if is_dashboard_post_allowed(dict(self.headers), {}, live=True).blocked:
            return self._send(403)
        apply_action(self.rfile.read(10))
