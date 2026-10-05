from dataclasses import dataclass


@dataclass
class Scope:

    target: str
    authorized: bool = False

    def confirm(self):
        self.authorized = True
        return True

    def allow(self):

        if not self.authorized:
            raise PermissionError(
                "Target is outside authorized scope."
            )

        return True
