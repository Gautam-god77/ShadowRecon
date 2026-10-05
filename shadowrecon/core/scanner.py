from shadowrecon.core.target import Target
from shadowrecon.core.scope import Scope


class Scanner:

    def __init__(self, target_value):

        self.target = Target.create(target_value)

        self.scope = Scope(
            target=self.target.host
        )

    def authorize(self):

        self.scope.confirm()

        return self.scope.allow()

    def get_target(self):

        return self.target
