from .base import Base as Parent
from .base import route as route_alias


class Impl(Parent):
    def run(self) -> str:
        def nested() -> str:
            return super().run()

        return nested()


def use_route() -> str:
    return route_alias()
