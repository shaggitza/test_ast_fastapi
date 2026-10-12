"""Call and inheritance fixture for future sandbox runs only."""


def target() -> str:
    return "baseline"


class Base:
    def inherited(self) -> str:
        return target()


class Child(Base):
    def method(self) -> str:
        return self.inherited()
