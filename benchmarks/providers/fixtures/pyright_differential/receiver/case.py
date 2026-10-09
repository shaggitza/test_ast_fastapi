from typing import Protocol

class Runner(Protocol):
    def run(self) -> str: ...

class Base:
    def run(self) -> str:
        return "base"

class Child(Base):
    def run(self) -> str:
        return "child"

def call(value: Runner) -> str:
    return value.run()

def open_base(value: Base) -> str:
    return value.run()

reveal_type(call(Child()))
